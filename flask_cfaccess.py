"""Zero Trust Access with Cloudflare Access for Flask applications."""
import typing as t

from functools import wraps
from importlib.metadata import PackageNotFoundError, version

import jwt
import requests

from flask import Flask, abort, current_app, g, request
from jwt.jwks_client import PyJWKClient
from werkzeug.local import LocalProxy

try:
    from _version import version as __version__
except ImportError:  # pragma: nocover
    try:
        __version__ = version("flask_cfaccess")
    except PackageNotFoundError:
        __version__ = "0.1-dev0"


class CfAccess:
    """Zero Trust Access with Cloudflare Access for Flask applications.

    :param app: The Flask application instance. The application instance is
                optional and can be passed by calling
                ``cfaccess.init_app(app)`` in your application factory\
                function.

    """

    def __init__(self, app: t.Optional[Flask] = None):
        self.default_app = app
        if app:
            self.init_app(app)

    def init_app(self, app: Flask):
        """Initialize the application.

        :param app: The Flask application.instance.

        """
        try:
            team = app.config["CLOUDFLARE_ACCESS_AUD"]
            team = app.config["CLOUDFLARE_ACCESS_TEAM"]
        except KeyError:
            raise RuntimeError(
                "CLOUDFLARE_ACCESS_AUD and CLOUDFLARE_ACCESS_TEAM is required "
                "for flask-cfaccess"
            )

        client = PyJWKClient(
            f"https://{team}.cloudflareaccess.com/cdn-cgi/access/certs"
        )

        if not hasattr(app, "extensions"):
            app.extensions = {}

        app.extensions["cfaccess"] = (self, client)

    def _get_app(self):
        try:
            return current_app._get_current_object()
        except RuntimeError:
            if self.default_app:
                return self.default_app

            raise

    def authenticate(self, token=None):
        """Validate that a request is authenticated."""
        if not token:
            token = request.headers.get("Cf-Access-Jwt-Assertion")
        if not token:
            token = request.cookies.get("CF_Authorization")
        if not token:
            return False

        app = self._get_app()

        try:
            cfaccess, jwks_client = app.extensions["cfaccess"]
        except (AttributeError, IndexError, KeyError, TypeError):
            raise RuntimeError(
                "flask-cfaccess not configured for this application"
            )

        aud = app.config["CLOUDFLARE_ACCESS_AUD"]
        key = jwks_client.get_signing_key_from_jwt(token)

        try:
            payload = jwt.decode(
                token, key, audience=aud, algorithms=["RS256"]
            )
        except jwt.DecodeError:
            return False

        g._cfaccess_token = token
        g._cfaccess_payload = payload

        return True

    def get_identity(self, token=None):
        """Get the user's identity."""
        if not token:
            token = getattr(g, "_cfaccess_token", None)

            if not token:
                self.authenticate()

            token = getattr(g, "_cfaccess_token", None)
            if not token:
                return

        team = self._get_app().config["CLOUDFLARE_ACCESS_TEAM"]
        url = (
            f"https://{team}.cloudflareaccess.com/cdn-cgi/access/get-identity"
        )

        res = requests.get(url, cookies={"CF_Authorization": token})
        res.raise_for_status()

        return res.json()

    def login_required(self, f):
        """Decorate a view to require a valid identity."""
        return login_required(f)

    def validate_identity(self, identify):
        """Decorate a view to validate the user's identity."""
        return validate_identity(identify)


def get_cfaccess():
    try:
        return current_app.extensions["cfaccess"][0]
    except (AttributeError, IndexError, KeyError, TypeError):
        raise RuntimeError(
            "flask-cfaccess not configured for this application"
        )


cfaccess = LocalProxy(get_cfaccess)


def login_required(f):
    """Decorate a view to require that the request is authenticated."""

    @wraps(f)
    def wrapper(*args, **kwargs):

        if not cfaccess.authenticate():
            abort(401)

        return f(*args, **kwargs)

    return wrapper


def get_identity():
    """Get the user's identity."""

    return cfaccess.get_identity()


def validate_identity(identify):
    """Decorate a view to validate the user's identity."""

    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if not cfaccess.authenticate():
                abort(401)

            identity = cfaccess.get_identity()
            if not identify(identity):
                abort(403)

            return f(*args, **kwargs)

        return wrapper

    return decorator
