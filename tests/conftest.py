import os
import secrets
import time

from pathlib import Path

import jwt
import pytest
import responses

from flask import Flask
from flask_cfaccess import CfAccess

try:
    import flask_login
except ImportError:
    flask_login = None


algo = jwt.algorithms.RSAAlgorithm(jwt.algorithms.RSAAlgorithm.SHA256)

key_dir = os.path.join(os.path.dirname(os.path.realpath(__file__)), "keys")

with open(os.path.join(key_dir, "rsa_private_key.json")) as private:
    PRIVATE_KEY = algo.from_jwk(private.read())

with open(os.path.join(key_dir, "rsa_public_key.json")) as public:
    PUBLIC_KEY = algo.from_jwk(public.read())


@pytest.fixture
def app(mocker, tmp_path: Path, token_payload):
    app = Flask("flask_cfaccess", instance_path=str(tmp_path / "instance"))

    app.config[
        "CLOUDFLARE_ACCESS_AUD"
    ] = "32eafc7626e974616deaf0dc3ce63d7bcbed58a2731e84d06bc3cdf1b53c4228"
    app.config["CLOUDFLARE_ACCESS_TEAM"] = "yourteam"

    app.secret_key = secrets.token_hex(16)
    app.testing = True

    CfAccess(app)

    jwks_client = app.extensions["cfaccess"][1]

    def get_public_key(token):
        return PUBLIC_KEY

    mocker.patch.object(
        jwks_client, "get_signing_key_from_jwt", get_public_key
    )

    responses.get(
        url="https://yourteam.cloudflareaccess.com/cdn-cgi/access/get-identity",
        json=token_payload,
    )

    return app


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture
def app_context(app: Flask):
    with app.app_context() as ctx:
        yield ctx


@pytest.fixture(scope="session")
def token(token_payload):
    return jwt.encode(token_payload, PRIVATE_KEY, "RS256")


@pytest.fixture(scope="session")
def token_payload():
    now = time.time()

    return {
        "aud": [
            "32eafc7626e974616deaf0dc3ce63d7bcbed58a2731e84d06bc3cdf1b53c4228"
        ],
        "email": "user@example.com",
        "exp": now + 300,
        "iat": now - 300,
        "nbf": now - 300,
        "iss": "https://yourteam.cloudflareaccess.com",
        "type": "app",
        "identity_nonce": "6ei69kawdKzMIAPF",
        "sub": "7335d417-61da-459d-899c-0a01c76a2f94",
        "country": "US",
    }


if flask_login:

    @pytest.fixture
    def login_manager(app: Flask):
        return flask_login.LoginManager(app)


def pytest_addoption(parser):
    parser.addoption(
        "--integration",
        action="store_true",
        default=False,
        help="run integration tests",
    )


def pytest_collection_modifyitems(config, items):
    if config.getoption("--integration"):
        # --integration given in cli: do not skip integration tests
        return
    skip_integration = pytest.mark.skip(
        reason="need --integration option to run",
    )
    for item in items:
        if "integration" in item.keywords:
            item.add_marker(skip_integration)
