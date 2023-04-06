Getting Started
===============

Initialize the extension
------------------------

Initialize the extension with your Flask application:

.. code-block:: python

    from flask import Flask
    from flask_cfaccess import CfAccess

    app = Flask(__name__)

    app.config["CLOUDFLARE_ACCESS_AUD"] = ""
    app.config["CLOUDFLARE_ACCESS_TEAM"] = ""

    cfaccess = CfAccess(app)


Or with initialize with the application factory pattern:

.. code-block:: python

    cfaccess = CfAccess()

    # later in your application factory

    cfaccess.init_app(app)


Configuration
-------------

``CLOUDFLARE_ACCESS_AUD`` and ``CLOUDFLARE_ACCESS_TEAM`` are required. 

The audience (``CLOUDFLARE_ACCESS_AUD``) can be obtained by following the
`Zero Trust documentation <https://developers.cloudflare.com/cloudflare-one/identity/authorization-cookie/validating-json/#get-your-aud-tag>`_.

The team (``CLOUDFLARE_ACCESS_TEAM``) is the subdomain in your Cloudflare Access URL:

    https://<team>.cloudflareaccess.com/cdn-cgi/access/certs.


Protect a route
---------------

Mark any routes that you want protected by Cloudflare Access with the :func:`login_required` function:

.. code-block:: python

    from flask_cfaccess import login_required

    @login_required
    @app.route("/protected")
    def protected():
        return "Protected!"


Or call :meth:`CfAccess.authenticate` within your view function:

.. code-block:: python

    from flask import abort

    @app.route("/protected")
    def protected():
        if not cfaccess.authenticate():
            abort(401)

        return "Protected!"


You could protect all routes or routes within a blueprint with a :meth:`before_request <flask.Flask.before_request>`
function:

.. code-block:: python

    @app.before_request
    def check_authentication():
        if not cfaccess.authenticate():
            abort(401)


Validate indentity
------------------

You may also want to interrogate the user's identity, for instance check their groups or returned IdP data:

.. code-block:: python

    from flask_cfaccess import validate_identity

    def identity(user_info):
        # only allow user@example.com
        if user_info["email"] == "user@example.com":
            return True

    @validate_identity(identity)
    @app.route("/protected")
    def protected():
        return "Protected!"


Or call :meth:`CfAccess.get_identity` within your view function or :meth:`before_request <flask.Flask.before_request>`
function:

.. code-block:: python

    from flask import abort

    @app.route("/protected")
    def protected():
        identity = cfaccess.get_identity()
        if not identity:
            abort(401)

        return f"Protected for {identity['email']}!"


For more information on available keys in the user identity see the
`application token documentation <https://developers.cloudflare.com/cloudflare-one/identity/authorization-cookie/application-token/#user-identity>`_
or provided by your individual IdP under the ``idp`` key.
