Use with Flask-Login
====================

Use the :meth:`LoginManager.request_loader <flask_login.LoginManager.request_loader>` to authenticate:


.. code-block:: python

    from flask_cfaccess import CfAccess
    from flask_login import LoginManager

    cfaccess = CfAccess()

    login_manager = LoginManager()

    @login_manager.request_loader
    def request_loader(request):
        identity = cfaccess.get_identity()
        if identity:
            return identity["user_uuid"]


You may substite ``user_uuid`` with any of the fields in
`application token documentation <https://developers.cloudflare.com/cloudflare-one/identity/authorization-cookie/application-token/#user-identity>`_
or provided by your individual IdP under the ``idp`` key.
