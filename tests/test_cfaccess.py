from dataclasses import dataclass

import jwt
import pytest
import responses

from flask_cfaccess import (
    CfAccess,
    cfaccess,
    login_required,
    validate_identity,
)

try:
    import flask_login
except ImportError:
    flask_login = None


FAKE_PRIVATE_KEY = """-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQCotVge0KSFI1+b
eq8yKMjT19bHIdITneE9nWcZyNsrJ+Z1GU/+WOo0KvbjfjRpcXTkE9uwHLHmupVT
x+QlWk5fR14u79hCn20m4jnOHMeY/5xu8XHrIqcd/GiD9Wqd4P1hqqCeCKu3V1ty
cMyfWuPvpP8fc0N/5qIxZuFHs2pJNRpIucWFZ0FtWAYUTkKwt//k5bFPVpXFh3rE
NqqYiem7qSd4y7ROuVzjOKQKxvUgkhCeQteggaMBjkv3WtIzxYIEj8Eu3pa76rsW
F8mqSKM28xNryvdO9mUiaLgT7OYlhJgu8n5lIwwfqZGbyxdOYBy/p1bikJPcBiJH
Jx5sdOHvAgMBAAECggEATXcrVcbu7DVQZreAL5N7l45RkBEvAZPqg1y9pSDNxjSl
hNpRGVShgb/CqrXeAha3Gi0mIGkkpPHCtHwh/abIOsat7/ZwgjLrL0IMUeB0JAQm
w+h4qwO34bRvFzx+rqzLG+f5pWcM1fw2QMebpYZaCEVmYf4OnfF8Qxve0IoJAUCx
1hbIG8TN5+i5aQsQ8T3eaq/cOuDTZKelAPIsIEQf/H6acUGEDC+XumP5/UywoD2A
5OKXMERDr1IqiE622vy8TblFhct5TTC34zZyp46lXN3ujeTCE8d5tWjxUqr58Sxg
n94SWgoykH2PfyOmuMZulj+DJcVLXMIcAWyo/JJiQQKBgQC+lR/OgYQE6CD/wzDV
QF7mauBXXH/LYWlNL1PMham4UC02hd+ppbwpVt2/+Xbn5ZCGVuNoRzntuxpXvREB
1TQofuM6s0Ocxa9gc3E5k/OT3YMENQTGXt9v+zzi8jBjmHryI480r8kZVfxintkF
A5QRmd4WXLs+MM3QUKA+/igLrwKBgQDinhgu4GwZ+KE0D8A2BnUdxslhmURrWHvt
4kYZFFus/jbB+meGHzpkyIP6GlmX0OiYn2rMwPK0npM12glwdn5ECsVrVPQQ9IR6
/iIXY28QBovYI/VD9Zw/PPPOmgUfFJH0lHlQsRjulWzAODngeJBfJBV46fmmfGFQ
S5nI6jLdwQKBgQCiu4LlOgIYjn1e5rST4tsltKzK69jTOOJJXdgYEynQj+WLYNSS
b0ozolDG06SMbqDxlM+pAuib7d+Ye4BCKGLZET/Fp7xb6RDPMsPDfmnGIKb2uK7T
E7+GRui+gD6BTHnuuB5XxqHYWGuhajG07lFIljHktlnLyLB05+Ns5mgbUQKBgQCl
6/ro14hOu6vL4nxpEfFOC+4Gd6GQtwiF89Y/Jpi44KhW/nAt00992xJGXGScs2iZ
1p7rq5oIhNJj63Bd12Q7jWdeXqUUhPM62jc7yKHYqfJaHnnFeF8eLhKUglCdoQH8
gXkRi5kllmI5mvFFWQDbqB/Ql/8h1o+pqrC+WjtEAQKBgQCRb3nuvlXg/dQrw1tt
vEAbOaQGMJRiRinadSHdSCpp+BNjbycKfeA7mwIQLZOeMjYw1175eKZsjQWuRmCz
kF0iWTxbimpV44KVaWenxchMTKGC9MCywS7oXwDnS8xjOBvmrhkWQh3bUaRzcG+t
C2/akUdFVqOhJ/Ux3WZHOk+QkA==
-----END PRIVATE KEY-----"""


def test_authenticate(app, token, token_payload):
    with app.test_request_context(headers={"Cf-Access-Jwt-Assertion": token}):
        assert cfaccess.authenticate()


def test_authenticate_bad_aud(app):
    app.config["CLOUDFLARE_ACCESS_AUD"] = "wrong"

    with app.test_request_context():
        assert not cfaccess.authenticate()


def test_authenticate_bad_token(app, token_payload):
    token = jwt.encode(token_payload, FAKE_PRIVATE_KEY, "RS256")

    with app.test_request_context(headers={"Cf-Access-Jwt-Assertion": token}):
        assert not cfaccess.authenticate()


def test_authenticate_missing_token(app, token, token_payload):
    with app.test_request_context():
        assert not cfaccess.authenticate()


def test_init_app(app):
    cfaccess = CfAccess()
    cfaccess.init_app(app)

    app.extensions["cfaccess"] is cfaccess


@responses.activate
def test_get_identity(app, mocker, token, token_payload):
    with app.test_request_context():
        assert not cfaccess.get_identity()
    with app.test_request_context(headers={"Cf-Access-Jwt-Assertion": token}):
        identity = cfaccess.get_identity()
        assert identity == token_payload


def test_login_required(app, client, token, token_payload):
    @app.route("/")
    @login_required
    def protected():
        return "Protected"

    resp = client.get("/")
    assert resp.status_code == 401

    headers = {
        "Cookie": f"CF_Authorization={token}",
        "Cf-Access-Jwt-Assertion": token,
    }

    resp = client.get("/", headers=headers)
    assert resp.status_code == 200


@responses.activate
def test_validate_identity(app, client, token):
    def identify(user_info):
        return user_info["email"] == "user@example.com"

    @app.route("/")
    @validate_identity(identify)
    def protected():
        return "Protected"

    headers = {
        "Cookie": f"CF_Authorization={token}",
        "Cf-Access-Jwt-Assertion": token,
    }

    resp = client.get("/", headers=headers)
    assert resp.status_code == 200


@responses.activate
def test_validate_identity_wrong_user(app, client, token):
    def identify(user_info):
        return user_info["email"] == "admin@example.com"

    @app.route("/")
    @validate_identity(identify)
    def protected():
        return "Protected"

    headers = {
        "Cookie": f"CF_Authorization={token}",
        "Cf-Access-Jwt-Assertion": token,
    }

    resp = client.get("/", headers=headers)
    assert resp.status_code == 403


def test_token_cookie_only(app, token):
    with app.test_request_context(headers={"Cf-Access-Jwt-Assertion": token}):
        assert cfaccess.authenticate()


def test_token_header_only(app, token):
    with app.test_request_context(
        headers={"Cookie": f"CF_Authorization={token}"}
    ):
        assert cfaccess.authenticate()


if flask_login:

    @dataclass
    class User(flask_login.UserMixin):
        email: str

        def get_id(self):
            return self.email

    @pytest.fixture
    def user():
        return User(email="user@example.com")

    @pytest.fixture
    def users(user):
        return {user.email: user}


def _test_flask_login(app, login_manager, users):
    @login_manager.request_loader
    def request_loader(request):
        identity = cfaccess.get_identity()
        if not identity:
            return
        return users.get(identity["email"])

    @app.route("/")
    @flask_login.login_required
    def protected():
        return "Protected"


@pytest.mark.skipif(not flask_login, reason="flask-login not installed")
@responses.activate
def test_flask_login(app, client, login_manager, token, user, users):
    _test_flask_login(app, login_manager, users)

    headers = {
        "Cookie": f"CF_Authorization={token}",
        "Cf-Access-Jwt-Assertion": token,
    }

    resp = client.get("/", headers=headers)
    assert resp.status_code == 200


@pytest.mark.skipif(not flask_login, reason="flask-login not installed")
@responses.activate
def test_flask_login_missing_token(
    app, client, login_manager, token, user, users
):
    _test_flask_login(app, login_manager, users)

    resp = client.get("/")
    assert resp.status_code == 401


@pytest.mark.skipif(not flask_login, reason="flask-login not installed")
@responses.activate
def test_flask_login_missing_user(
    app, client, login_manager, token, user, users
):
    _test_flask_login(app, login_manager, users)

    users.pop(user.email)

    headers = {
        "Cookie": f"CF_Authorization={token}",
        "Cf-Access-Jwt-Assertion": token,
    }

    resp = client.get("/", headers=headers)
    assert resp.status_code == 401
