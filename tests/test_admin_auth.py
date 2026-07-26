from fastapi.testclient import TestClient

from api.main import app


client = TestClient(app)


def test_admin_login_accepts_default_credentials():
    response = client.post(
        "/auth/admin/login",
        json={"username": "admin", "password": "admin123"},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["ok"] is True
    assert payload["token"]
    assert payload["user"]["role"] == "admin"


def test_admin_login_rejects_bad_password():
    response = client.post(
        "/auth/admin/login",
        json={"username": "admin", "password": "wrong"},
    )

    assert response.status_code == 401
