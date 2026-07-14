from fastapi.testclient import TestClient
from sqlalchemy.orm import sessionmaker

from app.models.user import User


def register(client: TestClient, email: str = "user@example.com") -> dict:
    response = client.post(
        "/api/v1/auth/register",
        json={"username": email.split("@")[0], "email": email, "password": "strong-password"},
    )
    assert response.status_code == 200
    return response.json()


def test_register_creates_token_pair(client: tuple[TestClient, sessionmaker]) -> None:
    test_client, _ = client
    tokens = register(test_client)
    assert tokens["token_type"] == "bearer"
    assert tokens["access_token"]
    assert tokens["refresh_token"]


def test_login_updates_last_login(client: tuple[TestClient, sessionmaker]) -> None:
    test_client, session_factory = client
    register(test_client)

    response = test_client.post(
        "/api/v1/auth/login",
        json={"email": "user@example.com", "password": "strong-password"},
    )
    assert response.status_code == 200
    assert response.json()["refresh_token"]

    db = session_factory()
    try:
        assert db.query(User).filter(User.email == "user@example.com").one().last_login is not None
    finally:
        db.close()


def test_oauth2_form_login_uses_email_as_username(client: tuple[TestClient, sessionmaker]) -> None:
    test_client, _ = client
    register(test_client)

    response = test_client.post(
        "/api/v1/auth/token",
        data={"username": "user@example.com", "password": "strong-password"},
    )

    assert response.status_code == 200
    tokens = response.json()
    assert tokens["token_type"] == "bearer"
    assert tokens["access_token"]
    assert tokens["refresh_token"]


def test_inactive_users_cannot_login_access_or_refresh(
    client: tuple[TestClient, sessionmaker],
) -> None:
    test_client, session_factory = client
    tokens = register(test_client)

    db = session_factory()
    try:
        user = db.query(User).filter(User.email == "user@example.com").one()
        user.is_active = False
        db.commit()
    finally:
        db.close()

    login = test_client.post(
        "/api/v1/auth/login",
        json={"email": "user@example.com", "password": "strong-password"},
    )
    assert login.status_code == 401

    protected = test_client.get(
        "/api/v1/users/me",
        headers={"Authorization": f"Bearer {tokens['access_token']}"},
    )
    assert protected.status_code == 401

    refresh = test_client.post(
        "/api/v1/auth/refresh", json={"refresh_token": tokens["refresh_token"]}
    )
    assert refresh.status_code == 401


def test_refresh_rotates_tokens_and_detects_reuse(
    client: tuple[TestClient, sessionmaker],
) -> None:
    test_client, _ = client
    tokens = register(test_client)

    rotation = test_client.post(
        "/api/v1/auth/refresh", json={"refresh_token": tokens["refresh_token"]}
    )
    assert rotation.status_code == 200
    rotated = rotation.json()
    assert rotated["refresh_token"]
    assert rotated["refresh_token"] != tokens["refresh_token"]

    reuse = test_client.post(
        "/api/v1/auth/refresh", json={"refresh_token": tokens["refresh_token"]}
    )
    assert reuse.status_code == 401

    family_revoked = test_client.post(
        "/api/v1/auth/refresh", json={"refresh_token": rotated["refresh_token"]}
    )
    assert family_revoked.status_code == 401


def test_logout_revokes_the_current_refresh_session(
    client: tuple[TestClient, sessionmaker],
) -> None:
    test_client, _ = client
    tokens = register(test_client)

    logout = test_client.post(
        "/api/v1/auth/logout", json={"refresh_token": tokens["refresh_token"]}
    )
    assert logout.status_code == 200

    refresh = test_client.post(
        "/api/v1/auth/refresh", json={"refresh_token": tokens["refresh_token"]}
    )
    assert refresh.status_code == 401
