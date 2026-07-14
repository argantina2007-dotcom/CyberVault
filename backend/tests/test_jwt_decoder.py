import base64
import json
from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient
from jose import jwt
from sqlalchemy.orm import sessionmaker


SECRET = "test-verification-secret"


def authenticated_headers(client: TestClient) -> dict[str, str]:
    registration = client.post(
        "/api/v1/auth/register",
        json={
            "username": "jwt-user",
            "email": "jwt-user@example.com",
            "password": "strong-password",
        },
    )
    assert registration.status_code == 200
    return {"Authorization": f"Bearer {registration.json()['access_token']}"}


def build_token(expires_at: datetime | None = None) -> str:
    payload = {"sub": "external-user", "type": "access", "iat": datetime.now(UTC)}
    if expires_at is not None:
        payload["exp"] = expires_at
    return jwt.encode(payload, SECRET, algorithm="HS256")


def decode(client: TestClient, payload: dict, headers: dict[str, str] | None = None):
    return client.post(
        "/api/v1/tools/jwt-decoder",
        json=payload,
        headers=headers or authenticated_headers(client),
    )


def test_valid_unverified_decoding(client: tuple[TestClient, sessionmaker]) -> None:
    token = build_token(datetime.now(UTC) + timedelta(minutes=5))
    response = decode(client[0], {"token": token})
    assert response.status_code == 200
    body = response.json()
    assert body["verified"] is False
    assert body["algorithm"] == "HS256"
    assert body["payload"]["sub"] == "external-user"
    assert "Do not trust" in body["validation_note"]


def test_valid_verified_decoding(client: tuple[TestClient, sessionmaker]) -> None:
    token = build_token(datetime.now(UTC) + timedelta(minutes=5))
    response = decode(
        client[0],
        {"token": token, "verify_signature": True, "secret_key": SECRET, "algorithms": ["HS256"]},
    )
    assert response.status_code == 200
    assert response.json()["verified"] is True


def test_wrong_secret_is_rejected(client: tuple[TestClient, sessionmaker]) -> None:
    response = decode(
        client[0],
        {
            "token": build_token(datetime.now(UTC) + timedelta(minutes=5)),
            "verify_signature": True,
            "secret_key": "wrong-secret",
            "algorithms": ["HS256"],
        },
    )
    assert response.status_code == 401


def test_verified_decoding_requires_secret(client: tuple[TestClient, sessionmaker]) -> None:
    response = decode(
        client[0],
        {"token": build_token(), "verify_signature": True, "algorithms": ["HS256"]},
    )
    assert response.status_code == 422


def test_verified_decoding_requires_algorithm_allowlist(client: tuple[TestClient, sessionmaker]) -> None:
    response = decode(
        client[0],
        {"token": build_token(), "verify_signature": True, "secret_key": SECRET},
    )
    assert response.status_code == 422


def test_disallowed_algorithm_is_rejected(client: tuple[TestClient, sessionmaker]) -> None:
    response = decode(
        client[0],
        {
            "token": build_token(),
            "verify_signature": True,
            "secret_key": SECRET,
            "algorithms": ["HS512"],
        },
    )
    assert response.status_code == 401


def test_malformed_token_is_rejected(client: tuple[TestClient, sessionmaker]) -> None:
    response = decode(client[0], {"token": "not-a-jwt"})
    assert response.status_code == 422


def test_expired_token_is_rejected_when_verifying(client: tuple[TestClient, sessionmaker]) -> None:
    response = decode(
        client[0],
        {
            "token": build_token(datetime.now(UTC) - timedelta(minutes=1)),
            "verify_signature": True,
            "secret_key": SECRET,
            "algorithms": ["HS256"],
        },
    )
    assert response.status_code == 401


def test_unsigned_token_is_rejected_when_verifying(client: tuple[TestClient, sessionmaker]) -> None:
    encode = lambda value: base64.urlsafe_b64encode(json.dumps(value).encode()).rstrip(b"=").decode()
    header = encode({"alg": "none", "typ": "JWT"})
    payload = encode({"sub": "external-user"})
    token = f"{header}.{payload}."
    response = decode(
        client[0],
        {"token": token, "verify_signature": True, "secret_key": SECRET, "algorithms": ["HS256"]},
    )
    assert response.status_code == 401


def test_jwt_decoder_requires_authentication(client: tuple[TestClient, sessionmaker]) -> None:
    response = client[0].post("/api/v1/tools/jwt-decoder", json={"token": build_token()})
    assert response.status_code == 401
