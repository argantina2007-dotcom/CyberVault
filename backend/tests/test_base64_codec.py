import base64

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import sessionmaker


def authenticated_headers(client: TestClient) -> dict[str, str]:
    registration = client.post(
        "/api/v1/auth/register",
        json={
            "username": "base64-user",
            "email": "base64-user@example.com",
            "password": "strong-password",
        },
    )
    assert registration.status_code == 200
    return {"Authorization": f"Bearer {registration.json()['access_token']}"}


def request(client: TestClient, path: str, payload: dict, headers: dict[str, str] | None = None):
    return client.post(path, json=payload, headers=headers or authenticated_headers(client))


def test_standard_encoding(client: tuple[TestClient, sessionmaker]) -> None:
    response = request(client[0], "/api/v1/tools/base64-encode", {"text": "CyberVault"})
    assert response.status_code == 200
    body = response.json()
    assert body["encoded_text"] == "Q3liZXJWYXVsdA=="
    assert body["input_byte_length"] == len("CyberVault".encode("utf-8"))
    assert body["padding_removed"] is False


def test_standard_decoding(client: tuple[TestClient, sessionmaker]) -> None:
    response = request(
        client[0],
        "/api/v1/tools/base64-decode",
        {"encoded_text": "Q3liZXJWYXVsdA=="},
    )
    assert response.status_code == 200
    assert response.json()["decoded_text"] == "CyberVault"
    assert response.json()["detected_encoding"] == "utf-8"


def test_url_safe_mode(client: tuple[TestClient, sessionmaker]) -> None:
    text = "\uffff"
    response = request(
        client[0],
        "/api/v1/tools/base64-encode",
        {"text": text, "url_safe": True},
    )
    assert response.status_code == 200
    assert response.json()["encoded_text"] == base64.urlsafe_b64encode(text.encode()).decode()


def test_removed_padding(client: tuple[TestClient, sessionmaker]) -> None:
    response = request(
        client[0],
        "/api/v1/tools/base64-encode",
        {"text": "a", "remove_padding": True},
    )
    assert response.status_code == 200
    assert response.json()["encoded_text"] == "YQ"
    assert response.json()["padding_removed"] is True


def test_missing_padding_is_restored(client: tuple[TestClient, sessionmaker]) -> None:
    response = request(client[0], "/api/v1/tools/base64-decode", {"encoded_text": "YQ"})
    assert response.status_code == 200
    assert response.json()["decoded_text"] == "a"


def test_malformed_input_is_rejected(client: tuple[TestClient, sessionmaker]) -> None:
    response = request(client[0], "/api/v1/tools/base64-decode", {"encoded_text": "%%%"})
    assert response.status_code == 422


def test_invalid_utf8_decoded_content_is_returned_as_base64_bytes(
    client: tuple[TestClient, sessionmaker]
) -> None:
    encoded = base64.b64encode(b"\xff").decode("ascii")
    response = request(client[0], "/api/v1/tools/base64-decode", {"encoded_text": encoded})
    assert response.status_code == 200
    body = response.json()
    assert body["decoded_text"] is None
    assert body["decoded_base64_bytes"] == encoded
    assert body["detected_encoding"] is None


@pytest.mark.parametrize(
    ("path", "payload"),
    [
        ("/api/v1/tools/base64-encode", {"text": "a" * (100 * 1024 + 1)}),
        ("/api/v1/tools/base64-decode", {"encoded_text": "a" * (100 * 1024 + 1)}),
    ],
)
def test_oversized_input_is_rejected(
    client: tuple[TestClient, sessionmaker], path: str, payload: dict
) -> None:
    response = request(client[0], path, payload)
    assert response.status_code == 422


@pytest.mark.parametrize(
    ("path", "payload"),
    [
        ("/api/v1/tools/base64-encode", {"text": ""}),
        ("/api/v1/tools/base64-decode", {"encoded_text": ""}),
    ],
)
def test_empty_input_is_rejected(
    client: tuple[TestClient, sessionmaker], path: str, payload: dict
) -> None:
    response = request(client[0], path, payload)
    assert response.status_code == 422


def test_base64_endpoints_require_authentication(client: tuple[TestClient, sessionmaker]) -> None:
    response = client[0].post("/api/v1/tools/base64-encode", json={"text": "CyberVault"})
    assert response.status_code == 401
