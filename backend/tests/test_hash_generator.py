import hashlib

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import sessionmaker

from app.core.security import verify_password


def authenticated_headers(client: TestClient) -> dict[str, str]:
    registration = client.post(
        "/api/v1/auth/register",
        json={
            "username": "hash-user",
            "email": "hash-user@example.com",
            "password": "strong-password",
        },
    )
    assert registration.status_code == 200
    return {"Authorization": f"Bearer {registration.json()['access_token']}"}


def generate(client: TestClient, payload: dict, headers: dict[str, str] | None = None):
    return client.post(
        "/api/v1/tools/hash-generator",
        json=payload,
        headers=headers or authenticated_headers(client),
    )


@pytest.mark.parametrize("algorithm", ["md5", "sha1", "sha256", "sha512"])
def test_hashlib_algorithms_are_deterministic(
    client: tuple[TestClient, sessionmaker], algorithm: str
) -> None:
    text = "CyberVault"
    response = generate(client[0], {"text": text, "algorithm": algorithm})
    assert response.status_code == 200
    body = response.json()
    assert body["algorithm"] == algorithm
    assert body["hash"] == hashlib.new(algorithm, text.encode("utf-8")).hexdigest()
    assert body["input_byte_length"] == len(text.encode("utf-8"))
    assert body["output_format"] == "lowercase hexadecimal"


def test_bcrypt_output_verifies_correctly(client: tuple[TestClient, sessionmaker]) -> None:
    response = generate(
        client[0],
        {"text": "CyberVault", "algorithm": "bcrypt", "bcrypt_rounds": 10},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["hash"].startswith("$2")
    assert verify_password("CyberVault", body["hash"])
    assert body["output_format"] == "bcrypt modular crypt format"


def test_empty_input_is_rejected(client: tuple[TestClient, sessionmaker]) -> None:
    response = generate(client[0], {"text": "", "algorithm": "sha256"})
    assert response.status_code == 422


def test_oversized_input_is_rejected(client: tuple[TestClient, sessionmaker]) -> None:
    response = generate(client[0], {"text": "a" * (100 * 1024 + 1), "algorithm": "sha256"})
    assert response.status_code == 422


def test_invalid_algorithm_is_rejected(client: tuple[TestClient, sessionmaker]) -> None:
    response = generate(client[0], {"text": "CyberVault", "algorithm": "sha3"})
    assert response.status_code == 422


@pytest.mark.parametrize("rounds", [9, 15])
def test_invalid_bcrypt_rounds_are_rejected(
    client: tuple[TestClient, sessionmaker], rounds: int
) -> None:
    response = generate(
        client[0],
        {"text": "CyberVault", "algorithm": "bcrypt", "bcrypt_rounds": rounds},
    )
    assert response.status_code == 422


def test_bcrypt_rounds_with_non_bcrypt_algorithm_is_rejected(
    client: tuple[TestClient, sessionmaker]
) -> None:
    response = generate(
        client[0],
        {"text": "CyberVault", "algorithm": "sha256", "bcrypt_rounds": 12},
    )
    assert response.status_code == 422


def test_hash_generator_requires_authentication(client: tuple[TestClient, sessionmaker]) -> None:
    response = client[0].post(
        "/api/v1/tools/hash-generator",
        json={"text": "CyberVault", "algorithm": "sha256"},
    )
    assert response.status_code == 401
