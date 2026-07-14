import string

from fastapi.testclient import TestClient
from sqlalchemy.orm import sessionmaker


def authenticated_headers(client: TestClient) -> dict[str, str]:
    registration = client.post(
        "/api/v1/auth/register",
        json={
            "username": "tool-user",
            "email": "tool-user@example.com",
            "password": "strong-password",
        },
    )
    assert registration.status_code == 200
    return {"Authorization": f"Bearer {registration.json()['access_token']}"}


def generate(client: TestClient, payload: dict, headers: dict[str, str] | None = None) -> dict:
    response = client.post(
        "/api/v1/tools/password-generator",
        json=payload,
        headers=headers or authenticated_headers(client),
    )
    assert response.status_code == 200
    return response.json()


def test_default_password_generation(client: tuple[TestClient, sessionmaker]) -> None:
    response = generate(client[0], {})
    assert response["length"] == 16
    assert len(response["password"]) == 16
    assert response["enabled_categories"] == ["uppercase", "lowercase", "numbers", "symbols"]
    assert response["estimated_entropy"] > 0


def test_custom_password_length(client: tuple[TestClient, sessionmaker]) -> None:
    response = generate(client[0], {"length": 40})
    assert response["length"] == 40
    assert len(response["password"]) == 40


def test_each_category_option(client: tuple[TestClient, sessionmaker]) -> None:
    test_client, _ = client
    headers = authenticated_headers(test_client)
    category_options = {
        "include_uppercase": string.ascii_uppercase,
        "include_lowercase": string.ascii_lowercase,
        "include_numbers": string.digits,
        "include_symbols": "!@#$%^&*()-_=+[]{};:,.?",
    }
    for enabled_option, alphabet in category_options.items():
        payload = {
            "length": 12,
            "include_uppercase": False,
            "include_lowercase": False,
            "include_numbers": False,
            "include_symbols": False,
            enabled_option: True,
        }
        response = generate(test_client, payload, headers)
        assert response["enabled_categories"] == [enabled_option.removeprefix("include_")]
        assert set(response["password"]).issubset(set(alphabet))


def test_excludes_ambiguous_characters(client: tuple[TestClient, sessionmaker]) -> None:
    response = generate(
        client[0],
        {"length": 128, "exclude_ambiguous": True},
    )
    assert not (set(response["password"]) & set("O0oIl1"))


def test_invalid_length_returns_422(client: tuple[TestClient, sessionmaker]) -> None:
    headers = authenticated_headers(client[0])
    for length in (7, 129):
        response = client[0].post(
            "/api/v1/tools/password-generator",
            json={"length": length},
            headers=headers,
        )
        assert response.status_code == 422


def test_no_enabled_categories_returns_422(client: tuple[TestClient, sessionmaker]) -> None:
    response = client[0].post(
        "/api/v1/tools/password-generator",
        json={
            "include_uppercase": False,
            "include_lowercase": False,
            "include_numbers": False,
            "include_symbols": False,
        },
        headers=authenticated_headers(client[0]),
    )
    assert response.status_code == 422


def test_password_contains_every_enabled_category(client: tuple[TestClient, sessionmaker]) -> None:
    response = generate(
        client[0],
        {
            "length": 20,
            "include_uppercase": True,
            "include_lowercase": True,
            "include_numbers": True,
            "include_symbols": True,
        },
    )
    password = response["password"]
    assert any(character in string.ascii_uppercase for character in password)
    assert any(character in string.ascii_lowercase for character in password)
    assert any(character in string.digits for character in password)
    assert any(character in "!@#$%^&*()-_=+[]{};:,.?" for character in password)


def test_password_generator_requires_authentication(client: tuple[TestClient, sessionmaker]) -> None:
    response = client[0].post("/api/v1/tools/password-generator", json={})
    assert response.status_code == 401
