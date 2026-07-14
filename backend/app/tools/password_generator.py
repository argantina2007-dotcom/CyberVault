import math
import secrets
import string


UPPERCASE = string.ascii_uppercase
LOWERCASE = string.ascii_lowercase
NUMBERS = string.digits
SYMBOLS = "!@#$%^&*()-_=+[]{};:,.?"
AMBIGUOUS_CHARACTERS = frozenset("O0oIl1")


def generate_password(length: int, character_sets: dict[str, str]) -> str:
    """Generate a cryptographically secure password containing every enabled set."""
    enabled_sets = list(character_sets.values())
    if length < len(enabled_sets):
        raise ValueError("Password length is shorter than the number of enabled categories")

    password_characters = [secrets.choice(characters) for characters in enabled_sets]
    character_pool = "".join(enabled_sets)
    password_characters.extend(
        secrets.choice(character_pool) for _ in range(length - len(password_characters))
    )
    secrets.SystemRandom().shuffle(password_characters)
    return "".join(password_characters)


def available_character_sets(exclude_ambiguous: bool) -> dict[str, str]:
    categories = {
        "uppercase": UPPERCASE,
        "lowercase": LOWERCASE,
        "numbers": NUMBERS,
        "symbols": SYMBOLS,
    }
    if not exclude_ambiguous:
        return categories
    return {
        category: "".join(character for character in values if character not in AMBIGUOUS_CHARACTERS)
        for category, values in categories.items()
    }


def estimate_entropy(length: int, character_pool_size: int) -> float:
    return round(length * math.log2(character_pool_size), 2)


def strength_rating(entropy: float) -> str:
    if entropy < 40:
        return "weak"
    if entropy < 60:
        return "fair"
    if entropy < 80:
        return "strong"
    return "very_strong"
