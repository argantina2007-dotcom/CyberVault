import hashlib

from app.core.security import pwd_context


def generate_hash(text: str, algorithm: str, bcrypt_rounds: int | None = None) -> str:
    """Generate a hash without persisting or logging the supplied text."""
    if algorithm == "bcrypt":
        if bcrypt_rounds is None:
            return pwd_context.hash(text)
        return pwd_context.handler("bcrypt").using(rounds=bcrypt_rounds).hash(text)
    return hashlib.new(algorithm, text.encode("utf-8")).hexdigest()


def hash_security_note(algorithm: str) -> str:
    if algorithm in {"md5", "sha1"}:
        return "MD5 and SHA1 are unsuitable for password storage because they are fast and collision-prone."
    if algorithm == "bcrypt":
        return "bcrypt is designed for password hashing; use an appropriate work factor and unique salts."
    return "This cryptographic digest is deterministic and is not a password-storage scheme."
