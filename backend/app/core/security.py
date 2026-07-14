import hashlib
import secrets
from datetime import datetime, timedelta
from jose import JWTError, jwt
from passlib.context import CryptContext

from app.core.config import settings

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)

def create_access_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(
        minutes=settings.access_token_expire_minutes
    )
    to_encode.update({"exp": expire, "type": "access"})
    return jwt.encode(
        to_encode,
        settings.secret_key.get_secret_value(),
        algorithm=settings.algorithm,
    )

def create_refresh_token(
    data: dict,
    *,
    token_identifier: str | None = None,
    family_identifier: str | None = None,
) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(days=settings.refresh_token_expire_days)
    to_encode.update(
        {
            "exp": expire,
            "type": "refresh",
            "jti": token_identifier or secrets.token_urlsafe(32),
            "family": family_identifier or secrets.token_urlsafe(24),
        }
    )
    return jwt.encode(
        to_encode,
        settings.secret_key.get_secret_value(),
        algorithm=settings.algorithm,
    )


def hash_token_identifier(token_identifier: str) -> str:
    """Return the fixed-length digest stored for a refresh-token identifier."""
    return hashlib.sha256(token_identifier.encode("utf-8")).hexdigest()

def decode_token(token: str) -> dict | None:
    try:
        payload = jwt.decode(
            token,
            settings.secret_key.get_secret_value(),
            algorithms=[settings.algorithm],
        )
        return payload
    except JWTError:
        return None
