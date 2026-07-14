from typing import Any

from fastapi import HTTPException, status
from jose import JWTError, jwt


def parse_unverified_token(token: str) -> tuple[dict[str, Any], dict[str, Any], bool]:
    """Parse only the JWT's public header and payload; no trust is implied."""
    parts = token.split(".")
    if len(parts) != 3 or not parts[0] or not parts[1]:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="Token must be a JWT with header, payload, and signature segments",
        )
    try:
        header = jwt.get_unverified_header(token)
        payload = jwt.get_unverified_claims(token)
    except (JWTError, ValueError, TypeError):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="Token header or payload is malformed",
        ) from None

    if not isinstance(header, dict) or not isinstance(payload, dict):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="Token header and payload must be JSON objects",
        )
    return header, payload, bool(parts[2])


def verify_token(token: str, secret_key: str, algorithms: list[str]) -> dict[str, Any]:
    """Verify a JWT against caller-supplied verification material only."""
    try:
        return jwt.decode(token, secret_key, algorithms=algorithms)
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token signature or registered claims could not be verified",
        ) from None
