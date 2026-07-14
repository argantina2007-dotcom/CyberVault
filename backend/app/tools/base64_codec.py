import base64
import binascii

from fastapi import HTTPException, status


def encode_text(text: str, url_safe: bool, remove_padding: bool) -> tuple[str, int, bool]:
    """Encode UTF-8 text using Base64 without retaining the source text."""
    input_bytes = text.encode("utf-8")
    encoded = (
        base64.urlsafe_b64encode(input_bytes) if url_safe else base64.b64encode(input_bytes)
    ).decode("ascii")
    padding_removed = remove_padding and encoded.endswith("=")
    if padding_removed:
        encoded = encoded.rstrip("=")
    return encoded, len(input_bytes), padding_removed


def decode_text(encoded_text: str, url_safe: bool, strict_validation: bool) -> bytes:
    """Decode Base64 after restoring optional omitted padding."""
    normalized = encoded_text + "=" * (-len(encoded_text) % 4)
    try:
        return base64.b64decode(
            normalized,
            altchars=b"-_" if url_safe else None,
            validate=strict_validation,
        )
    except (binascii.Error, ValueError):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="Encoded text is not valid Base64",
        ) from None
