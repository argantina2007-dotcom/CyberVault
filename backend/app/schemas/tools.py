import codecs
from typing import Any, Literal

from pydantic import BaseModel, Field, SecretStr, field_validator, model_validator


class PasswordGeneratorRequest(BaseModel):
    """Options for a cryptographically secure generated password."""

    length: int = Field(default=16, ge=8, le=128, description="Password length in characters.")
    include_uppercase: bool = Field(default=True, description="Include A-Z.")
    include_lowercase: bool = Field(default=True, description="Include a-z.")
    include_numbers: bool = Field(default=True, description="Include 0-9.")
    include_symbols: bool = Field(default=True, description="Include supported punctuation symbols.")
    exclude_ambiguous: bool = Field(
        default=False,
        description="Exclude visually ambiguous characters such as O, 0, I, l, and 1.",
    )

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "length": 20,
                    "include_uppercase": True,
                    "include_lowercase": True,
                    "include_numbers": True,
                    "include_symbols": True,
                    "exclude_ambiguous": True,
                }
            ]
        }
    }

    @model_validator(mode="after")
    def validate_enabled_categories(self) -> "PasswordGeneratorRequest":
        enabled_categories = sum(
            (
                self.include_uppercase,
                self.include_lowercase,
                self.include_numbers,
                self.include_symbols,
            )
        )
        if enabled_categories == 0:
            raise ValueError("At least one character category must be enabled")
        if self.length < enabled_categories:
            raise ValueError("Length must accommodate every enabled character category")
        return self


class PasswordGeneratorResponse(BaseModel):
    password: str = Field(description="Generated password. It is returned once and is never stored.")
    length: int
    enabled_categories: list[str]
    estimated_entropy: float = Field(description="Estimated entropy in bits.")
    strength_rating: Literal["weak", "fair", "strong", "very_strong"]


class HashGeneratorRequest(BaseModel):
    text: str = Field(description="UTF-8 text to hash. It is not stored or logged.")
    algorithm: Literal["md5", "sha1", "sha256", "sha512", "bcrypt"] = Field(
        description="Hashing algorithm. MD5 and SHA1 must not be used for password storage."
    )
    bcrypt_rounds: int | None = Field(
        default=None,
        ge=10,
        le=14,
        description="bcrypt work factor. Allowed only when algorithm is bcrypt.",
    )

    model_config = {
        "json_schema_extra": {
            "examples": [
                {"text": "CyberVault", "algorithm": "sha256"},
                {"text": "password-to-hash", "algorithm": "bcrypt", "bcrypt_rounds": 12},
            ]
        }
    }

    @field_validator("algorithm", mode="before")
    @classmethod
    def normalize_algorithm(cls, value: str) -> str:
        return value.lower() if isinstance(value, str) else value

    @field_validator("text")
    @classmethod
    def validate_text(cls, value: str) -> str:
        if not value:
            raise ValueError("Text must not be empty")
        if len(value.encode("utf-8")) > 100 * 1024:
            raise ValueError("Text must not exceed 100 KB when UTF-8 encoded")
        return value

    @model_validator(mode="after")
    def validate_bcrypt_options(self) -> "HashGeneratorRequest":
        if self.algorithm != "bcrypt" and self.bcrypt_rounds is not None:
            raise ValueError("bcrypt_rounds is allowed only when algorithm is bcrypt")
        return self


class HashGeneratorResponse(BaseModel):
    algorithm: Literal["md5", "sha1", "sha256", "sha512", "bcrypt"]
    hash: str = Field(description="Generated digest or bcrypt modular crypt string.")
    input_byte_length: int = Field(description="UTF-8 byte length of the supplied text.")
    output_format: str
    security_note: str


class JwtDecoderRequest(BaseModel):
    token: str = Field(description="JWT compact serialization. It is not stored or logged.")
    verify_signature: bool = Field(
        default=False,
        description="Verify the signature and registered claims using the supplied key and allowlist.",
    )
    secret_key: SecretStr | None = Field(
        default=None,
        description="Verification key supplied only for verified decoding; the server signing key is never used.",
    )
    algorithms: list[str] | None = Field(
        default=None,
        description="Explicit algorithm allowlist required for verified decoding, for example ['HS256'].",
    )

    model_config = {
        "json_schema_extra": {
            "examples": [
                {"token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...", "verify_signature": False},
                {
                    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                    "verify_signature": True,
                    "secret_key": "caller-provided-verification-key",
                    "algorithms": ["HS256"],
                },
            ]
        }
    }

    @field_validator("token")
    @classmethod
    def validate_token(cls, value: str) -> str:
        if not value or not value.strip():
            raise ValueError("Token must not be empty")
        if len(value.encode("utf-8")) > 16 * 1024:
            raise ValueError("Token must not exceed 16 KB when UTF-8 encoded")
        return value

    @field_validator("algorithms")
    @classmethod
    def validate_algorithms(cls, value: list[str] | None) -> list[str] | None:
        if value is None:
            return value
        if not all(isinstance(algorithm, str) and algorithm.strip() for algorithm in value):
            raise ValueError("Algorithms must contain non-empty algorithm names")
        if any(algorithm.lower() == "none" for algorithm in value):
            raise ValueError("The 'none' algorithm is not allowed")
        return value

    @model_validator(mode="after")
    def validate_verification_options(self) -> "JwtDecoderRequest":
        if not self.verify_signature:
            return self
        if self.secret_key is None or not self.secret_key.get_secret_value():
            raise ValueError("secret_key is required when verify_signature is true")
        if not self.algorithms:
            raise ValueError("A non-empty algorithms allowlist is required when verify_signature is true")
        return self


class JwtDecoderResponse(BaseModel):
    header: dict[str, Any]
    payload: dict[str, Any]
    signature_present: bool
    verified: bool
    algorithm: str | None
    token_type: str | None
    issued_at: Any | None
    expires_at: Any | None
    not_before: Any | None
    validation_note: str


class Base64EncodeRequest(BaseModel):
    text: str = Field(description="UTF-8 text to encode. It is not stored or logged.")
    url_safe: bool = Field(default=False, description="Use the URL-safe Base64 alphabet.")
    remove_padding: bool = Field(default=False, description="Remove trailing '=' padding characters.")

    model_config = {
        "json_schema_extra": {
            "examples": [
                {"text": "CyberVault", "url_safe": False, "remove_padding": False},
                {"text": "path/value", "url_safe": True, "remove_padding": True},
            ]
        }
    }

    @field_validator("text")
    @classmethod
    def validate_text(cls, value: str) -> str:
        if not value:
            raise ValueError("Text must not be empty")
        try:
            encoded = value.encode("utf-8")
        except UnicodeEncodeError:
            raise ValueError("Text must be valid UTF-8") from None
        if len(encoded) > 100 * 1024:
            raise ValueError("Text must not exceed 100 KB when UTF-8 encoded")
        return value


class Base64DecodeRequest(BaseModel):
    encoded_text: str = Field(description="Base64-encoded text. It is not stored or logged.")
    url_safe: bool = Field(default=False, description="Interpret input using the URL-safe Base64 alphabet.")
    strict_validation: bool = Field(
        default=True,
        description="Reject characters outside the selected Base64 alphabet.",
    )
    output_encoding: str = Field(
        default="utf-8",
        description="Text encoding used to decode output bytes, for example utf-8 or latin-1.",
    )

    model_config = {
        "json_schema_extra": {
            "examples": [
                {"encoded_text": "Q3liZXJWYXVsdA==", "output_encoding": "utf-8"},
                {
                    "encoded_text": "cGF0aC92YWx1ZQ",
                    "url_safe": True,
                    "strict_validation": True,
                },
            ]
        }
    }

    @field_validator("encoded_text")
    @classmethod
    def validate_encoded_text(cls, value: str) -> str:
        if not value or not value.strip():
            raise ValueError("Encoded text must not be empty")
        if len(value.encode("utf-8")) > 100 * 1024:
            raise ValueError("Encoded text must not exceed 100 KB when UTF-8 encoded")
        return value

    @field_validator("output_encoding")
    @classmethod
    def validate_output_encoding(cls, value: str) -> str:
        try:
            return codecs.lookup(value).name
        except LookupError:
            raise ValueError("output_encoding is not a supported text encoding") from None


class Base64EncodeResponse(BaseModel):
    encoded_text: str
    input_byte_length: int
    output_length: int
    url_safe: bool
    padding_removed: bool
    security_note: str


class Base64DecodeResponse(BaseModel):
    decoded_text: str | None
    decoded_base64_bytes: str | None = Field(
        description="Standard Base64 representation of output bytes when text decoding fails."
    )
    output_byte_length: int
    detected_encoding: str | None
    url_safe: bool
    validation_note: str
