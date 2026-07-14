from typing import Literal

from pydantic import BaseModel, Field, field_validator, model_validator


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
