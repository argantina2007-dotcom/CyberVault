from typing import Literal

from pydantic import BaseModel, Field, model_validator


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
