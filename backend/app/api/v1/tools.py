from fastapi import APIRouter, Depends

from app.api.v1.deps import get_current_user
from app.models.user import User
from app.schemas.tools import PasswordGeneratorRequest, PasswordGeneratorResponse
from app.tools.password_generator import (
    available_character_sets,
    estimate_entropy,
    generate_password,
    strength_rating,
)


router = APIRouter(prefix="/api/v1/tools", tags=["Security Tools"])


@router.post(
    "/password-generator",
    response_model=PasswordGeneratorResponse,
    summary="Generate a cryptographically secure password",
    description=(
        "Creates a password using Python's secrets module. Generated passwords are not logged "
        "or stored. Authentication is required."
    ),
)
def password_generator(
    options: PasswordGeneratorRequest,
    _: User = Depends(get_current_user),
) -> PasswordGeneratorResponse:
    character_sets = available_character_sets(options.exclude_ambiguous)
    enabled_character_sets = {
        "uppercase": character_sets["uppercase"],
        "lowercase": character_sets["lowercase"],
        "numbers": character_sets["numbers"],
        "symbols": character_sets["symbols"],
    }
    selected_sets = {
        category: characters
        for category, characters, is_enabled in (
            ("uppercase", enabled_character_sets["uppercase"], options.include_uppercase),
            ("lowercase", enabled_character_sets["lowercase"], options.include_lowercase),
            ("numbers", enabled_character_sets["numbers"], options.include_numbers),
            ("symbols", enabled_character_sets["symbols"], options.include_symbols),
        )
        if is_enabled
    }
    password = generate_password(options.length, selected_sets)
    entropy = estimate_entropy(options.length, len("".join(selected_sets.values())))

    return PasswordGeneratorResponse(
        password=password,
        length=options.length,
        enabled_categories=list(selected_sets),
        estimated_entropy=entropy,
        strength_rating=strength_rating(entropy),
    )
