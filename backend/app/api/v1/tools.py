from fastapi import APIRouter, Depends
import base64

from app.api.v1.deps import get_current_user
from app.models.user import User
from app.schemas.tools import (
    Base64DecodeRequest,
    Base64DecodeResponse,
    Base64EncodeRequest,
    Base64EncodeResponse,
    HashGeneratorRequest,
    HashGeneratorResponse,
    JwtDecoderRequest,
    JwtDecoderResponse,
    PasswordGeneratorRequest,
    PasswordGeneratorResponse,
)
from app.tools.base64_codec import decode_text, encode_text
from app.tools.hash_generator import generate_hash, hash_security_note
from app.tools.jwt_decoder import parse_unverified_token, verify_token
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


@router.post(
    "/hash-generator",
    response_model=HashGeneratorResponse,
    summary="Generate a text hash",
    description=(
        "Hashes UTF-8 text without logging or storing it. MD5 and SHA1 are provided only for "
        "legacy interoperability and are unsuitable for password storage. Authentication is required."
    ),
)
def hash_generator(
    options: HashGeneratorRequest,
    _: User = Depends(get_current_user),
) -> HashGeneratorResponse:
    generated_hash = generate_hash(options.text, options.algorithm, options.bcrypt_rounds)
    return HashGeneratorResponse(
        algorithm=options.algorithm,
        hash=generated_hash,
        input_byte_length=len(options.text.encode("utf-8")),
        output_format="bcrypt modular crypt format" if options.algorithm == "bcrypt" else "lowercase hexadecimal",
        security_note=hash_security_note(options.algorithm),
    )


@router.post(
    "/jwt-decoder",
    response_model=JwtDecoderResponse,
    summary="Decode or verify a JWT",
    description=(
        "Decoding alone does not prove authenticity. Verified mode requires a caller-supplied secret "
        "and explicit algorithm allowlist; the application's own signing key is never used."
    ),
)
def jwt_decoder(
    options: JwtDecoderRequest,
    _: User = Depends(get_current_user),
) -> JwtDecoderResponse:
    header, unverified_payload, signature_present = parse_unverified_token(options.token)
    verified = options.verify_signature
    payload = unverified_payload
    if verified:
        payload = verify_token(
            options.token,
            options.secret_key.get_secret_value(),
            options.algorithms,
        )

    return JwtDecoderResponse(
        header=header,
        payload=payload,
        signature_present=signature_present,
        verified=verified,
        algorithm=header.get("alg"),
        token_type=payload.get("type"),
        issued_at=payload.get("iat"),
        expires_at=payload.get("exp"),
        not_before=payload.get("nbf"),
        validation_note=(
            "Signature and registered claims were verified using the caller-supplied key and allowlist."
            if verified
            else "Decoded without signature or claim verification. Do not trust these claims as authentic."
        ),
    )


@router.post(
    "/base64-encode",
    response_model=Base64EncodeResponse,
    summary="Encode UTF-8 text as Base64",
    description="Base64 is encoding, not encryption. Supplied text and output are not logged or stored.",
)
def base64_encode(
    options: Base64EncodeRequest,
    _: User = Depends(get_current_user),
) -> Base64EncodeResponse:
    encoded_text, input_byte_length, padding_removed = encode_text(
        options.text,
        options.url_safe,
        options.remove_padding,
    )
    return Base64EncodeResponse(
        encoded_text=encoded_text,
        input_byte_length=input_byte_length,
        output_length=len(encoded_text),
        url_safe=options.url_safe,
        padding_removed=padding_removed,
        security_note="Base64 is encoding, not encryption.",
    )


@router.post(
    "/base64-decode",
    response_model=Base64DecodeResponse,
    summary="Decode Base64 text",
    description=(
        "Decodes Base64 without executing the result. Base64 is encoding, not encryption. "
        "Binary or text that cannot use the requested encoding is returned as Base64 bytes."
    ),
)
def base64_decode(
    options: Base64DecodeRequest,
    _: User = Depends(get_current_user),
) -> Base64DecodeResponse:
    decoded_bytes = decode_text(
        options.encoded_text,
        options.url_safe,
        options.strict_validation,
    )
    try:
        decoded_text = decoded_bytes.decode(options.output_encoding)
    except UnicodeDecodeError:
        return Base64DecodeResponse(
            decoded_text=None,
            decoded_base64_bytes=base64.b64encode(decoded_bytes).decode("ascii"),
            output_byte_length=len(decoded_bytes),
            detected_encoding=None,
            url_safe=options.url_safe,
            validation_note=(
                f"Decoded bytes are not valid {options.output_encoding} text; returned as Base64 bytes."
            ),
        )

    return Base64DecodeResponse(
        decoded_text=decoded_text,
        decoded_base64_bytes=None,
        output_byte_length=len(decoded_bytes),
        detected_encoding=options.output_encoding,
        url_safe=options.url_safe,
        validation_note="Base64 decoded successfully. Base64 is encoding, not encryption.",
    )
