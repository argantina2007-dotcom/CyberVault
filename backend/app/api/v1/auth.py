from datetime import timedelta
import secrets
import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.rate_limit import limiter
from app.core.security import (
    create_access_token,
    create_refresh_token,
    decode_token,
    hash_password,
    hash_token_identifier,
    verify_password,
)
from app.core.time import utc_now
from app.database import get_db
from app.models.refresh_session import RefreshSession
from app.models.user import User
from app.schemas.token import AccessTokenResponse, RefreshTokenRequest
from app.schemas.user import TokenResponse, UserLogin, UserRegister


router = APIRouter(prefix="/api/v1/auth", tags=["Authentication"])


def _unauthorized(detail: str = "Invalid or expired refresh token") -> HTTPException:
    return HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=detail)


def _refresh_claims(refresh_token: str) -> tuple[dict, str, str, str]:
    payload = decode_token(refresh_token)
    if payload is None or payload.get("type") != "refresh":
        raise _unauthorized()

    user_id = payload.get("sub")
    token_identifier = payload.get("jti")
    family_id = payload.get("family")
    if not all(isinstance(value, str) and value for value in (user_id, token_identifier, family_id)):
        raise _unauthorized()
    return payload, user_id, token_identifier, family_id


def _issue_token_pair(db: Session, user: User, family_id: str | None = None) -> tuple[str, str]:
    """Create a token pair and persist only the refresh token's identifier digest."""
    token_identifier = secrets.token_urlsafe(32)
    family_id = family_id or str(uuid.uuid4())
    refresh_token = create_refresh_token(
        {"sub": str(user.id)},
        token_identifier=token_identifier,
        family_identifier=family_id,
    )
    db.add(
        RefreshSession(
            user_id=str(user.id),
            family_id=family_id,
            token_identifier_hash=hash_token_identifier(token_identifier),
            expires_at=utc_now()
            + timedelta(days=settings.refresh_token_expire_days),
        )
    )
    return create_access_token({"sub": str(user.id)}), refresh_token


def _revoke_family(db: Session, family_id: str) -> None:
    db.query(RefreshSession).filter(
        RefreshSession.family_id == family_id,
        RefreshSession.revoked_at.is_(None),
    ).update({RefreshSession.revoked_at: utc_now()}, synchronize_session=False)


@router.post("/register", response_model=TokenResponse)
@limiter.limit(settings.register_rate_limit)
def register(request: Request, data: UserRegister, db: Session = Depends(get_db)):
    if db.query(User).filter(User.email == data.email).first():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already registered")

    if db.query(User).filter(User.username == data.username).first():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Username already taken")

    user = User(
        username=data.username,
        email=data.email,
        hashed_password=hash_password(data.password),
        last_login=utc_now(),
    )
    db.add(user)
    try:
        db.flush()
        access_token, refresh_token = _issue_token_pair(db, user)
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username or email already registered",
        ) from None

    return TokenResponse(access_token=access_token, refresh_token=refresh_token)


@router.post("/login", response_model=TokenResponse)
@limiter.limit(settings.login_rate_limit)
def login(request: Request, data: UserLogin, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == data.email).first()
    if not user or not user.is_active or not verify_password(data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )

    user.last_login = utc_now()
    try:
        access_token, refresh_token = _issue_token_pair(db, user)
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Unable to create an authentication session",
        ) from None

    return TokenResponse(access_token=access_token, refresh_token=refresh_token)


@router.post("/refresh", response_model=AccessTokenResponse)
@limiter.limit(settings.refresh_rate_limit)
def refresh_token(
    request: Request,
    data: RefreshTokenRequest,
    db: Session = Depends(get_db),
):
    _, user_id, token_identifier, family_id = _refresh_claims(data.refresh_token)
    session = (
        db.query(RefreshSession)
        .filter(
            RefreshSession.token_identifier_hash == hash_token_identifier(token_identifier),
            RefreshSession.user_id == user_id,
            RefreshSession.family_id == family_id,
        )
        .with_for_update()
        .first()
    )

    if session is None:
        raise _unauthorized()

    if session.revoked_at is not None:
        _revoke_family(db, family_id)
        db.commit()
        raise _unauthorized("Refresh token reuse detected")

    user = db.query(User).filter(User.id == user_id).first()
    if user is None or not user.is_active or session.expires_at <= utc_now():
        session.revoked_at = utc_now()
        db.commit()
        raise _unauthorized()

    session.revoked_at = utc_now()
    try:
        access_token, new_refresh_token = _issue_token_pair(db, user, family_id)
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Unable to rotate the refresh token",
        ) from None

    return AccessTokenResponse(
        access_token=access_token,
        refresh_token=new_refresh_token,
    )


@router.post("/logout")
def logout(data: RefreshTokenRequest, db: Session = Depends(get_db)):
    _, user_id, token_identifier, family_id = _refresh_claims(data.refresh_token)
    session = (
        db.query(RefreshSession)
        .filter(
            RefreshSession.token_identifier_hash == hash_token_identifier(token_identifier),
            RefreshSession.user_id == user_id,
            RefreshSession.family_id == family_id,
        )
        .first()
    )
    if session is None:
        raise _unauthorized()

    if session.revoked_at is None:
        session.revoked_at = utc_now()
        db.commit()

    return {"detail": "Logged out successfully"}
