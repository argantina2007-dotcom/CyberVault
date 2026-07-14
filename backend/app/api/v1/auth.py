from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.user import User

from app.schemas.user import (
    UserRegister,
    UserLogin,
    TokenResponse,
)

from app.schemas.token import (
    RefreshTokenRequest,
    AccessTokenResponse,
)

from app.core.security import (
    hash_password,
    verify_password,
    create_access_token,
    create_refresh_token,
    decode_token,
)

router = APIRouter(
    prefix="/api/v1/auth",
    tags=["Authentication"]
)


@router.post("/register", response_model=TokenResponse)
def register(data: UserRegister, db: Session = Depends(get_db)):
    # التحقق من البريد الإلكتروني
    if db.query(User).filter(User.email == data.email).first():
        raise HTTPException(
            status_code=400,
            detail="Email already registered"
        )

    # التحقق من اسم المستخدم
    if db.query(User).filter(User.username == data.username).first():
        raise HTTPException(
            status_code=400,
            detail="Username already taken"
        )

    user = User(
        username=data.username,
        email=data.email,
        hashed_password=hash_password(data.password)
    )

    db.add(user)
    db.commit()
    db.refresh(user)

    return TokenResponse(
        access_token=create_access_token({"sub": str(user.id)}),
        refresh_token=create_refresh_token({"sub": str(user.id)})
    )


@router.post("/login", response_model=TokenResponse)
def login(data: UserLogin, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == data.email).first()

    if not user or not verify_password(
        data.password,
        user.hashed_password
    ):
        raise HTTPException(
            status_code=401,
            detail="Invalid credentials"
        )

    return TokenResponse(
        access_token=create_access_token({"sub": str(user.id)}),
        refresh_token=create_refresh_token({"sub": str(user.id)})
    )


@router.post("/refresh", response_model=AccessTokenResponse)
def refresh_token(data: RefreshTokenRequest):
    payload = decode_token(data.refresh_token)

    if payload is None:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired refresh token"
        )

    if payload.get("type") != "refresh":
        raise HTTPException(
            status_code=401,
            detail="Invalid token type"
        )

    new_access_token = create_access_token(
        {
            "sub": payload["sub"]
        }
    )

    return AccessTokenResponse(
        access_token=new_access_token
    )