from fastapi import APIRouter, Depends

from app.api.v1.deps import get_current_user
from app.models.user import User

router = APIRouter(
    prefix="/api/v1/users",
    tags=["Users"],
)


@router.get("/me")
def read_current_user(
    current_user: User = Depends(get_current_user),
):
    return {
        "id": current_user.id,
        "username": current_user.username,
        "email": current_user.email,
    }