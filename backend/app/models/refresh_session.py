import uuid

from sqlalchemy import Column, DateTime, ForeignKey, String

from app.database import Base
from app.core.time import utc_now


class RefreshSession(Base):
    """A server-side record for one refresh token in a rotating token family."""

    __tablename__ = "refresh_sessions"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String(36), ForeignKey("users.id"), nullable=False, index=True)
    family_id = Column(String(36), nullable=False, index=True)
    token_identifier_hash = Column(String(64), nullable=False, unique=True, index=True)
    expires_at = Column(DateTime, nullable=False)
    revoked_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=utc_now, nullable=False)
