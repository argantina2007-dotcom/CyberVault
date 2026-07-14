from collections.abc import Generator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.api.v1.deps import get_db
from app.core.rate_limit import limiter
from app.database import Base
from app.main import app
from app.models.refresh_session import RefreshSession  # noqa: F401
from app.models.user import User  # noqa: F401


@pytest.fixture
def client(tmp_path) -> Generator[tuple[TestClient, sessionmaker], None, None]:
    engine = create_engine(
        f"sqlite:///{tmp_path / 'test.db'}",
        connect_args={"check_same_thread": False},
    )
    testing_session = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    Base.metadata.create_all(bind=engine)

    def override_get_db() -> Generator[Session, None, None]:
        db = testing_session()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    previous_limiter_state = limiter.enabled
    limiter.enabled = False
    try:
        with TestClient(app) as test_client:
            yield test_client, testing_session
    finally:
        limiter.enabled = previous_limiter_state
        app.dependency_overrides.clear()
        Base.metadata.drop_all(bind=engine)
        engine.dispose()
