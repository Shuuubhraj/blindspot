"""Database session management."""

from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path

from sqlalchemy.orm import sessionmaker

from ..config import settings
from .models import get_engine, init_db

# The engine is created at import time, so make sure the sqlite parent
# directory exists here (not only in create_app()).
_db_path = settings.database_url
if _db_path.startswith("sqlite:///"):
    Path(_db_path.replace("sqlite:///", "")).parent.mkdir(parents=True, exist_ok=True)

_engine = get_engine(settings.database_url)
init_db(_engine)
_Session = sessionmaker(bind=_engine, future=True)


@contextmanager
def session_scope():
    session = _Session()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
