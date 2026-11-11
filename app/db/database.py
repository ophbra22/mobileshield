import logging
import time

from sqlalchemy import create_engine, text
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from app.settings import get_settings

_LOG = logging.getLogger('mobileshield.database')


class Base(DeclarativeBase):
    pass


settings = get_settings()
engine = create_engine(settings.database_url, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


def initialize_database() -> bool:
    """Create tables, retrying while the database starts.

    Message analysis never touches the database, so the API keeps serving scans
    when it is unreachable; only ``/readyz`` and the admin/key routes need it.
    Returns whether the database is ready.
    """
    from app.db import models  # noqa: F401  (register tables on Base.metadata)

    for attempt in range(1, settings.db_startup_attempts + 1):
        try:
            with engine.begin() as connection:
                connection.execute(text('SELECT 1'))
            Base.metadata.create_all(bind=engine)
            return True
        except OperationalError:
            if attempt < settings.db_startup_attempts:
                time.sleep(1)
    _LOG.warning('database unavailable after %s attempts; continuing without it', settings.db_startup_attempts)
    return False
