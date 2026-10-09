from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from app.settings import get_settings


class Base(DeclarativeBase):
    pass


settings = get_settings()
engine = create_engine(settings.database_url, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


def initialize_database() -> None:
    """Preserve the existing production schema startup and retry behavior."""
    import time
    from sqlalchemy import text
    from sqlalchemy.exc import OperationalError

    last_error: Exception | None = None
    for attempt in range(1, 21):
        try:
            with engine.begin() as connection:
                connection.execute(text('SELECT 1'))
                Base.metadata.create_all(bind=engine)
                # lightweight migrations for new columns/tables
                connection.execute(
                    text("ALTER TABLE scans ADD COLUMN IF NOT EXISTS breakdown JSON NOT NULL DEFAULT '[]'::json;")
                )
                connection.execute(
                    text("ALTER TABLE scans ADD COLUMN IF NOT EXISTS reputation VARCHAR(32);")
                )
                connection.execute(
                    text("ALTER TABLE scans ADD COLUMN IF NOT EXISTS reputation_score_hint INTEGER;")
                )
                connection.execute(
                    text("ALTER TABLE scans ADD COLUMN IF NOT EXISTS user_id INTEGER NULL;")
                )
                connection.execute(
                    text("ALTER TABLE scans ADD COLUMN IF NOT EXISTS api_key_id INTEGER NULL;")
                )
            return
        except OperationalError as exc:
            last_error = exc
            time.sleep(1)
    raise RuntimeError('Database did not become ready after 20 startup attempts.') from last_error
