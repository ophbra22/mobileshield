"""API keys are looked up by their keyed hash, never by the shared public prefix."""
import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.auth import require_api_key
from app.db.database import Base
from app.db.models import ApiKey
from app.security import generate_api_key, hash_api_key


@pytest.fixture
def db():
    engine = create_engine('sqlite://', connect_args={'check_same_thread': False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        yield session
    engine.dispose()


def _add_key(db, name):
    raw = generate_api_key()
    key_hash, prefix, last4 = hash_api_key(raw)
    record = ApiKey(name=name, key_hash=key_hash, key_prefix=prefix, last4=last4, is_active=True)
    db.add(record)
    db.commit()
    return raw, record


def test_every_key_shares_the_public_marker():
    assert generate_api_key()[:8] == generate_api_key()[:8] == 'ms_live_'


def test_many_keys_authenticate_independently(db):
    keys = [_add_key(db, f'key-{i}') for i in range(3)]
    for raw, record in keys:
        assert require_api_key(raw, db).id == record.id


def test_unknown_or_revoked_keys_are_rejected(db):
    raw, record = _add_key(db, 'revoked')
    _add_key(db, 'other')
    with pytest.raises(HTTPException) as unknown:
        require_api_key('ms_live_' + 'x' * 43, db)
    assert unknown.value.status_code == 401
    record.is_active = False
    db.commit()
    with pytest.raises(HTTPException) as revoked:
        require_api_key(raw, db)
    assert revoked.value.status_code == 401
