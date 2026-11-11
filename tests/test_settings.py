"""Production refuses placeholder secrets; development keeps working defaults."""
import pytest
from pydantic import ValidationError

from app.settings import Settings

STRONG = 'x' * 40


def test_dev_defaults_are_allowed():
    assert Settings(_env_file=None, env='dev').jwt_secret == 'change-me'


@pytest.mark.parametrize('overrides,field', [
    ({}, 'jwt_secret'),
    ({'jwt_secret': STRONG}, 'server_key'),
    ({'jwt_secret': STRONG, 'server_key': 'short'}, 'server_key'),
    ({'jwt_secret': STRONG, 'server_key': STRONG, 'enable_admin': True, 'admin_token': 'change-me-now'}, 'admin_token'),
])
def test_prod_rejects_weak_secrets(overrides, field):
    with pytest.raises(ValidationError, match=field):
        Settings(_env_file=None, env='prod', **overrides)


def test_prod_accepts_strong_secrets():
    settings = Settings(_env_file=None, env='prod', jwt_secret=STRONG, server_key=STRONG,
                        enable_admin=True, admin_token=STRONG)
    assert settings.env == 'prod'


def test_unreachable_database_does_not_stop_startup(monkeypatch):
    from sqlalchemy.exc import OperationalError

    from app.db import database

    class Down:
        def begin(self):
            raise OperationalError('SELECT 1', {}, Exception('synthetic: database down'))

    monkeypatch.setattr(database, 'engine', Down())
    monkeypatch.setattr(database.settings, 'db_startup_attempts', 1)
    assert database.initialize_database() is False
