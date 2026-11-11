from functools import lru_cache

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_INSECURE_DEFAULTS = {'change-me', 'change-me-server-key', 'change-me-now'}


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file='.env', env_file_encoding='utf-8', extra='ignore')

    app_name: str = 'mobileshield-ai'
    env: str = 'dev'  # 'dev' or 'prod'; prod refuses placeholder secrets
    database_url: str = 'postgresql+psycopg2://mobileshield:mobileshield@db:5432/mobileshield'
    db_startup_attempts: int = Field(default=20, ge=1)
    rate_limit_per_minute: int = Field(default=60, ge=1)
    cors_origins: str = 'http://localhost:3000,http://127.0.0.1:3000'
    admin_token: str | None = None
    enable_admin: bool = False
    admin_allow_ips: str | None = None
    jwt_secret: str = 'change-me'
    jwt_expires_minutes: int = 120
    server_key: str = 'change-me-server-key'

    @model_validator(mode='after')
    def _refuse_placeholder_secrets_in_prod(self) -> 'Settings':
        if self.env.lower() != 'prod':
            return self
        problems = [name for name in ('jwt_secret', 'server_key')
                    if getattr(self, name) in _INSECURE_DEFAULTS or len(getattr(self, name)) < 32]
        if self.enable_admin and (not self.admin_token or self.admin_token in _INSECURE_DEFAULTS
                                  or len(self.admin_token) < 32):
            problems.append('admin_token')
        if problems:
            raise ValueError('ENV=prod requires strong values (32+ characters) for: ' + ', '.join(problems))
        return self


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
