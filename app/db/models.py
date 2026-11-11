from datetime import datetime

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    String,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.database import Base


class User(Base):
    __tablename__ = 'users'

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())

    api_keys: Mapped[list['ApiKey']] = relationship(back_populates='user', cascade='all, delete-orphan')


class ApiKey(Base):
    __tablename__ = 'api_keys'

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int | None] = mapped_column(ForeignKey('users.id', ondelete='CASCADE'), nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    key_hash: Mapped[str] = mapped_column(String(255), nullable=False, unique=True, index=True)
    key_prefix: Mapped[str] = mapped_column(String(12), nullable=False, index=True)
    last4: Mapped[str] = mapped_column(String(4), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, server_default='true')
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    user: Mapped[User | None] = relationship(back_populates='api_keys')
    usage: Mapped[list['ApiKeyUsage']] = relationship(back_populates='api_key', cascade='all, delete-orphan')


class ApiKeyUsage(Base):
    __tablename__ = 'api_key_usage'
    __table_args__ = (UniqueConstraint('api_key_id', 'window_start', name='uq_api_key_window_start'),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    api_key_id: Mapped[int] = mapped_column(ForeignKey('api_keys.id', ondelete='CASCADE'), nullable=False, index=True)
    window_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    api_key: Mapped[ApiKey] = relationship(back_populates='usage')


class RateLimitWindow(Base):
    __tablename__ = 'rate_limit_windows'
    __table_args__ = (UniqueConstraint('scope', 'identity', 'window_start', name='uq_scope_identity_window'),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scope: Mapped[str] = mapped_column(String(64), nullable=False)
    identity: Mapped[str] = mapped_column(String(255), nullable=False)
    window_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

