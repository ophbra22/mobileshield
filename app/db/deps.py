from collections.abc import Generator

import jwt
from fastapi import Depends, Header, HTTPException, status
from sqlalchemy.orm import Session

from app.db.database import SessionLocal
from app.db.models import User
from app.security import decode_jwt


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def user_from_bearer(authorization: str | None, db: Session) -> User:
    """Resolve ``Authorization: Bearer <jwt>`` to a user or raise 401."""
    if not authorization or not authorization.lower().startswith('bearer '):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Not authenticated')
    try:
        payload = decode_jwt(authorization.split(' ', 1)[1])
        user_id = int(payload['sub'])
    except (jwt.InvalidTokenError, KeyError, TypeError, ValueError):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Invalid token') from None
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='User not found')
    return user


def get_current_user(authorization: str | None = Header(default=None, alias='Authorization'),
                     db: Session = Depends(get_db)) -> User:
    return user_from_bearer(authorization, db)
