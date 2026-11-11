"""Production entry point. Scans are ephemeral and public history is retired.

Release checks: validate ASGI proxy client identity and infrastructure logging.
Auth/key routes remain disabled for the public beta; admin retains its controls.
"""
import asyncio
from contextlib import asynccontextmanager, suppress

from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint

from app.auth import require_admin_ip_allowlist, require_admin_token
from app.db.database import engine, initialize_database
from app.db.deps import get_db
from app.db.models import ApiKey
from app.routers.analyze import router as analyze_router
from app.scan_limits import (
    PrivateRequestMiddleware,
    RequestWorkAdmission,
    ScanRateLimiter,
    configure_private_server_logging,
)
from app.settings import get_settings

settings = get_settings()
configure_private_server_logging()


@asynccontextmanager
async def lifespan(application: FastAPI):
    initialize_database()

    async def expire_idle_identities():
        # No request traffic is needed to remove expired client identities.
        while True:
            await asyncio.sleep(1)
            application.state.scan_limiter.expire()

    cleanup = asyncio.create_task(expire_idle_identities())
    application.state.scan_cleanup_task = cleanup
    try:
        yield
    finally:
        cleanup.cancel()
        with suppress(asyncio.CancelledError):
            await cleanup


app = FastAPI(title='MobileShield AI', lifespan=lifespan)
app.state.scan_limiter = ScanRateLimiter(settings.rate_limit_per_minute)
app.state.scan_work = RequestWorkAdmission()
origins = [origin.strip() for origin in settings.cors_origins.split(',') if origin.strip()]
app.add_middleware(CORSMiddleware, allow_origins=origins, allow_credentials=False,
                   allow_methods=['*'], allow_headers=['*'])


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        response = await call_next(request)
        response.headers.setdefault('X-Content-Type-Options', 'nosniff')
        response.headers.setdefault('Referrer-Policy', 'no-referrer')
        response.headers.setdefault('X-Frame-Options', 'DENY')
        docs_paths = {'/docs', '/docs/', '/redoc', '/openapi.json', '/docs/oauth2-redirect'}
        # Match the router's ASGI path: malformed Host values can poison the
        # path reconstructed by older Starlette versions in request.url.
        if request.scope['path'] in docs_paths:
            # Relaxed CSP for Swagger UI assets from jsdelivr
            csp = (
                "default-src 'self'; "
                "base-uri 'self'; "
                "frame-ancestors 'none'; "
                "object-src 'none'; "
                "img-src 'self' data: https://fastapi.tiangolo.com https:; "
                "font-src 'self' data: https:; "
                "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
                "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
                "connect-src 'self' https:;"
            )
            response.headers['Content-Security-Policy'] = csp
        else:
            response.headers.setdefault('Content-Security-Policy', "default-src 'none'; frame-ancestors 'none'")
        return response


app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(PrivateRequestMiddleware, cors_origins=origins)
app.include_router(analyze_router)


@app.exception_handler(RequestValidationError)
async def validation_error(request: Request, exc: RequestValidationError):
    # Pydantic loc/msg/ctx can also contain attacker-controlled keys or values.
    return JSONResponse(status_code=422, content={
        'detail': [{'type': 'invalid_request', 'loc': ['body']}],
        'request_id': request.state.request_id,
    })


@app.exception_handler(StarletteHTTPException)
async def http_error(request: Request, exc: StarletteHTTPException):
    # Even a library-raised HTTPException may carry private detail or headers.
    codes = {401: 'unauthorized', 403: 'forbidden', 404: 'not_found',
             405: 'method_not_allowed', 409: 'client_upgrade_required', 410: 'scan_history_unavailable',
             413: 'body_too_large', 422: 'invalid_request',
             429: 'rate_limit_exceeded', 503: 'analysis_unavailable'}
    return JSONResponse(status_code=exc.status_code, content={
        'detail': codes.get(exc.status_code, 'request_failed'),
        'request_id': request.state.request_id,
        **({'message': 'Refresh or update your client before trying again.'} if exc.status_code == 409 else {}),
    })


class CreateApiKeyRequest(BaseModel):
    name: str = Field(min_length=2, max_length=120)


@app.get('/health')
def health() -> dict:
    return {'ok': True, 'service': settings.app_name}


@app.get('/readyz')
def readyz() -> dict:
    try:
        with engine.connect() as connection:
            connection.execute(text('SELECT 1'))
        return {'ready': True}
    except OperationalError:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail='database not ready') from None


@app.post('/admin/create-api-key')
def create_api_key(
    payload: CreateApiKeyRequest,
    _: None = Depends(require_admin_token),
    __: None = Depends(require_admin_ip_allowlist),
    db: Session = Depends(get_db),
) -> dict:
    from app.security import generate_api_key, hash_api_key

    api_key_value = generate_api_key()
    key_hash, prefix, last4 = hash_api_key(api_key_value)
    record = ApiKey(name=payload.name, key_hash=key_hash, key_prefix=prefix, last4=last4, is_active=True)
    db.add(record)
    db.commit()
    return {'name': payload.name, 'api_key': api_key_value}
