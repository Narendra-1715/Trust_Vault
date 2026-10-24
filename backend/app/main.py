import json
import uuid
import time
from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from app.core.config import settings
from app.core.rate_limit import get_client_ip
from app.core.logging import (
    setup_structured_logging,
    request_id_ctx,
    correlation_id_ctx,
    client_ip_ctx
)
from app.services.authorization import DocumentNotFoundException, not_found_response
from app.api.v1 import auth, users, admin, documents, permissions, audit, ai, health, notifications, access_requests, alerts, backups, security_policies, access_reviews, policy_simulator

# Phase 11: Initialize Structured Logging
if settings.STRUCTURED_LOGGING_ENABLED:
    setup_structured_logging(settings.LOG_LEVEL)

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="TrustVault - Confidential Document Management Platform API",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Invariant I3: Uniform 404 Exception Handler (Byte-identical body & headers, zero existence leaks)
@app.exception_handler(DocumentNotFoundException)
async def document_not_found_handler(request: Request, exc: DocumentNotFoundException):
    return not_found_response()

# Global Unhandled Exception Handler (ensures CORS headers and clean JSON on unexpected errors)
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled exception on {request.method} {request.url.path}: {exc}", exc_info=True)
    origin = request.headers.get("origin")
    cors_hdrs = {}
    if origin and (origin in settings.cors_origins or origin.endswith(".onrender.com")):
        cors_hdrs["Access-Control-Allow-Origin"] = origin
        cors_hdrs["Access-Control-Allow-Credentials"] = "true"
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "An internal server error occurred."},
        headers=cors_hdrs
    )

# Phase 9: Request Body Size Enforcement ASGI Middleware
# Hard cap 50 MB for file uploads, 1 MB for JSON API payloads.
# Rejects oversized payloads BEFORE buffering to disk or memory.
class RequestBodyLimitMiddleware:
    def __init__(self, app, max_upload_bytes: int = settings.MAX_FILE_SIZE_BYTES, max_json_bytes: int = settings.MAX_JSON_BODY_BYTES):
        self.app = app
        self.max_upload_bytes = max_upload_bytes
        self.max_json_bytes = max_json_bytes

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")
        method = scope.get("method", "GET")
        is_upload = (
            path.endswith("/upload") or
            ("/versions" in path and method == "POST")
        )
        max_limit = self.max_upload_bytes if is_upload else self.max_json_bytes

        # 1. Early Content-Length Header Check
        headers = dict(scope.get("headers", []))
        cl_header = headers.get(b"content-length")
        if cl_header:
            try:
                cl_val = int(cl_header.decode("ascii"))
                if cl_val > max_limit:
                    await self._send_413(send, max_limit)
                    return
            except ValueError:
                pass

        # 2. Streaming Chunk Limiter (Defends against chunked/unbounded streams)
        received_bytes = 0
        async def limited_receive():
            nonlocal received_bytes
            message = await receive()
            if message["type"] == "http.request":
                chunk_len = len(message.get("body", b""))
                received_bytes += chunk_len
                if received_bytes > max_limit:
                    raise MemoryError("payload_too_large")
            return message

        try:
            await self.app(scope, limited_receive, send)
        except MemoryError as e:
            if str(e) == "payload_too_large":
                await self._send_413(send, max_limit)
            else:
                raise

    async def _send_413(self, send, max_limit: int):
        body = json.dumps({
            "detail": f"Request entity too large. Maximum allowed request size is {max_limit} bytes."
        }).encode("utf-8")
        hsts_val = f"max-age={settings.HSTS_MAX_AGE_SECONDS}; includeSubDomains" + ("; preload" if settings.HSTS_PRELOAD else "")
        await send({
            "type": "http.response.start",
            "status": 413,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode("ascii")),
                (b"x-content-type-options", b"nosniff"),
                (b"x-frame-options", b"DENY"),
                (b"content-security-policy", b"default-src 'none'; frame-ancestors 'none'; object-src 'none';"),
                (b"strict-transport-security", hsts_val.encode("ascii")),
                (b"cross-origin-resource-policy", b"same-origin"),
                (b"connection", b"close")
            ]
        })
        await send({"type": "http.response.body", "body": body})

app.add_middleware(RequestBodyLimitMiddleware)

# Phase 9: Comprehensive Security Headers & Direct-to-Origin Middleware
class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # Cloudflare Direct-to-Origin Enforcement (when enabled in production)
        if settings.ENFORCE_CLOUDFLARE_ORIGIN:
            cf_ray = request.headers.get("cf-ray")
            cf_connecting_ip = request.headers.get("cf-connecting-ip")
            if not cf_ray or not cf_connecting_ip:
                return JSONResponse(
                    status_code=status.HTTP_403_FORBIDDEN,
                    content={"detail": "Direct-to-origin access is forbidden. All traffic must transit Cloudflare."}
                )

        response = await call_next(request)

        # Phase 9 Required External Security Headers
        hsts_header = f"max-age={settings.HSTS_MAX_AGE_SECONDS}; includeSubDomains"
        if settings.HSTS_PRELOAD:
            hsts_header += "; preload"
        response.headers["Strict-Transport-Security"] = hsts_header
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), usb=(), payment=()"
        response.headers["Cross-Origin-Embedder-Policy"] = "require-corp"
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"

        # Cross-Origin-Resource-Policy: Permit permitted frontend origins (e.g. Render UI) to read cross-origin API responses
        origin_header = request.headers.get("origin")
        if origin_header and (origin_header in settings.cors_origins or "onrender.com" in origin_header):
            response.headers["Cross-Origin-Resource-Policy"] = "cross-origin"
        else:
            response.headers["Cross-Origin-Resource-Policy"] = "same-origin"

        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"

        # Content-Security-Policy (default restrictive policy)
        if "Content-Security-Policy" not in response.headers:
            response.headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'none'; object-src 'none';"

        # Invariant I2 & Phase 3: Zero-cache guarantees across all API and content routes
        if request.url.path.startswith("/api/") or "/download" in request.url.path or "/pages/" in request.url.path:
            response.headers["Cache-Control"] = "no-store, private"
            response.headers["Pragma"] = "no-cache"

        # Phase 9 CORS Strictness: Never allow credentials if origin was not explicitly permitted
        allow_origin = response.headers.get("access-control-allow-origin")
        if not allow_origin or (allow_origin not in settings.cors_origins and not allow_origin.endswith(".onrender.com")):
            if "access-control-allow-credentials" in response.headers:
                del response.headers["access-control-allow-credentials"]

        return response

# Phase 9: Hardened CORS Middleware (runs inside SecurityHeadersMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_origin_regex=r"^https:\/\/.*\.onrender\.com$",
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["*"],
    max_age=600,  # Preflight cache max-age capped
    expose_headers=[
        "Content-Disposition",
        "X-Content-Type-Options",
        "Content-Length",
        "Cache-Control",
        "Pragma",
        "Cross-Origin-Resource-Policy",
        "X-TrustVault-Page",
        "X-TrustVault-Total-Pages",
        "X-TrustVault-Watermark",
        "Retry-After",
        "X-Request-ID",
        "X-Correlation-ID"
    ]
)

# Phase 11: Request Tracing and Context Correlation Middleware
class CorrelationLoggingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        req_id = request.headers.get("x-request-id") or str(uuid.uuid4())
        correlation_id = request.headers.get("x-correlation-id") or req_id
        client_ip = get_client_ip(request)

        # Set asynchronous context variables for structured logger
        req_token = request_id_ctx.set(req_id)
        corr_token = correlation_id_ctx.set(correlation_id)
        ip_token = client_ip_ctx.set(client_ip)

        try:
            response = await call_next(request)
            response.headers["X-Request-ID"] = req_id
            response.headers["X-Correlation-ID"] = correlation_id
            return response
        finally:
            request_id_ctx.reset(req_token)
            correlation_id_ctx.reset(corr_token)
            client_ip_ctx.reset(ip_token)

app.add_middleware(CorrelationLoggingMiddleware)

# Outermost: SecurityHeadersMiddleware (runs on final response after all inner handlers)
app.add_middleware(SecurityHeadersMiddleware)

# Include API v1 Routers
api_v1 = f"{settings.API_V1_STR}"
app.include_router(auth.router, prefix=f"{api_v1}/auth", tags=["Authentication"])
app.include_router(admin.router, prefix=f"{api_v1}/admin", tags=["Administrative Control"])
app.include_router(users.router, prefix=f"{api_v1}/users", tags=["Users & Administration"])
app.include_router(documents.router, prefix=f"{api_v1}/documents", tags=["Documents"])
app.include_router(permissions.router, prefix=f"{api_v1}", tags=["Permissions"])
app.include_router(notifications.router, prefix=f"{api_v1}/notifications", tags=["Security Alerts"])
app.include_router(alerts.router, prefix=f"{api_v1}/alerts", tags=["Security Alerts & Incident Response"])
app.include_router(security_policies.router, prefix=f"{api_v1}/security-policies", tags=["Document Classification & Security Policies"])
app.include_router(access_reviews.router, prefix=f"{api_v1}/access-reviews", tags=["Periodic Access Reviews"])
app.include_router(policy_simulator.router, prefix=f"{api_v1}/policy-simulator", tags=["Access Policy Simulator"])
app.include_router(backups.router, prefix=f"{api_v1}/backups", tags=["Backup & Disaster Recovery"])
app.include_router(access_requests.router, prefix=f"{api_v1}/access-requests", tags=["Access Requests"])
app.include_router(ai.router, prefix=f"{api_v1}", tags=["AI Access Recommendations"])
app.include_router(audit.router, prefix=f"{api_v1}/audit", tags=["Audit & Integrity"])
app.include_router(health.router, prefix=f"{api_v1}", tags=["Health Check"])

@app.get("/")
def root():
    return {
        "name": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "docs": "/docs",
        "health": f"{settings.API_V1_STR}/health"
    }
