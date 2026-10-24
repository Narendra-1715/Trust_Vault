from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from app.core.config import settings
from app.api.v1 import auth, users, documents, permissions, audit, ai, health, notifications, access_requests

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="TrustVault - Confidential Document Management Platform API",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Strict Security Headers Middleware
class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        if not settings.DEBUG:
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response

app.add_middleware(SecurityHeadersMiddleware)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["*"],
    expose_headers=["Content-Disposition", "X-Content-Type-Options", "Content-Length"]
)

# Include API v1 Routers
api_v1 = f"{settings.API_V1_STR}"
app.include_router(auth.router, prefix=f"{api_v1}/auth", tags=["Authentication"])
app.include_router(users.router, prefix=f"{api_v1}/users", tags=["Users & Administration"])
app.include_router(documents.router, prefix=f"{api_v1}/documents", tags=["Documents"])
app.include_router(permissions.router, prefix=f"{api_v1}", tags=["Permissions"])
app.include_router(notifications.router, prefix=f"{api_v1}/notifications", tags=["Security Alerts"])
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
