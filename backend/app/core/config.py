import os
from typing import List, Optional, Union
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import field_validator

class Settings(BaseSettings):
    PROJECT_NAME: str = "TrustVault"
    VERSION: str = "1.0.0"
    API_V1_STR: str = "/api/v1"
    COMMIT_SHA: str = os.getenv("RENDER_GIT_COMMIT", os.getenv("GIT_COMMIT", os.getenv("COMMIT_SHA", "local-dev")))
    
    # Environment
    ENVIRONMENT: str = "development"
    DEBUG: bool = False
    
    # Security
    SECRET_KEY: str = "trustvault_super_secure_secret_key_change_in_production_9988776655"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 8  # 8 hours

    # Information Leak Hardening & Timing Equalization (Phase 4 / Invariant I3)
    TIMING_EQUALIZATION_ENABLED: bool = True
    TIMING_LATENCY_FLOOR_MS: int = 30  # Milliseconds minimum floor for authorization denials
    TIMING_JITTER_MAX_MS: int = 15     # Milliseconds max cryptographically random jitter

    # Audit Ledger & Cryptographic Chaining (Phase 5 / Invariant I5)
    AUDIT_HMAC_KEY: str = "trustvault_audit_hmac_secret_key_distinct_from_data_encryption_9988"
    AUDIT_IP_SALT_SECRET: str = "trustvault_daily_ip_salt_secret_change_in_production_11223344"
    AUDIT_CHECKPOINT_DIR: str = "./data/audit_checkpoints"

    # Key Management & Envelope Encryption (Phase 2)
    KMS_PROVIDER: str = "local"  # "local", "aws_kms", "gcp_kms", "vault", "env"
    LOCAL_KEK: Optional[str] = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"  # 256-bit hex KEK
    AWS_KMS_KEY_ARN: Optional[str] = None
    GCP_KMS_KEY_NAME: Optional[str] = None
    VAULT_TRANSIT_KEY_NAME: Optional[str] = None

    @field_validator("KMS_PROVIDER")
    @classmethod
    def validate_kms_provider(cls, v: str, info) -> str:
        # Fail closed in production if local key provider is selected without non-default KEK
        env = info.data.get("ENVIRONMENT", "development") if hasattr(info, "data") else "development"
        local_kek = info.data.get("LOCAL_KEK") if hasattr(info, "data") else None
        dev_default = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        if env and str(env).lower() == "production":
            if str(v).lower() == "local" and (not local_kek or local_kek == dev_default):
                raise ValueError("LocalDevKeyProvider with default static dev KEK is strictly prohibited when ENVIRONMENT=production. A production KMS provider or distinct LOCAL_KEK must be configured.")
        return v
    
    # Database
    DATABASE_URL: str = "sqlite:///./data/trustvault.db"
    
    @field_validator("DATABASE_URL", mode="before")
    @classmethod
    def assemble_db_connection(cls, v: str) -> str:
        if isinstance(v, str):
            if v.startswith("postgres://"):
                return v.replace("postgres://", "postgresql+psycopg://", 1)
            elif v.startswith("postgresql://") and not v.startswith("postgresql+"):
                return v.replace("postgresql://", "postgresql+psycopg://", 1)
            elif v.startswith("sqlite:///./data/"):
                backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
                db_file = v.replace("sqlite:///./data/", "")
                resolved_path = os.path.join(backend_dir, "data", db_file).replace("\\", "/")
                return f"sqlite:///{resolved_path}"
        return v
    
    # Private Storage
    STORAGE_BACKEND: str = "local"  # "local" or "s3"
    STORAGE_DIR: str = "./data/vault_storage"
    S3_ENDPOINT_URL: Optional[str] = None  # Supabase, Cloudflare R2, or AWS S3 endpoint
    S3_BUCKET_NAME: Optional[str] = None
    S3_ACCESS_KEY_ID: Optional[str] = None
    S3_SECRET_ACCESS_KEY: Optional[str] = None
    S3_REGION_NAME: Optional[str] = "us-east-1"
    MAX_FILE_SIZE_BYTES: int = 50 * 1024 * 1024  # 50 MB hard cap (Phase 9)
    MAX_JSON_BODY_BYTES: int = 1 * 1024 * 1024   # 1 MB hard cap for JSON APIs (Phase 9)

    # External Security Posture & Headers (Phase 9)
    HSTS_MAX_AGE_SECONDS: int = 63072000  # 2 years (preload eligible)
    HSTS_INCLUDE_SUBDOMAINS: bool = True
    HSTS_PRELOAD: bool = True
    ENFORCE_CLOUDFLARE_ORIGIN: bool = False  # Set True in production to reject direct-to-origin

    # Cookie Security (Phase 9 RFC 6265bis __Host- prefix)
    SESSION_COOKIE_NAME: str = "__Host-trustvault_session"
    COOKIE_SECURE: bool = True
    COOKIE_SAMESITE: str = "Strict"

    # Security Observability, SIEM & Webhooks (Phase 11)
    STRUCTURED_LOGGING_ENABLED: bool = True
    LOG_LEVEL: str = "INFO"
    SECURITY_WEBHOOK_ENABLED: bool = False
    SECURITY_WEBHOOK_URL: Optional[str] = None
    SECURITY_WEBHOOK_SECRET: Optional[str] = None  # HMAC-SHA256 signing secret
    SECURITY_WEBHOOK_MAX_PER_MINUTE: int = 10
    SIEM_SYSLOG_HOST: Optional[str] = None
    SIEM_SYSLOG_PORT: Optional[int] = 514

    # Backup & Disaster Recovery
    BACKUP_DIR: str = "./data/backups"
    BACKUP_ENCRYPTION_KEY: Optional[str] = None
    BACKUP_RETENTION_COUNT: int = 14
    ALLOWED_EXTENSIONS: List[str] = [
        "pdf", "docx", "xlsx", "pptx", "txt", "csv", "json", "md", "png", "jpg", "jpeg"
    ]
    ALLOWED_MIME_TYPES: List[str] = [
        "application/pdf",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        "text/plain",
        "text/csv",
        "application/json",
        "text/markdown",
        "image/png",
        "image/jpeg"
    ]
    
    # Demo Data Seeding
    SEED_DEMO_DATA: bool = False

    # AI Integration
    GEMINI_API_KEY: Optional[str] = None
    AI_PROVIDER: str = "gemini"  # "gemini" or "mock"
    AI_MODEL: str = "gemini-3.8-flash"
    
    # CORS
    BACKEND_CORS_ORIGINS: Union[str, List[str]] = [
        "http://localhost:5173",
        "http://localhost:3000",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:3000"
    ]

    @property
    def cors_origins(self) -> List[str]:
        val = self.BACKEND_CORS_ORIGINS
        if isinstance(val, list):
            return [o.strip() for o in val if o and o.strip() != "*" and o.strip().lower() != "null"]
        if isinstance(val, str):
            val = val.strip()
            if val.startswith("["):
                try:
                    import json
                    parsed = json.loads(val)
                    return [o.strip() for o in parsed if o and o.strip() != "*" and o.strip().lower() != "null"]
                except Exception:
                    pass
            return [origin.strip() for origin in val.split(",") if origin.strip() and origin.strip() != "*" and origin.strip().lower() != "null"]
        return []

    model_config = SettingsConfigDict(env_file=".env", case_sensitive=True, extra="ignore")

settings = Settings()
