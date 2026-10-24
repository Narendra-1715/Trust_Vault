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
    KMS_PROVIDER: str = "local"  # "local", "aws_kms", "gcp_kms", "vault"
    LOCAL_KEK: Optional[str] = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"  # 256-bit hex KEK
    AWS_KMS_KEY_ARN: Optional[str] = None
    GCP_KMS_KEY_NAME: Optional[str] = None
    VAULT_TRANSIT_KEY_NAME: Optional[str] = None

    @field_validator("KMS_PROVIDER")
    @classmethod
    def validate_kms_provider(cls, v: str, info) -> str:
        # Fail closed in production if local key provider is selected
        env = info.data.get("ENVIRONMENT", "development") if hasattr(info, "data") else "development"
        if env and str(env).lower() == "production" and str(v).lower() == "local":
            raise ValueError("LocalDevKeyProvider is strictly prohibited when ENVIRONMENT=production. A production KMS provider must be configured.")
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
    MAX_FILE_SIZE_BYTES: int = 25 * 1024 * 1024  # 25 MB

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
            return val
        if isinstance(val, str):
            val = val.strip()
            if val.startswith("["):
                try:
                    import json
                    return json.loads(val)
                except Exception:
                    pass
            return [origin.strip() for origin in val.split(",") if origin.strip()]
        return ["*"]

    model_config = SettingsConfigDict(env_file=".env", case_sensitive=True, extra="ignore")

settings = Settings()
