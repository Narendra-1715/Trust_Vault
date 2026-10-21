import os
from typing import List, Optional
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    PROJECT_NAME: str = "TrustVault"
    VERSION: str = "1.0.0"
    API_V1_STR: str = "/api/v1"
    
    # Environment
    ENVIRONMENT: str = "development"
    DEBUG: bool = False
    
    # Security
    SECRET_KEY: str = os.getenv("SECRET_KEY", "trustvault_super_secure_secret_key_change_in_production_9988776655")
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 8  # 8 hours
    
    # Database
    DATABASE_URL: str = os.getenv(
        "DATABASE_URL", 
        "sqlite:///./data/trustvault.db"
    )
    
    # Private Storage
    STORAGE_DIR: str = os.getenv("STORAGE_DIR", "./data/vault_storage")
    MAX_FILE_SIZE_BYTES: int = 25 * 1024 * 1024  # 25 MB
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
    
    # AI Integration
    GEMINI_API_KEY: Optional[str] = os.getenv("GEMINI_API_KEY", "AQ.Ab8RN6KneIAuL4Jiv9m4Ah3ty6LT3OksWBVtlmk11bkQiRhLlQ")
    AI_PROVIDER: str = os.getenv("AI_PROVIDER", "gemini")  # "gemini" or "mock"
    AI_MODEL: str = os.getenv("AI_MODEL", "gemini-3.8-flash")
    
    # CORS
    BACKEND_CORS_ORIGINS: List[str] = [
        origin.strip()
        for origin in os.getenv(
            "BACKEND_CORS_ORIGINS",
            "http://localhost:5173,http://localhost:3000,http://127.0.0.1:5173,http://127.0.0.1:3000"
        ).split(",")
        if origin.strip()
    ]

    model_config = SettingsConfigDict(env_file=".env", case_sensitive=True, extra="ignore")

settings = Settings()
