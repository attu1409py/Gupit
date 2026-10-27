"""Application configuration using Pydantic Settings."""

from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # App Information
    APP_NAME: str = "Gupit"
    APP_VERSION: str = "0.1.0"
    ENVIRONMENT: str = "development"
    DEBUG: bool = True

    # Server Configuration
    HOST: str = "127.0.0.1"
    PORT: int = 8000
    FRONTEND_URL: str = "http://localhost:5173"

    # Cryptography & Master Key Management
    # 32-byte hex key used to protect user private keys at rest in this prototype
    SERVER_MASTER_KEY: str = "0000000000000000000000000000000000000000000000000000000000000000"
    SESSION_SECRET_KEY: str = "change-me-to-a-secure-random-secret-for-session-signing-at-least-32-chars"

    # Session & Cookie Security
    SESSION_COOKIE_NAME: str = "gupit_session"
    SESSION_MAX_AGE_SECONDS: int = 86400
    COOKIE_SECURE: bool = False
    COOKIE_SAMESITE: str = "lax"
    CSRF_COOKIE_NAME: str = "gupit_csrf"

    # Persistence & Storage
    DATABASE_URL: str = "sqlite:///./app/data/gupit_dev.db"
    STORAGE_BACKEND: str = "local"
    LOCAL_STORAGE_DIR: str = "./storage/packages"

    # Policies & Thresholds
    MAX_FILE_SIZE_BYTES: int = 52428800  # 50 MB
    DEFAULT_SHARE_EXPIRY_HOURS: int = 72
    MAX_DOWNLOAD_LIMIT: int = 10

    model_config = SettingsConfigDict(
        env_file=str(Path(__file__).resolve().parent.parent.parent.parent / ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )


settings = Settings()
