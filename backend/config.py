import os
import secrets

from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    APP_NAME: str = "APK Threat Analysis Platform"
    VERSION: str = "1.0.0"
    DEBUG: bool = False

    # MongoDB
    MONGODB_URL: str = "mongodb://localhost:27017"
    MONGODB_DB_NAME: str = "apk_threat_analyzer"

    # File storage
    UPLOAD_DIR: str = "data/uploads"
    EXTRACT_DIR: str = "data/extracted"
    REPORT_DIR: str = "data/reports"
    MAX_FILE_SIZE: int = 200 * 1024 * 1024  # 200MB

    # Analysis
    ANALYSIS_TIMEOUT: int = 600  # 10 minutes
    JADX_PATH: str = "jadx"
    APKTOOL_PATH: str = "apktool"
    AAPT_PATH: str = "aapt"

    # Auth
    SECRET_KEY: str = os.getenv("SECRET_KEY", "") or secrets.token_urlsafe(32)
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60

    # Security
    ALLOWED_ORIGINS: str = "http://localhost:3000,http://localhost:5173,http://127.0.0.1:3000,http://127.0.0.1:5173"
    RATE_LIMIT_PER_MINUTE: int = 100
    UPLOAD_RATE_LIMIT_PER_MINUTE: int = 10

    # ML
    ML_MODEL_PATH: str = "ml_models/classifier.onnx"

    # YARA
    YARA_RULES_DIR: str = "yara_rules"

    # IOC
    IOC_DIR: str = "static/iocs"

    # Paths
    class Config:
        env_file = ".env"

settings = Settings()
