"""
Application configuration
"""
from pydantic_settings import BaseSettings
from typing import List

class Settings(BaseSettings):
    """Application settings"""

    # Application
    APP_NAME: str = "Nmap Scanner"
    ENVIRONMENT: str = "development"
    SECRET_KEY: str = "your-secret-key-change-in-production"

    # Database
    DATABASE_URL: str = "postgresql://scanner_user:scanner_pass_2024@database:5432/nmap_scanner"

    # Redis
    REDIS_URL: str = "redis://redis:6379/0"

    # CORS
    CORS_ORIGINS: List[str] = [
        "http://localhost:3000",
        "http://localhost:8000",
        "http://frontend:80"
    ]

    # Scan settings
    MAX_CONCURRENT_SCANS: int = 5
    SCAN_RESULTS_DIR: str = "/app/scan_results"
    DEFAULT_SCAN_TIMEOUT: int = 1800  # 30 minutes

    # Nmap settings
    NMAP_PATH: str = "/usr/bin/nmap"

    class Config:
        env_file = ".env"
        case_sensitive = True

settings = Settings()
