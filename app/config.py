"""
Phishing Guard V2 — Centralized Configuration

All settings are loaded from environment variables (via .env file).
Uses Pydantic Settings for validation and type safety.
"""

from pydantic_settings import BaseSettings
from pydantic import Field
from typing import List
from functools import lru_cache


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    # ── App ──────────────────────────────────────────────
    APP_NAME: str = "Phishing Guard"
    APP_VERSION: str = "2.0.0"
    DEBUG: bool = False

    # ── Database ─────────────────────────────────────────
    DATABASE_URL: str = "postgresql://phishing_user:phishing_pass@postgres:5432/phishing_guard"

    # ── VirusTotal ───────────────────────────────────────
    VIRUSTOTAL_API_KEYS: str = ""  # Comma-separated keys

    @property
    def vt_api_keys(self) -> List[str]:
        """Parse comma-separated VT keys into a list."""
        return [k.strip() for k in self.VIRUSTOTAL_API_KEYS.split(",") if k.strip()]

    # ── Email (IMAP) ─────────────────────────────────────
    EMAIL_HOST: str = "imap.gmail.com"
    EMAIL_PORT: int = 993
    EMAIL_ADDRESS: str = ""
    EMAIL_PASSWORD: str = ""

    # ── Paths ────────────────────────────────────────────
    ATTACHMENT_DIR: str = "/app/uploads"
    MODEL_PATH: str = "/app/data/phishing_model.joblib"

    # ── Attachment Engine ────────────────────────────────
    # Maximum file size (bytes) the attachment engine will read into memory.
    # Files exceeding this are skipped and flagged in the breakdown.
    MAX_ATTACHMENT_BYTES: int = 52_428_800  # 50 MB

    # Set to True once app/integrations/virustotal.py is wired up.
    # When False, attachment analysis runs static-only (no VT hash lookups).
    ENABLE_VT_HASH_LOOKUP: bool = False

    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "extra": "ignore",
    }


@lru_cache
def get_settings() -> Settings:
    """Cached settings singleton — call this everywhere."""
    return Settings()
