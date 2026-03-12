from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    env: str
    log_level: str
    admin_token: str
    db_path: str
    allow_insecure_no_auth: bool


def load_settings() -> Settings:
    default_db = str(Path.cwd() / "data" / "exkururu_soc.db")
    insecure_raw = os.getenv("SOC_ALLOW_INSECURE_NO_AUTH", "0").strip().lower()
    return Settings(
        env=os.getenv("SOC_ENV", "dev"),
        log_level=os.getenv("SOC_LOG_LEVEL", "INFO"),
        admin_token=os.getenv("SOC_API_ADMIN_TOKEN", ""),
        db_path=os.getenv("SOC_DB_PATH", default_db),
        allow_insecure_no_auth=insecure_raw in {"1", "true", "yes", "on"},
    )
