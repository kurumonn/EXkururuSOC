from __future__ import annotations

from fastapi import APIRouter

from ..app_context import get_read_storage
from ..config import load_settings

router = APIRouter()


@router.get("/healthz")
def healthz() -> dict[str, str]:
    settings = load_settings()
    get_read_storage()
    return {
        "status": "ok",
        "service": "exkururusoc",
        "env": settings.env,
        "db_path": settings.db_path,
    }
