from __future__ import annotations

import os
from hmac import compare_digest

from fastapi import HTTPException, status

from .config import load_settings
from .storage import SocStorage

_storage: SocStorage | None = None


def get_storage() -> SocStorage:
    global _storage
    if _storage is None:
        _storage = SocStorage(load_settings().db_path)
    return _storage


def require_admin_token(x_admin_token: str | None) -> None:
    settings = load_settings()
    if not settings.admin_token:
        if settings.allow_insecure_no_auth:
            return
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="admin_token_not_configured")
    if not x_admin_token or not compare_digest(x_admin_token, settings.admin_token):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid_admin_token")


def is_admin_token_valid(x_admin_token: str | None) -> bool:
    settings = load_settings()
    if not settings.admin_token:
        return bool(settings.allow_insecure_no_auth)
    return bool(x_admin_token) and compare_digest(x_admin_token, settings.admin_token)


def resolve_secret_ref(secret_ref: str) -> str:
    if secret_ref.startswith("env:"):
        return os.getenv(secret_ref.split(":", 1)[1], "")
    return secret_ref


def require_source_or_admin_token(
    *,
    source_id: str,
    x_admin_token: str | None,
    x_source_token: str | None,
) -> None:
    if is_admin_token_valid(x_admin_token):
        return
    st = get_storage()
    try:
        source = st.get_source(source_id)
    except KeyError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="source_not_found") from exc
    configured = resolve_secret_ref(str(source.get("auth_secret_ref", "")))
    if not configured:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="source_token_not_configured")
    if not x_source_token or not compare_digest(x_source_token, configured):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid_source_token")
