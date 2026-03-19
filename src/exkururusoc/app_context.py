from __future__ import annotations

import hashlib
import hmac
import os
import re
import time
from hmac import compare_digest

from fastapi import HTTPException, status

from .config import load_settings
from .replay_cache import replay_cache_from_env
from .storage import SocStorage
from .storage_facade import SocReadStorage, SocWriteStorage

_storage: SocStorage | None = None
_NONCE_PATTERN = re.compile(r"^[A-Za-z0-9._:-]{8,80}$")
_REPLAY_GUARD = replay_cache_from_env(
    namespace="soc",
    backend_env="SOC_REPLAY_BACKEND",
    redis_url_env="SOC_REDIS_URL",
    fallback_env="SOC_REPLAY_FALLBACK_TO_MEMORY",
    max_items_env="SOC_REPLAY_CACHE_MAX_ITEMS",
    ttl_env="SOC_SOURCE_REPLAY_TTL_SEC",
)


def get_storage() -> SocStorage:
    global _storage
    if _storage is None:
        _storage = SocStorage(load_settings().db_path)
    return _storage


def get_read_storage() -> SocReadStorage:
    return SocReadStorage(get_storage())


def get_write_storage() -> SocWriteStorage:
    return SocWriteStorage(get_storage())


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


def _env_bool(name: str, default: bool) -> bool:
    raw = str(os.getenv(name, "1" if default else "0") or "").strip().lower()
    return raw in {"1", "true", "on", "yes"}


def _env_int(name: str, default: int, min_value: int, max_value: int) -> int:
    raw = str(os.getenv(name, str(default)) or "").strip()
    try:
        value = int(raw)
    except ValueError:
        value = default
    return max(min_value, min(max_value, value))


def _replay_guard_add(raw_key: str, ttl_sec: int) -> bool:
    return _REPLAY_GUARD.add(raw_key, ttl_sec=ttl_sec)


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


def verify_source_signature(
    *,
    source_id: str,
    source_secret: str,
    raw_body: bytes,
    timestamp: str | None,
    signature: str | None,
    nonce: str | None,
) -> None:
    if not timestamp or not signature:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="source_signature_required")
    require_nonce = _env_bool("SOC_SOURCE_REQUIRE_NONCE", True)
    nonce_value = str(nonce or "").strip()
    if require_nonce and not nonce_value:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="source_nonce_required")
    if nonce_value and not _NONCE_PATTERN.fullmatch(nonce_value):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="source_nonce_invalid")
    try:
        ts_int = int(str(timestamp).strip())
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="invalid_source_timestamp") from exc
    now_ts = int(time.time())
    if abs(now_ts - ts_int) > _env_int("SOC_SOURCE_SIGNATURE_MAX_SKEW_SEC", 300, 30, 3600):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="source_signature_expired")
    if nonce_value:
        payload = f"{timestamp}.{nonce_value}.".encode("utf-8") + raw_body
    else:
        payload = f"{timestamp}.".encode("utf-8") + raw_body
    expected = hmac.new(source_secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()
    legacy_expected = hmac.new(source_secret.encode("utf-8"), f"{timestamp}.".encode("utf-8") + raw_body, hashlib.sha256).hexdigest()
    signature_value = str(signature).strip()
    if not compare_digest(expected, signature_value) and not (
        not require_nonce and compare_digest(legacy_expected, signature_value)
    ):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="source_signature_invalid")
    replay_raw = f"{source_id}:{timestamp}:{signature_value}:{nonce_value}"
    ttl = _env_int("SOC_SOURCE_REPLAY_TTL_SEC", 310, 30, 3600)
    if not _replay_guard_add(replay_raw, ttl_sec=ttl):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="source_replay_detected")
