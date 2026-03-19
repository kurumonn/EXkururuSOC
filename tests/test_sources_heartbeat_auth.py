from __future__ import annotations

import importlib
import hashlib
import hmac
import time

import pytest
from fastapi import HTTPException

from exkururusoc.replay_cache import ReplayCache
from exkururusoc.routers.sources_dashboard import (
    SourceCreateRequest,
    SourceHeartbeatRequest,
    _source_heartbeat_impl,
    create_source,
)


def test_source_heartbeat_requires_source_or_admin_token(setup_env) -> None:
    source = SourceCreateRequest(
        source_id="ipros-main",
        product_name="exkururuipros",
        source_type="api",
        base_url="http://127.0.0.1:8811",
        auth_type="token",
        auth_secret_ref="hb-secret",
    )
    created = create_source(source, x_admin_token="test-admin-token")
    assert created["source_id"] == "ipros-main"

    with pytest.raises(HTTPException) as exc:
        _source_heartbeat_impl(
            "ipros-main",
            SourceHeartbeatRequest(health_payload={"status": "ok"}),
            raw_body=b'{"health_payload":{"status":"ok"}}',
            x_admin_token=None,
            x_source_token=None,
        )
    assert exc.value.status_code == 401

    allowed = _source_heartbeat_impl(
        "ipros-main",
        SourceHeartbeatRequest(health_payload={"status": "ok", "queue": 0}),
        raw_body=b'{"health_payload":{"status":"ok","queue":0}}',
        x_admin_token=None,
        x_source_token="hb-secret",
    )
    assert allowed["source_id"] == "ipros-main"
    assert allowed["last_health"]["status"] == "ok"


def test_source_heartbeat_signed_required_requires_signature_and_blocks_replay(setup_env) -> None:
    source = SourceCreateRequest(
        source_id="ipros-signed",
        product_name="exkururuipros",
        source_type="api",
        base_url="http://127.0.0.1:8811",
        auth_type="signed_required",
        auth_secret_ref="signed-secret",
    )
    created = create_source(source, x_admin_token="test-admin-token")
    assert created["source_id"] == "ipros-signed"

    req = SourceHeartbeatRequest(health_payload={"status": "ok", "queue": 1})
    raw_body = b'{"health_payload":{"status":"ok","queue":1}}'
    with pytest.raises(HTTPException) as exc:
        _source_heartbeat_impl(
            "ipros-signed",
            req,
            raw_body=raw_body,
            x_admin_token=None,
            x_source_token="signed-secret",
            x_source_timestamp=None,
            x_source_signature=None,
            x_source_nonce=None,
        )
    assert exc.value.status_code == 401
    assert exc.value.detail == "source_signature_required"

    ts = str(int(time.time()))
    nonce = "nonce-soc-001"
    sig = hmac.new(b"signed-secret", f"{ts}.{nonce}.".encode("utf-8") + raw_body, hashlib.sha256).hexdigest()

    first = _source_heartbeat_impl(
        "ipros-signed",
        req,
        raw_body=raw_body,
        x_admin_token=None,
        x_source_token="signed-secret",
        x_source_timestamp=ts,
        x_source_signature=sig,
        x_source_nonce=nonce,
    )
    assert first["source_id"] == "ipros-signed"

    with pytest.raises(HTTPException) as replay_exc:
        _source_heartbeat_impl(
            "ipros-signed",
            req,
            raw_body=raw_body,
            x_admin_token=None,
            x_source_token="signed-secret",
            x_source_timestamp=ts,
            x_source_signature=sig,
            x_source_nonce=nonce,
        )
    assert replay_exc.value.status_code == 409
    assert replay_exc.value.detail == "source_replay_detected"


def test_source_heartbeat_signed_required_uses_exact_raw_body_bytes(setup_env) -> None:
    source = SourceCreateRequest(
        source_id="ipros-signed-raw",
        product_name="exkururuipros",
        source_type="api",
        base_url="http://127.0.0.1:8811",
        auth_type="signed_required",
        auth_secret_ref="signed-secret-raw",
    )
    created = create_source(source, x_admin_token="test-admin-token")
    assert created["source_id"] == "ipros-signed-raw"

    req = SourceHeartbeatRequest(health_payload={"queue": 2, "status": "ok"})
    signed_raw_body = b'{"health_payload":{"queue":2,"status":"ok"}}'
    alt_raw_body = b'{"health_payload": {"status": "ok", "queue": 2}}'
    ts = str(int(time.time()))
    nonce = "nonce-soc-002"
    sig = hmac.new(b"signed-secret-raw", f"{ts}.{nonce}.".encode("utf-8") + signed_raw_body, hashlib.sha256).hexdigest()

    ok = _source_heartbeat_impl(
        "ipros-signed-raw",
        req,
        raw_body=signed_raw_body,
        x_admin_token=None,
        x_source_token="signed-secret-raw",
        x_source_timestamp=ts,
        x_source_signature=sig,
        x_source_nonce=nonce,
    )
    assert ok["source_id"] == "ipros-signed-raw"

    with pytest.raises(HTTPException) as mismatch_exc:
        _source_heartbeat_impl(
            "ipros-signed-raw",
            req,
            raw_body=alt_raw_body,
            x_admin_token=None,
            x_source_token="signed-secret-raw",
            x_source_timestamp=ts,
            x_source_signature=sig,
            x_source_nonce=nonce,
        )
    assert mismatch_exc.value.status_code == 401
    assert mismatch_exc.value.detail == "source_signature_invalid"


def test_source_heartbeat_signed_required_replay_across_cache_instances(monkeypatch, setup_env) -> None:
    app_context = importlib.import_module("exkururusoc.app_context")
    raw_body = b'{"health_payload":{"queue":3,"status":"ok"}}'
    ts = str(int(time.time()))
    nonce = "nonce-soc-003"
    sig = hmac.new(b"signed-secret-cross", f"{ts}.{nonce}.".encode("utf-8") + raw_body, hashlib.sha256).hexdigest()

    class _SharedRedis:
        def __init__(self, clock_fn):
            self._clock = clock_fn
            self._values: dict[str, float] = {}

        def set(self, key, value, nx=False, ex=None):
            now = float(self._clock())
            current = self._values.get(key)
            if nx and current is not None and current > now:
                return False
            self._values[key] = now + float(ex or 0)
            return True

    clock = lambda: 1000.0
    shared_redis = _SharedRedis(clock)
    cache_a = ReplayCache(
        namespace="soc",
        backend="redis",
        redis_url="redis://example.invalid/0",
        fallback_to_memory=True,
        max_items=10,
        default_ttl_sec=60,
        redis_client_factory=lambda: shared_redis,
        clock=clock,
    )
    cache_b = ReplayCache(
        namespace="soc",
        backend="redis",
        redis_url="redis://example.invalid/0",
        fallback_to_memory=True,
        max_items=10,
        default_ttl_sec=60,
        redis_client_factory=lambda: shared_redis,
        clock=clock,
    )

    monkeypatch.setattr(app_context, "_REPLAY_GUARD", cache_a, raising=False)
    app_context.verify_source_signature(
        source_id="soc-edge-01",
        source_secret="signed-secret-cross",
        raw_body=raw_body,
        timestamp=ts,
        signature=sig,
        nonce=nonce,
    )

    monkeypatch.setattr(app_context, "_REPLAY_GUARD", cache_b, raising=False)
    with pytest.raises(HTTPException) as replay_exc:
        app_context.verify_source_signature(
            source_id="soc-edge-01",
            source_secret="signed-secret-cross",
            raw_body=raw_body,
            timestamp=ts,
            signature=sig,
            nonce=nonce,
        )
    assert replay_exc.value.status_code == 409
    assert replay_exc.value.detail == "source_replay_detected"
