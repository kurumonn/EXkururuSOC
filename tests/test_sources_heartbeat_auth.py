from __future__ import annotations

import pytest
from fastapi import HTTPException

from exkururusoc.routers.sources_dashboard import SourceCreateRequest, SourceHeartbeatRequest, create_source, source_heartbeat


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
        source_heartbeat(
            "ipros-main",
            SourceHeartbeatRequest(health_payload={"status": "ok"}),
            x_admin_token=None,
            x_source_token=None,
        )
    assert exc.value.status_code == 401

    allowed = source_heartbeat(
        "ipros-main",
        SourceHeartbeatRequest(health_payload={"status": "ok", "queue": 0}),
        x_admin_token=None,
        x_source_token="hb-secret",
    )
    assert allowed["source_id"] == "ipros-main"
    assert allowed["last_health"]["status"] == "ok"
