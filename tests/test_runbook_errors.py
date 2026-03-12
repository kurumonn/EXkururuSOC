from __future__ import annotations

import pytest
from fastapi import HTTPException

from exkururusoc.routers.safety_runbooks_feedback import (
    RunbookCreateRequest,
    RunbookExecuteRequest,
    create_runbook,
    execute_runbook,
    update_runbook,
    RunbookUpdateRequest,
)


def test_execute_nonexistent_runbook_returns_404(setup_env) -> None:
    with pytest.raises(HTTPException) as exc:
        execute_runbook(
            "missing-runbook",
            RunbookExecuteRequest(incident_ref="inc-1", operator="op"),
            x_admin_token="test-admin-token",
        )
    assert exc.value.status_code == 404
    assert exc.value.detail == "runbook_not_found"


def test_execute_disabled_runbook_returns_400(setup_env) -> None:
    create_runbook(
        RunbookCreateRequest(
            runbook_id="rb-disabled",
            name="Disabled runbook",
            incident_type="test_incident",
            trigger_condition={"severity": "high"},
            steps=[{"step": "notify"}],
            safety_policy={},
            enabled=True,
        ),
        x_admin_token="test-admin-token",
    )
    update_runbook(
        "rb-disabled",
        RunbookUpdateRequest(enabled=False),
        x_admin_token="test-admin-token",
    )
    with pytest.raises(HTTPException) as exc:
        execute_runbook(
            "rb-disabled",
            RunbookExecuteRequest(incident_ref="inc-2", operator="op"),
            x_admin_token="test-admin-token",
        )
    assert exc.value.status_code == 400
    assert exc.value.detail == "runbook_disabled"
