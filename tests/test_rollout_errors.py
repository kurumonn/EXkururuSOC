from __future__ import annotations

import pytest
from fastapi import HTTPException

from exkururusoc.routers.candidates import (
    CandidateCreateRequest,
    CandidateStatusRequest,
    create_candidate,
    update_candidate_status,
)
from exkururusoc.routers.evaluations_rollouts import RolloutCreateRequest, create_rollout
from exkururusoc.routers.safety_runbooks_feedback import (
    ProtectedAssetCreateRequest,
    SafetyGuardConfigRequest,
    create_protected_asset,
    set_safety_policy,
)


def _new_candidate() -> CandidateCreateRequest:
    return CandidateCreateRequest(
        source_product="exkururuipros",
        source_kind="rule_hit",
        candidate_type="block_strategy_tuning",
        target_scope="ip",
        target_ref="10.0.0.9",
        title="rollout target",
        proposal={"block": True},
        evidence={"events": 5},
        reason_summary="test",
        expected_benefit={"defense_delta": 0.1},
        risk_level="medium",
        created_by_type="human",
        created_by="tester",
    )


def test_rollout_requires_approved_candidate(setup_env) -> None:
    cand = create_candidate(_new_candidate(), x_admin_token="test-admin-token")
    with pytest.raises(HTTPException) as exc:
        create_rollout(
            RolloutCreateRequest(candidate_id=cand["candidate_id"], rollout_scope={"target_count": 1}),
            x_admin_token="test-admin-token",
        )
    assert exc.value.status_code == 400
    assert exc.value.detail == "candidate_not_ready_for_rollout"


def test_rollout_blocked_by_blast_radius(setup_env) -> None:
    cand = create_candidate(_new_candidate(), x_admin_token="test-admin-token")
    update_candidate_status(
        cand["candidate_id"],
        CandidateStatusRequest(status="approved", decision_note="ok"),
        x_admin_token="test-admin-token",
    )
    set_safety_policy(
        SafetyGuardConfigRequest(max_targets=1, block_protected_assets=False),
        x_admin_token="test-admin-token",
    )
    with pytest.raises(HTTPException) as exc:
        create_rollout(
            RolloutCreateRequest(candidate_id=cand["candidate_id"], rollout_scope={"target_count": 2}),
            x_admin_token="test-admin-token",
        )
    assert exc.value.status_code == 400
    assert exc.value.detail == "blast_radius_exceeded"


def test_rollout_blocked_by_protected_asset(setup_env) -> None:
    req = _new_candidate()
    req.target_ref = "10.0.0.1"
    cand = create_candidate(req, x_admin_token="test-admin-token")
    update_candidate_status(
        cand["candidate_id"],
        CandidateStatusRequest(status="approved", decision_note="ok"),
        x_admin_token="test-admin-token",
    )
    create_protected_asset(
        ProtectedAssetCreateRequest(asset_type="ip", asset_key="10.0.0.1", reason="critical"),
        x_admin_token="test-admin-token",
    )
    set_safety_policy(
        SafetyGuardConfigRequest(max_targets=10, block_protected_assets=True),
        x_admin_token="test-admin-token",
    )
    with pytest.raises(HTTPException) as exc:
        create_rollout(
            RolloutCreateRequest(candidate_id=cand["candidate_id"], rollout_scope={"target_count": 1}),
            x_admin_token="test-admin-token",
        )
    assert exc.value.status_code == 400
    assert exc.value.detail == "protected_asset_blocked"
