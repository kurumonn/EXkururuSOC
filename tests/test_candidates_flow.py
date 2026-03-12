from __future__ import annotations

from exkururusoc.routers.candidates import (
    CandidateApprovalRequest,
    CandidateCreateRequest,
    apply_candidate_approval,
    create_candidate,
    list_candidates,
)


def test_candidate_create_filter_and_approval_flow(setup_env) -> None:
    payload = CandidateCreateRequest(
        source_product="exkururuipros",
        source_kind="rule_hit",
        candidate_type="rule_score_tuning",
        target_scope="rule",
        target_ref="SCAN-003",
        title="Tune SCAN-003",
        proposal={"score": 60},
        evidence={"feedback_hits": 5},
        reason_summary="Too noisy",
        expected_benefit={"fp_delta": -0.1},
        risk_level="medium",
        created_by_type="human",
        created_by="reviewer-a",
    )
    candidate = create_candidate(payload, x_admin_token="test-admin-token")
    candidate_id = candidate["candidate_id"]

    filtered = list_candidates(
        status="new",
        source_product="exkururuipros",
        candidate_type="rule_score_tuning",
        risk_level="medium",
        limit=100,
        x_admin_token="test-admin-token",
    )
    assert any(item["candidate_id"] == candidate_id for item in filtered["items"])

    hold = apply_candidate_approval(
        candidate_id,
        CandidateApprovalRequest(action="hold", decision_note="need replay", reviewer="lead-1"),
        x_admin_token="test-admin-token",
    )
    assert hold["status"] == "approval_pending"

    approve = apply_candidate_approval(
        candidate_id,
        CandidateApprovalRequest(action="approve", decision_note="ok", reviewer="lead-1"),
        x_admin_token="test-admin-token",
    )
    assert approve["status"] == "approved"
