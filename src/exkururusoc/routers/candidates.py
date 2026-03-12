from __future__ import annotations

import secrets
from typing import Any

from fastapi import APIRouter, Header, HTTPException, Query
from pydantic import BaseModel, Field

from ..app_context import get_storage, require_admin_token

router = APIRouter()


class CandidateCreateRequest(BaseModel):
    source_product: str = Field(min_length=1, max_length=40)
    source_kind: str = Field(min_length=1, max_length=40)
    candidate_type: str = Field(min_length=1, max_length=80)
    target_scope: str = Field(min_length=1, max_length=80)
    target_ref: str = Field(min_length=1, max_length=160)
    title: str = Field(min_length=1, max_length=240)
    proposal: dict[str, Any] = Field(default_factory=dict)
    evidence: dict[str, Any] = Field(default_factory=dict)
    reason_summary: str = Field(min_length=1)
    expected_benefit: dict[str, Any] = Field(default_factory=dict)
    risk_level: str = Field(default="medium", min_length=1, max_length=20)
    created_by_type: str = Field(default="human", min_length=1, max_length=20)
    created_by: str = Field(default="api", min_length=1, max_length=80)


class CandidateUpdateRequest(BaseModel):
    title: str | None = Field(default=None, min_length=1, max_length=240)
    proposal: dict[str, Any] | None = None
    evidence: dict[str, Any] | None = None
    reason_summary: str | None = None
    expected_benefit: dict[str, Any] | None = None
    risk_level: str | None = Field(default=None, min_length=1, max_length=20)


class CandidateStatusRequest(BaseModel):
    status: str = Field(min_length=1, max_length=40)
    decision_note: str = ""


class CandidateApprovalRequest(BaseModel):
    action: str = Field(min_length=4, max_length=10, description="approve|reject|hold")
    decision_note: str = ""
    reviewer: str = Field(default="soc_admin", min_length=1, max_length=80)


@router.get("/api/v1/candidates")
def list_candidates(
    status: str | None = Query(default=None),
    source_product: str | None = Query(default=None),
    candidate_type: str | None = Query(default=None),
    risk_level: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=1000),
    x_admin_token: str | None = Header(default=None),
) -> dict[str, Any]:
    require_admin_token(x_admin_token)
    return {
        "items": get_storage().list_candidates(
            status=status,
            source_product=source_product,
            candidate_type=candidate_type,
            risk_level=risk_level,
            limit=limit,
        )
    }


@router.get("/api/v1/candidates/{candidate_id}")
def get_candidate(candidate_id: str, x_admin_token: str | None = Header(default=None)) -> dict[str, Any]:
    require_admin_token(x_admin_token)
    st = get_storage()
    try:
        return st.get_candidate(candidate_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="candidate_not_found") from exc


@router.post("/api/v1/candidates")
def create_candidate(req: CandidateCreateRequest, x_admin_token: str | None = Header(default=None)) -> dict[str, Any]:
    require_admin_token(x_admin_token)
    st = get_storage()
    candidate_id = f"cand-{secrets.token_hex(8)}"
    item = st.create_candidate(
        candidate_id=candidate_id,
        source_product=req.source_product,
        source_kind=req.source_kind,
        candidate_type=req.candidate_type,
        target_scope=req.target_scope,
        target_ref=req.target_ref,
        title=req.title,
        proposal=req.proposal,
        evidence=req.evidence,
        reason_summary=req.reason_summary,
        expected_benefit=req.expected_benefit,
        risk_level=req.risk_level,
        created_by_type=req.created_by_type,
        created_by=req.created_by,
    )
    st.create_audit_log(
        audit_id=f"audit-{secrets.token_hex(8)}",
        actor_type=req.created_by_type,
        actor_name=req.created_by,
        action_type="candidate_create",
        target_type="improvement_candidate",
        target_ref=candidate_id,
        before=None,
        after=item,
        result="ok",
    )
    return item


@router.put("/api/v1/candidates/{candidate_id}")
def update_candidate(
    candidate_id: str,
    req: CandidateUpdateRequest,
    x_admin_token: str | None = Header(default=None),
) -> dict[str, Any]:
    require_admin_token(x_admin_token)
    st = get_storage()
    try:
        before = st.get_candidate(candidate_id)
        item = st.update_candidate(
            candidate_id,
            title=req.title,
            proposal=req.proposal,
            evidence=req.evidence,
            reason_summary=req.reason_summary,
            expected_benefit=req.expected_benefit,
            risk_level=req.risk_level,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="candidate_not_found") from exc
    st.create_audit_log(
        audit_id=f"audit-{secrets.token_hex(8)}",
        actor_type="admin_api",
        actor_name="soc_admin",
        action_type="candidate_update",
        target_type="improvement_candidate",
        target_ref=candidate_id,
        before=before,
        after=item,
        result="ok",
    )
    return item


@router.post("/api/v1/candidates/{candidate_id}/status")
def update_candidate_status(
    candidate_id: str,
    req: CandidateStatusRequest,
    x_admin_token: str | None = Header(default=None),
) -> dict[str, Any]:
    require_admin_token(x_admin_token)
    st = get_storage()
    try:
        before = st.get_candidate(candidate_id)
        item = st.update_candidate_status(candidate_id, req.status, req.decision_note)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="candidate_not_found") from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    st.create_audit_log(
        audit_id=f"audit-{secrets.token_hex(8)}",
        actor_type="admin_api",
        actor_name="soc_admin",
        action_type="candidate_status_update",
        target_type="improvement_candidate",
        target_ref=candidate_id,
        before=before,
        after=item,
        result="ok",
    )
    return item


@router.post("/api/v1/candidates/{candidate_id}/approval")
def apply_candidate_approval(
    candidate_id: str,
    req: CandidateApprovalRequest,
    x_admin_token: str | None = Header(default=None),
) -> dict[str, Any]:
    require_admin_token(x_admin_token)
    st = get_storage()
    try:
        before = st.get_candidate(candidate_id)
        item = st.apply_approval_action(candidate_id, action=req.action, decision_note=req.decision_note)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="candidate_not_found") from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    st.create_audit_log(
        audit_id=f"audit-{secrets.token_hex(8)}",
        actor_type="reviewer",
        actor_name=req.reviewer,
        action_type=f"candidate_{req.action}",
        target_type="improvement_candidate",
        target_ref=candidate_id,
        before=before,
        after=item,
        result="ok",
    )
    return item
