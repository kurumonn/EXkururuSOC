from __future__ import annotations

import secrets
from typing import Any

from fastapi import APIRouter, Header, HTTPException, Query
from pydantic import BaseModel, Field

from ..app_context import get_read_storage, get_write_storage, require_admin_token

router = APIRouter()


class EvaluationCreateRequest(BaseModel):
    candidate_id: str = Field(min_length=1, max_length=80)
    evaluation_type: str = Field(min_length=1, max_length=40)
    dataset_ref: str | None = Field(default=None, max_length=240)
    baseline_metrics: dict[str, Any] = Field(default_factory=dict)
    candidate_metrics: dict[str, Any] = Field(default_factory=dict)
    diff_metrics: dict[str, Any] = Field(default_factory=dict)
    verdict: str = Field(min_length=1, max_length=40)
    evaluator_type: str = Field(default="human", min_length=1, max_length=20)
    evaluator_name: str = Field(default="soc_admin", min_length=1, max_length=80)


class RolloutCreateRequest(BaseModel):
    candidate_id: str = Field(min_length=1, max_length=80)
    rollout_scope: dict[str, Any] = Field(default_factory=dict)
    rollback_point: str | None = Field(default=None, max_length=240)


class RolloutRollbackRequest(BaseModel):
    reason: str = Field(default="manual_rollback", min_length=1, max_length=240)
    operator: str = Field(default="soc_admin", min_length=1, max_length=80)


@router.post("/api/v1/evaluations")
def create_evaluation(req: EvaluationCreateRequest, x_admin_token: str | None = Header(default=None)) -> dict[str, Any]:
    require_admin_token(x_admin_token)
    st = get_write_storage()
    try:
        st.get_candidate(req.candidate_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="candidate_not_found") from exc
    evaluation_id = f"eval-{secrets.token_hex(8)}"
    item = st.create_evaluation(
        evaluation_id=evaluation_id,
        candidate_id=req.candidate_id,
        evaluation_type=req.evaluation_type,
        dataset_ref=req.dataset_ref,
        baseline_metrics=req.baseline_metrics,
        candidate_metrics=req.candidate_metrics,
        diff_metrics=req.diff_metrics,
        verdict=req.verdict,
        evaluator_type=req.evaluator_type,
        evaluator_name=req.evaluator_name,
    )
    st.create_audit_log(
        audit_id=f"audit-{secrets.token_hex(8)}",
        actor_type=req.evaluator_type,
        actor_name=req.evaluator_name,
        action_type="candidate_evaluation_create",
        target_type="candidate_evaluation",
        target_ref=evaluation_id,
        before=None,
        after={"candidate_id": req.candidate_id, "verdict": req.verdict},
        result="ok",
    )
    return item


@router.get("/api/v1/evaluations")
def list_evaluations(
    candidate_id: str | None = Query(default=None),
    evaluation_type: str | None = Query(default=None),
    verdict: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=1000),
    x_admin_token: str | None = Header(default=None),
) -> dict[str, Any]:
    require_admin_token(x_admin_token)
    items = get_read_storage().list_evaluations(
        candidate_id=candidate_id,
        evaluation_type=evaluation_type,
        verdict=verdict,
        limit=limit,
    )
    return {"items": items}


@router.get("/api/v1/evaluations/{evaluation_id}")
def get_evaluation(evaluation_id: str, x_admin_token: str | None = Header(default=None)) -> dict[str, Any]:
    require_admin_token(x_admin_token)
    try:
        return get_read_storage().get_evaluation(evaluation_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="evaluation_not_found") from exc


@router.post("/api/v1/rollouts")
def create_rollout(req: RolloutCreateRequest, x_admin_token: str | None = Header(default=None)) -> dict[str, Any]:
    require_admin_token(x_admin_token)
    st = get_write_storage()
    try:
        candidate = st.get_candidate(req.candidate_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="candidate_not_found") from exc
    if candidate["status"] not in {"approved", "rollout"}:
        raise HTTPException(status_code=400, detail="candidate_not_ready_for_rollout")
    try:
        st.validate_rollout_safety(candidate_id=req.candidate_id, rollout_scope=req.rollout_scope or {"scope": "default"})
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    rollout_id = f"rollout-{secrets.token_hex(8)}"
    item = st.create_rollout_job(
        rollout_id=rollout_id,
        candidate_id=req.candidate_id,
        rollout_scope=req.rollout_scope or {"scope": "default"},
        current_stage="canary",
        status="running",
        rollback_point=req.rollback_point,
    )
    st.update_candidate_status(req.candidate_id, "rollout", "rollout_started")
    st.create_audit_log(
        audit_id=f"audit-{secrets.token_hex(8)}",
        actor_type="admin_api",
        actor_name="soc_admin",
        action_type="rollout_create",
        target_type="rollout_job",
        target_ref=rollout_id,
        before=None,
        after=item,
        result="ok",
    )
    return item


@router.get("/api/v1/rollouts")
def list_rollouts(
    candidate_id: str | None = Query(default=None),
    status: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=1000),
    x_admin_token: str | None = Header(default=None),
) -> dict[str, Any]:
    require_admin_token(x_admin_token)
    return {"items": get_read_storage().list_rollout_jobs(candidate_id=candidate_id, status=status, limit=limit)}


@router.get("/api/v1/rollouts/{rollout_id}")
def get_rollout(rollout_id: str, x_admin_token: str | None = Header(default=None)) -> dict[str, Any]:
    require_admin_token(x_admin_token)
    try:
        return get_read_storage().get_rollout_job(rollout_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="rollout_not_found") from exc


@router.post("/api/v1/rollouts/{rollout_id}/advance")
def advance_rollout(rollout_id: str, x_admin_token: str | None = Header(default=None)) -> dict[str, Any]:
    require_admin_token(x_admin_token)
    st = get_write_storage()
    try:
        before = st.get_rollout_job(rollout_id)
        item = st.advance_rollout_stage(rollout_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="rollout_not_found") from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if item["status"] == "completed":
        st.update_candidate_status(item["candidate_id"], "completed", "rollout_completed")
    st.create_audit_log(
        audit_id=f"audit-{secrets.token_hex(8)}",
        actor_type="admin_api",
        actor_name="soc_admin",
        action_type="rollout_advance",
        target_type="rollout_job",
        target_ref=rollout_id,
        before=before,
        after=item,
        result="ok",
    )
    return item


@router.post("/api/v1/rollouts/{rollout_id}/rollback")
def rollback_rollout(
    rollout_id: str,
    req: RolloutRollbackRequest,
    x_admin_token: str | None = Header(default=None),
) -> dict[str, Any]:
    require_admin_token(x_admin_token)
    st = get_write_storage()
    try:
        before = st.get_rollout_job(rollout_id)
        item = st.rollback_rollout(rollout_id, reason=req.reason)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="rollout_not_found") from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    st.update_candidate_status(item["candidate_id"], "rolled_back", req.reason)
    st.create_audit_log(
        audit_id=f"audit-{secrets.token_hex(8)}",
        actor_type="operator",
        actor_name=req.operator,
        action_type="rollout_rollback",
        target_type="rollout_job",
        target_ref=rollout_id,
        before=before,
        after=item,
        result="ok",
    )
    return item
