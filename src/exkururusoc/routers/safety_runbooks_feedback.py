from __future__ import annotations

import secrets
from typing import Any

from fastapi import APIRouter, Header, HTTPException, Query
from pydantic import BaseModel, Field

from ..app_context import get_storage, require_admin_token

router = APIRouter()


class SafetyGuardConfigRequest(BaseModel):
    max_targets: int = Field(default=10, ge=1, le=100000)
    block_protected_assets: bool = True


class ProtectedAssetCreateRequest(BaseModel):
    asset_type: str = Field(min_length=1, max_length=40)
    asset_key: str = Field(min_length=1, max_length=160)
    reason: str = ""


class RunbookCreateRequest(BaseModel):
    runbook_id: str = Field(min_length=3, max_length=80, pattern=r"^[a-z0-9_-]+$")
    name: str = Field(min_length=1, max_length=200)
    incident_type: str = Field(min_length=1, max_length=80)
    trigger_condition: dict[str, Any] = Field(default_factory=dict)
    steps: list[dict[str, Any]] = Field(default_factory=list)
    safety_policy: dict[str, Any] = Field(default_factory=dict)
    enabled: bool = True


class RunbookUpdateRequest(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=200)
    incident_type: str | None = Field(default=None, min_length=1, max_length=80)
    trigger_condition: dict[str, Any] | None = None
    steps: list[dict[str, Any]] | None = None
    safety_policy: dict[str, Any] | None = None
    enabled: bool | None = None


class RunbookExecuteRequest(BaseModel):
    incident_ref: str | None = Field(default=None, max_length=120)
    operator: str = Field(default="soc_admin", min_length=1, max_length=80)


class FeedbackCreateRequest(BaseModel):
    source_product: str = Field(min_length=1, max_length=40)
    source_ref: str = Field(min_length=1, max_length=160)
    feedback_type: str = Field(min_length=1, max_length=40)
    feedback_value: str = Field(min_length=1, max_length=80)
    severity_override: str | None = Field(default=None, max_length=20)
    comment: str | None = None
    created_by: str = Field(default="analyst", min_length=1, max_length=80)


class FeedbackAutoCandidateRequest(BaseModel):
    min_hits: int = Field(default=3, ge=1, le=1000)
    created_by: str = Field(default="feedback-bot", min_length=1, max_length=80)


@router.get("/api/v1/safety/policy")
def get_safety_policy(x_admin_token: str | None = Header(default=None)) -> dict[str, Any]:
    require_admin_token(x_admin_token)
    return get_storage().get_safety_guard_config()


@router.put("/api/v1/safety/policy")
def set_safety_policy(req: SafetyGuardConfigRequest, x_admin_token: str | None = Header(default=None)) -> dict[str, Any]:
    require_admin_token(x_admin_token)
    st = get_storage()
    before = st.get_safety_guard_config()
    try:
        item = st.upsert_safety_guard_config(
            max_targets=req.max_targets,
            block_protected_assets=req.block_protected_assets,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    st.create_audit_log(
        audit_id=f"audit-{secrets.token_hex(8)}",
        actor_type="admin_api",
        actor_name="soc_admin",
        action_type="safety_policy_update",
        target_type="safety_guard_config",
        target_ref="global",
        before=before,
        after=item,
        result="ok",
    )
    return item


@router.get("/api/v1/safety/protected-assets")
def list_protected_assets(
    asset_type: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=1000),
    x_admin_token: str | None = Header(default=None),
) -> dict[str, Any]:
    require_admin_token(x_admin_token)
    return {"items": get_storage().list_protected_assets(asset_type=asset_type, limit=limit)}


@router.post("/api/v1/safety/protected-assets")
def create_protected_asset(req: ProtectedAssetCreateRequest, x_admin_token: str | None = Header(default=None)) -> dict[str, Any]:
    require_admin_token(x_admin_token)
    st = get_storage()
    protected_id = f"pa-{secrets.token_hex(8)}"
    try:
        item = st.create_protected_asset(
            protected_id=protected_id,
            asset_type=req.asset_type,
            asset_key=req.asset_key,
            reason=req.reason,
        )
    except Exception as exc:
        raise HTTPException(status_code=400, detail="protected_asset_create_failed") from exc
    st.create_audit_log(
        audit_id=f"audit-{secrets.token_hex(8)}",
        actor_type="admin_api",
        actor_name="soc_admin",
        action_type="protected_asset_create",
        target_type="protected_asset",
        target_ref=protected_id,
        before=None,
        after=item,
        result="ok",
    )
    return item


@router.delete("/api/v1/safety/protected-assets/{protected_id}")
def delete_protected_asset(protected_id: str, x_admin_token: str | None = Header(default=None)) -> dict[str, str]:
    require_admin_token(x_admin_token)
    st = get_storage()
    try:
        before = st.get_protected_asset(protected_id)
        st.delete_protected_asset(protected_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="protected_asset_not_found") from exc
    st.create_audit_log(
        audit_id=f"audit-{secrets.token_hex(8)}",
        actor_type="admin_api",
        actor_name="soc_admin",
        action_type="protected_asset_delete",
        target_type="protected_asset",
        target_ref=protected_id,
        before=before,
        after={},
        result="ok",
    )
    return {"status": "deleted", "protected_id": protected_id}


@router.get("/api/v1/runbooks")
def list_runbooks(
    incident_type: str | None = Query(default=None),
    enabled: bool | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=1000),
    x_admin_token: str | None = Header(default=None),
) -> dict[str, Any]:
    require_admin_token(x_admin_token)
    return {"items": get_storage().list_runbooks(incident_type=incident_type, enabled=enabled, limit=limit)}


@router.get("/api/v1/runbooks/{runbook_id}")
def get_runbook(runbook_id: str, x_admin_token: str | None = Header(default=None)) -> dict[str, Any]:
    require_admin_token(x_admin_token)
    try:
        return get_storage().get_runbook(runbook_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="runbook_not_found") from exc


@router.post("/api/v1/runbooks")
def create_runbook(req: RunbookCreateRequest, x_admin_token: str | None = Header(default=None)) -> dict[str, Any]:
    require_admin_token(x_admin_token)
    st = get_storage()
    try:
        item = st.create_runbook(
            runbook_id=req.runbook_id,
            name=req.name,
            incident_type=req.incident_type,
            trigger_condition=req.trigger_condition,
            steps=req.steps,
            safety_policy=req.safety_policy,
            enabled=req.enabled,
        )
    except Exception as exc:
        raise HTTPException(status_code=400, detail="runbook_create_failed") from exc
    st.create_audit_log(
        audit_id=f"audit-{secrets.token_hex(8)}",
        actor_type="admin_api",
        actor_name="soc_admin",
        action_type="runbook_create",
        target_type="runbook",
        target_ref=req.runbook_id,
        before=None,
        after=item,
        result="ok",
    )
    return item


@router.put("/api/v1/runbooks/{runbook_id}")
def update_runbook(
    runbook_id: str,
    req: RunbookUpdateRequest,
    x_admin_token: str | None = Header(default=None),
) -> dict[str, Any]:
    require_admin_token(x_admin_token)
    st = get_storage()
    try:
        before = st.get_runbook(runbook_id)
        item = st.update_runbook(
            runbook_id,
            name=req.name,
            incident_type=req.incident_type,
            trigger_condition=req.trigger_condition,
            steps=req.steps,
            safety_policy=req.safety_policy,
            enabled=req.enabled,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="runbook_not_found") from exc
    st.create_audit_log(
        audit_id=f"audit-{secrets.token_hex(8)}",
        actor_type="admin_api",
        actor_name="soc_admin",
        action_type="runbook_update",
        target_type="runbook",
        target_ref=runbook_id,
        before=before,
        after=item,
        result="ok",
    )
    return item


@router.post("/api/v1/runbooks/{runbook_id}/execute")
def execute_runbook(
    runbook_id: str,
    req: RunbookExecuteRequest,
    x_admin_token: str | None = Header(default=None),
) -> dict[str, Any]:
    require_admin_token(x_admin_token)
    st = get_storage()
    try:
        runbook = st.get_runbook(runbook_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="runbook_not_found") from exc
    if not runbook["enabled"]:
        raise HTTPException(status_code=400, detail="runbook_disabled")
    execution_id = f"rbx-{secrets.token_hex(8)}"
    execution = st.create_runbook_execution(
        execution_id=execution_id,
        runbook_id=runbook_id,
        incident_ref=req.incident_ref,
        status="completed",
        execution_log={
            "operator": req.operator,
            "steps_count": len(runbook.get("steps", [])),
            "result": "simulated_success",
        },
    )
    execution = st.update_runbook_execution(
        execution_id,
        status="completed",
        execution_log=execution["execution_log"],
        finished=True,
    )
    st.create_audit_log(
        audit_id=f"audit-{secrets.token_hex(8)}",
        actor_type="operator",
        actor_name=req.operator,
        action_type="runbook_execute",
        target_type="runbook_execution",
        target_ref=execution_id,
        before=None,
        after={"runbook_id": runbook_id, "status": execution["status"]},
        result="ok",
    )
    return execution


@router.get("/api/v1/runbook-executions")
def list_runbook_executions(
    runbook_id: str | None = Query(default=None),
    status: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=1000),
    x_admin_token: str | None = Header(default=None),
) -> dict[str, Any]:
    require_admin_token(x_admin_token)
    return {"items": get_storage().list_runbook_executions(runbook_id=runbook_id, status=status, limit=limit)}


@router.get("/api/v1/runbook-executions/{execution_id}")
def get_runbook_execution(execution_id: str, x_admin_token: str | None = Header(default=None)) -> dict[str, Any]:
    require_admin_token(x_admin_token)
    try:
        return get_storage().get_runbook_execution(execution_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="runbook_execution_not_found") from exc


@router.post("/api/v1/feedback")
def create_feedback(req: FeedbackCreateRequest, x_admin_token: str | None = Header(default=None)) -> dict[str, Any]:
    require_admin_token(x_admin_token)
    st = get_storage()
    feedback_id = f"fb-{secrets.token_hex(8)}"
    item = st.create_feedback(
        feedback_id=feedback_id,
        source_product=req.source_product,
        source_ref=req.source_ref,
        feedback_type=req.feedback_type,
        feedback_value=req.feedback_value,
        severity_override=req.severity_override,
        comment=req.comment,
        created_by=req.created_by,
    )
    st.create_audit_log(
        audit_id=f"audit-{secrets.token_hex(8)}",
        actor_type="analyst",
        actor_name=req.created_by,
        action_type="feedback_create",
        target_type="analyst_feedback",
        target_ref=feedback_id,
        before=None,
        after=item,
        result="ok",
    )
    return item


@router.get("/api/v1/feedback")
def list_feedback(
    source_product: str | None = Query(default=None),
    feedback_type: str | None = Query(default=None),
    created_by: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=1000),
    x_admin_token: str | None = Header(default=None),
) -> dict[str, Any]:
    require_admin_token(x_admin_token)
    return {
        "items": get_storage().list_feedback(
            source_product=source_product,
            feedback_type=feedback_type,
            created_by=created_by,
            limit=limit,
        )
    }


@router.post("/api/v1/feedback/auto-candidates")
def generate_auto_candidates_from_feedback(
    req: FeedbackAutoCandidateRequest,
    x_admin_token: str | None = Header(default=None),
) -> dict[str, Any]:
    require_admin_token(x_admin_token)
    st = get_storage()
    try:
        created = st.generate_candidates_from_feedback(min_hits=req.min_hits, created_by=req.created_by)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    st.create_audit_log(
        audit_id=f"audit-{secrets.token_hex(8)}",
        actor_type="program",
        actor_name=req.created_by,
        action_type="feedback_auto_candidates",
        target_type="improvement_candidate",
        target_ref="batch",
        before=None,
        after={"created_count": len(created), "min_hits": req.min_hits},
        result="ok",
    )
    return {"created_count": len(created), "items": created}


@router.get("/api/v1/audit-logs")
def list_audit_logs(
    action_type: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=1000),
    x_admin_token: str | None = Header(default=None),
) -> dict[str, Any]:
    require_admin_token(x_admin_token)
    return {"items": get_storage().list_audit_logs(action_type=action_type, limit=limit)}
