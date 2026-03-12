from __future__ import annotations

import secrets
from typing import Any

from fastapi import APIRouter, Header, HTTPException, Query
from pydantic import BaseModel, Field

from ..app_context import get_storage, require_admin_token

router = APIRouter()


class PolicyUpsertRequest(BaseModel):
    scope_type: str = Field(min_length=1, max_length=40)
    scope_value: str = Field(min_length=1, max_length=120)
    decision_mode: str = Field(min_length=2, max_length=20)
    severity_threshold: str | None = None
    auto_allowed_actions: list[str] = Field(default_factory=list)
    auto_allowed_improvements: list[str] = Field(default_factory=list)
    freeze_enabled: bool = False


class DecisionModeUpdateRequest(BaseModel):
    decision_mode: str = Field(min_length=2, max_length=20)
    severity_threshold: str | None = Field(default=None, max_length=20)


def _ensure_policy_exists(policy_id: str) -> dict[str, Any]:
    st = get_storage()
    try:
        return st.get_decision_policy(policy_id)
    except KeyError:
        return st.upsert_decision_policy(
            policy_id=policy_id,
            scope_type="global",
            scope_value="*",
            decision_mode="human",
            severity_threshold="high",
            auto_allowed_actions=[],
            auto_allowed_improvements=[],
            freeze_enabled=False,
        )


@router.get("/api/v1/policies")
def list_policies(x_admin_token: str | None = Header(default=None)) -> dict[str, Any]:
    require_admin_token(x_admin_token)
    return {"items": get_storage().list_decision_policies()}


@router.put("/api/v1/policies/{policy_id}")
def upsert_policy(policy_id: str, req: PolicyUpsertRequest, x_admin_token: str | None = Header(default=None)) -> dict[str, Any]:
    require_admin_token(x_admin_token)
    st = get_storage()
    before = None
    try:
        before = st.get_decision_policy(policy_id)
    except KeyError:
        before = None
    item = st.upsert_decision_policy(
        policy_id=policy_id,
        scope_type=req.scope_type,
        scope_value=req.scope_value,
        decision_mode=req.decision_mode,
        severity_threshold=req.severity_threshold,
        auto_allowed_actions=req.auto_allowed_actions,
        auto_allowed_improvements=req.auto_allowed_improvements,
        freeze_enabled=req.freeze_enabled,
    )
    st.create_audit_log(
        audit_id=f"audit-{secrets.token_hex(8)}",
        actor_type="admin_api",
        actor_name="soc_admin",
        action_type="policy_upsert",
        target_type="decision_policy",
        target_ref=policy_id,
        before=before,
        after=item,
        result="ok",
    )
    return item


@router.get("/api/v1/decision/mode")
def get_decision_mode(
    policy_id: str = Query(default="global-default"),
    x_admin_token: str | None = Header(default=None),
) -> dict[str, Any]:
    require_admin_token(x_admin_token)
    return _ensure_policy_exists(policy_id)


@router.put("/api/v1/decision/mode")
def set_decision_mode(
    req: DecisionModeUpdateRequest,
    policy_id: str = Query(default="global-default"),
    x_admin_token: str | None = Header(default=None),
) -> dict[str, Any]:
    require_admin_token(x_admin_token)
    st = get_storage()
    before = _ensure_policy_exists(policy_id)
    try:
        item = st.set_policy_mode(
            policy_id,
            decision_mode=req.decision_mode,
            severity_threshold=req.severity_threshold,
            freeze_enabled=None,
        )
    except KeyError:
        item = st.upsert_decision_policy(
            policy_id=policy_id,
            scope_type="global",
            scope_value="*",
            decision_mode=req.decision_mode,
            severity_threshold=req.severity_threshold or "high",
            auto_allowed_actions=[],
            auto_allowed_improvements=[],
            freeze_enabled=False,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    st.create_audit_log(
        audit_id=f"audit-{secrets.token_hex(8)}",
        actor_type="admin_api",
        actor_name="soc_admin",
        action_type="decision_mode_update",
        target_type="decision_policy",
        target_ref=policy_id,
        before=before,
        after=item,
        result="ok",
    )
    return item


@router.post("/api/v1/decision/freeze")
def set_freeze(
    enabled: bool = Query(...),
    policy_id: str = Query(default="global-default"),
    x_admin_token: str | None = Header(default=None),
) -> dict[str, Any]:
    require_admin_token(x_admin_token)
    st = get_storage()
    before = _ensure_policy_exists(policy_id)
    try:
        item = st.set_policy_mode(
            policy_id,
            decision_mode=before["decision_mode"],
            severity_threshold=before.get("severity_threshold"),
            freeze_enabled=enabled,
        )
    except KeyError:
        item = st.upsert_decision_policy(
            policy_id=policy_id,
            scope_type="global",
            scope_value="*",
            decision_mode="human",
            severity_threshold="high",
            auto_allowed_actions=[],
            auto_allowed_improvements=[],
            freeze_enabled=enabled,
        )
    st.create_audit_log(
        audit_id=f"audit-{secrets.token_hex(8)}",
        actor_type="admin_api",
        actor_name="soc_admin",
        action_type="decision_freeze_toggle",
        target_type="decision_policy",
        target_ref=policy_id,
        before=before,
        after=item,
        result="ok",
    )
    return item
