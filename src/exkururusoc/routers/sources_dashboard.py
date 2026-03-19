from __future__ import annotations

import html
import json
import secrets
from typing import Any

from fastapi import APIRouter, Header, HTTPException, Query, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

from ..app_context import (
    get_read_storage,
    get_write_storage,
    require_admin_token,
    require_source_or_admin_token,
    resolve_secret_ref,
    verify_source_signature,
)

router = APIRouter()


class SourceCreateRequest(BaseModel):
    source_id: str = Field(min_length=3, max_length=80, pattern=r"^[a-z0-9_-]+$")
    product_name: str = Field(min_length=3, max_length=40)
    source_type: str = Field(default="api", min_length=2, max_length=40)
    base_url: str = Field(min_length=1, max_length=500)
    auth_type: str = Field(default="token", min_length=2, max_length=40)
    auth_secret_ref: str = Field(default="", max_length=200)


class SourceUpdateRequest(BaseModel):
    base_url: str | None = Field(default=None, min_length=1, max_length=500)
    auth_type: str | None = Field(default=None, min_length=2, max_length=40)
    auth_secret_ref: str | None = Field(default=None, max_length=200)
    status: str | None = Field(default=None, min_length=2, max_length=40)


class SourceHeartbeatRequest(BaseModel):
    seen_at: str | None = None
    health_payload: dict[str, Any] = Field(default_factory=dict)


@router.get("/api/v1/sources")
def list_sources(
    product_name: str | None = Query(default=None),
    status: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=1000),
    x_admin_token: str | None = Header(default=None),
) -> dict[str, Any]:
    require_admin_token(x_admin_token)
    return {"items": get_read_storage().list_sources(product_name=product_name, status=status, limit=limit)}


@router.post("/api/v1/sources")
def create_source(req: SourceCreateRequest, x_admin_token: str | None = Header(default=None)) -> dict[str, Any]:
    require_admin_token(x_admin_token)
    st = get_write_storage()
    item = st.create_source(
        source_id=req.source_id,
        product_name=req.product_name,
        source_type=req.source_type,
        base_url=req.base_url,
        auth_type=req.auth_type,
        auth_secret_ref=req.auth_secret_ref,
    )
    st.create_audit_log(
        audit_id=f"audit-{secrets.token_hex(8)}",
        actor_type="admin_api",
        actor_name="soc_admin",
        action_type="source_create",
        target_type="product_source",
        target_ref=req.source_id,
        before=None,
        after=item,
        result="ok",
    )
    return item


@router.put("/api/v1/sources/{source_id}")
def update_source(source_id: str, req: SourceUpdateRequest, x_admin_token: str | None = Header(default=None)) -> dict[str, Any]:
    require_admin_token(x_admin_token)
    st = get_write_storage()
    try:
        before = st.get_source(source_id)
        item = st.update_source(
            source_id,
            base_url=req.base_url,
            auth_type=req.auth_type,
            auth_secret_ref=req.auth_secret_ref,
            status=req.status,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="source_not_found") from exc
    st.create_audit_log(
        audit_id=f"audit-{secrets.token_hex(8)}",
        actor_type="admin_api",
        actor_name="soc_admin",
        action_type="source_update",
        target_type="product_source",
        target_ref=source_id,
        before=before,
        after=item,
        result="ok",
    )
    return item


def _source_heartbeat_impl(
    source_id: str,
    req: SourceHeartbeatRequest,
    raw_body: bytes,
    x_admin_token: str | None = None,
    x_source_token: str | None = None,
    x_source_timestamp: str | None = None,
    x_source_signature: str | None = None,
    x_source_nonce: str | None = None,
) -> dict[str, Any]:
    require_source_or_admin_token(source_id=source_id, x_admin_token=x_admin_token, x_source_token=x_source_token)
    st = get_write_storage()
    try:
        source = st.get_source(source_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="source_not_found") from exc
    auth_type = str(source.get("auth_type") or "token").strip().lower()
    if auth_type == "signed_required":
        source_secret = resolve_secret_ref(str(source.get("auth_secret_ref", "")))
        if not source_secret:
            raise HTTPException(status_code=401, detail="source_token_not_configured")
        verify_source_signature(
            source_id=source_id,
            source_secret=source_secret,
            raw_body=raw_body,
            timestamp=x_source_timestamp,
            signature=x_source_signature,
            nonce=x_source_nonce,
        )
    try:
        item = st.source_heartbeat(source_id, health_payload=req.health_payload, seen_at=req.seen_at)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="source_not_found") from exc
    st.create_audit_log(
        audit_id=f"audit-{secrets.token_hex(8)}",
        actor_type="product_source",
        actor_name=source_id,
        action_type="source_heartbeat",
        target_type="product_source",
        target_ref=source_id,
        before=None,
        after={"seen_at": item.get("last_seen_at"), "status": item.get("status")},
        result="ok",
    )
    return item


@router.post("/api/v1/sources/{source_id}/heartbeat")
async def source_heartbeat(
    request: Request,
    source_id: str,
    req: SourceHeartbeatRequest,
    x_admin_token: str | None = Header(default=None),
    x_source_token: str | None = Header(default=None),
    x_source_timestamp: str | None = Header(default=None),
    x_source_signature: str | None = Header(default=None),
    x_source_nonce: str | None = Header(default=None),
) -> dict[str, Any]:
    raw_body = await request.body()
    return _source_heartbeat_impl(
        source_id,
        req,
        raw_body,
        x_admin_token=x_admin_token,
        x_source_token=x_source_token,
        x_source_timestamp=x_source_timestamp,
        x_source_signature=x_source_signature,
        x_source_nonce=x_source_nonce,
    )


@router.get("/api/v1/command-center")
def command_center_summary(x_admin_token: str | None = Header(default=None)) -> dict[str, Any]:
    require_admin_token(x_admin_token)
    return get_read_storage().command_center_summary()


@router.get("/secops/soc/dashboard/", response_class=HTMLResponse)
def soc_dashboard(token: str | None = Query(default=None), x_admin_token: str | None = Header(default=None)) -> str:
    if token and not x_admin_token:
        x_admin_token = token
    require_admin_token(x_admin_token)
    data = get_read_storage().command_center_summary()

    def _e(value: Any) -> str:
        if isinstance(value, (dict, list)):
            return html.escape(json.dumps(value, ensure_ascii=False))
        return html.escape(str(value if value is not None else ""))

    sources_rows = "".join(
        [
            (
                "<tr>"
                f"<td>{_e(item.get('product_name',''))}</td>"
                f"<td>{_e(item.get('source_id',''))}</td>"
                f"<td>{_e(item.get('status',''))}</td>"
                f"<td>{_e(item.get('last_seen_at') or '-')}</td>"
                f"<td>{_e(item.get('last_health',{}))}</td>"
                "</tr>"
            )
            for item in data["recent_sources"]
        ]
    )
    audit_rows = "".join(
        [
            (
                "<tr>"
                f"<td>{_e(item.get('created_at',''))}</td>"
                f"<td>{_e(item.get('action_type',''))}</td>"
                f"<td>{_e(item.get('target_type',''))}:{_e(item.get('target_ref',''))}</td>"
                f"<td>{_e(item.get('actor_type',''))}:{_e(item.get('actor_name',''))}</td>"
                f"<td>{_e(item.get('result',''))}</td>"
                "</tr>"
            )
            for item in data["recent_audits"]
        ]
    )
    status_badges = " ".join([f"{_e(k)}:{_e(v)}" for k, v in data["candidate_status_counts"].items()]) or "-"
    return f"""
<!doctype html>
<html lang="ja">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>EXkururuSOC Dashboard</title>
  <style>
    :root {{
      --bg: #0b1220;
      --panel: #121a2b;
      --text: #eef4ff;
      --muted: #c3d0e8;
      --line: #304766;
      --ok: #2ec27e;
    }}
    body {{
      margin: 0; padding: 20px; background: radial-gradient(circle at 20% 0%, #19253f 0%, #0b1220 50%);
      color: var(--text); font-family: "Noto Sans JP", "Hiragino Kaku Gothic ProN", sans-serif; overflow-x: hidden;
    }}
    .wrap {{ max-width: 1100px; margin: 0 auto; overflow-x: hidden; }}
    .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); gap: 10px; }}
    .card {{ background: var(--panel); border: 1px solid var(--line); border-radius: 12px; padding: 12px; overflow-x: auto; -webkit-overflow-scrolling: touch; }}
    .k {{ color: var(--muted); font-size: 12px; }}
    .v {{ font-size: 24px; font-weight: 700; margin-top: 4px; }}
    .ok {{ color: var(--ok); }}
    h1 {{ margin: 0 0 12px 0; font-size: 24px; }}
    h2 {{ margin-top: 20px; font-size: 18px; }}
    table {{ width: 100%; border-collapse: collapse; background: var(--panel); border: 1px solid var(--line); border-radius: 12px; overflow: hidden; }}
    th, td {{ padding: 8px 10px; border-bottom: 1px solid var(--line); font-size: 13px; text-align: left; word-break: break-word; overflow-wrap: anywhere; }}
    th {{ color: var(--muted); }}
    tr:last-child td {{ border-bottom: none; }}
    .mono {{ font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }}
    @media (max-width: 600px) {{
      body {{ padding: 12px; }}
      .grid {{ grid-template-columns: 1fr; gap: 8px; }}
      .card {{ padding: 10px; }}
      h1 {{ font-size: 20px; }}
      h2 {{ font-size: 15px; margin-top: 14px; }}
      .v {{ font-size: 20px; }}
      table {{ display: block; overflow-x: auto; white-space: nowrap; }}
      th, td {{ padding: 7px 8px; font-size: 12px; }}
    }}
  </style>
</head>
<body>
  <div class="wrap">
    <h1>EXkururuSOC Command Center</h1>
    <div class="grid">
      <div class="card"><div class="k">Policies</div><div class="v">{data["policy_count"]}</div></div>
      <div class="card"><div class="k">Candidates</div><div class="v">{data["candidate_count"]}</div></div>
      <div class="card"><div class="k">Sources</div><div class="v">{data["source_count"]}</div></div>
      <div class="card"><div class="k">Active Sources</div><div class="v ok">{data["source_active_count"]}</div></div>
      <div class="card"><div class="k">Protected Assets</div><div class="v">{data["protected_asset_count"]}</div></div>
      <div class="card"><div class="k">Audit (24h)</div><div class="v">{data["audit_24h"]}</div></div>
      <div class="card"><div class="k">Candidate States</div><div class="v mono" style="font-size:14px">{status_badges}</div></div>
    </div>
    <h2>Recent Sources</h2>
    <table>
      <thead><tr><th>Product</th><th>Source</th><th>Status</th><th>Last Seen</th><th>Health</th></tr></thead>
      <tbody>{sources_rows or '<tr><td colspan="5">No sources</td></tr>'}</tbody>
    </table>
    <h2>Recent Audits</h2>
    <table>
      <thead><tr><th>Time</th><th>Action</th><th>Target</th><th>Actor</th><th>Result</th></tr></thead>
      <tbody>{audit_rows or '<tr><td colspan="5">No audit logs</td></tr>'}</tbody>
    </table>
  </div>
</body>
</html>
"""
