from __future__ import annotations

import json
import os
import secrets
import sqlite3
import subprocess
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Any, Iterator


VALID_DECISION_MODES = {"human", "ai", "program"}
VALID_CANDIDATE_STATUSES = {
    "new",
    "evaluating",
    "approval_pending",
    "approved",
    "rejected",
    "rollout",
    "rolled_back",
    "completed",
}
VALID_APPROVAL_ACTIONS = {"approve", "reject", "hold"}
APPROVAL_ACTION_TO_STATUS = {
    "approve": "approved",
    "reject": "rejected",
    "hold": "approval_pending",
}
ALLOWED_APPROVAL_FROM = {"new", "evaluating", "approval_pending"}
ROLLOUT_STAGE_ORDER = ["canary", "staged", "full"]
ROLLOUT_ACTIVE_STATUSES = {"running", "paused"}


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


class SocStorage:
    def __init__(self, db_path: str | Path) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def _init_db(self) -> None:
        with self.connect() as conn:
            conn.execute("PRAGMA journal_mode = WAL")
            conn.execute("PRAGMA synchronous = NORMAL")
            conn.execute("PRAGMA temp_store = MEMORY")
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS decision_policies (
                    policy_id TEXT PRIMARY KEY,
                    scope_type TEXT NOT NULL,
                    scope_value TEXT NOT NULL,
                    decision_mode TEXT NOT NULL,
                    severity_threshold TEXT NULL,
                    auto_allowed_actions_json TEXT NOT NULL DEFAULT '[]',
                    auto_allowed_improvements_json TEXT NOT NULL DEFAULT '[]',
                    freeze_enabled INTEGER NOT NULL DEFAULT 0,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS improvement_candidates (
                    candidate_id TEXT PRIMARY KEY,
                    created_at TEXT NOT NULL,
                    source_product TEXT NOT NULL,
                    source_kind TEXT NOT NULL,
                    candidate_type TEXT NOT NULL,
                    target_scope TEXT NOT NULL,
                    target_ref TEXT NOT NULL,
                    title TEXT NOT NULL,
                    proposal_json TEXT NOT NULL,
                    evidence_json TEXT NOT NULL DEFAULT '{}',
                    reason_summary TEXT NOT NULL,
                    expected_benefit_json TEXT NOT NULL DEFAULT '{}',
                    risk_level TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_by_type TEXT NOT NULL,
                    created_by TEXT NOT NULL,
                    decision_note TEXT NOT NULL DEFAULT '',
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS candidate_evaluations (
                    evaluation_id TEXT PRIMARY KEY,
                    candidate_id TEXT NOT NULL,
                    evaluated_at TEXT NOT NULL,
                    evaluation_type TEXT NOT NULL,
                    dataset_ref TEXT NULL,
                    baseline_metrics_json TEXT NOT NULL,
                    candidate_metrics_json TEXT NOT NULL,
                    diff_metrics_json TEXT NOT NULL,
                    verdict TEXT NOT NULL,
                    evaluator_type TEXT NOT NULL,
                    evaluator_name TEXT NOT NULL,
                    FOREIGN KEY(candidate_id) REFERENCES improvement_candidates(candidate_id)
                );

                CREATE TABLE IF NOT EXISTS rollout_jobs (
                    rollout_id TEXT PRIMARY KEY,
                    candidate_id TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    finished_at TEXT NULL,
                    rollout_scope_json TEXT NOT NULL,
                    current_stage TEXT NOT NULL,
                    status TEXT NOT NULL,
                    rollback_point TEXT NULL,
                    result_summary_json TEXT NOT NULL DEFAULT '{}',
                    FOREIGN KEY(candidate_id) REFERENCES improvement_candidates(candidate_id)
                );

                CREATE TABLE IF NOT EXISTS analyst_feedback (
                    feedback_id TEXT PRIMARY KEY,
                    created_at TEXT NOT NULL,
                    source_product TEXT NOT NULL,
                    source_ref TEXT NOT NULL,
                    feedback_type TEXT NOT NULL,
                    feedback_value TEXT NOT NULL,
                    severity_override TEXT NULL,
                    comment TEXT NULL,
                    created_by TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS audit_logs (
                    audit_id TEXT PRIMARY KEY,
                    created_at TEXT NOT NULL,
                    actor_type TEXT NOT NULL,
                    actor_name TEXT NOT NULL,
                    action_type TEXT NOT NULL,
                    target_type TEXT NOT NULL,
                    target_ref TEXT NOT NULL,
                    before_json TEXT NOT NULL DEFAULT '{}',
                    after_json TEXT NOT NULL DEFAULT '{}',
                    result TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS product_sources (
                    source_id TEXT PRIMARY KEY,
                    product_name TEXT NOT NULL,
                    source_type TEXT NOT NULL,
                    base_url TEXT NOT NULL,
                    auth_type TEXT NOT NULL,
                    auth_secret_ref TEXT NOT NULL DEFAULT '',
                    status TEXT NOT NULL DEFAULT 'active',
                    last_seen_at TEXT NULL,
                    last_health_json TEXT NOT NULL DEFAULT '{}',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS protected_assets (
                    protected_id TEXT PRIMARY KEY,
                    asset_type TEXT NOT NULL,
                    asset_key TEXT NOT NULL UNIQUE,
                    reason TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS safety_guard_config (
                    config_id TEXT PRIMARY KEY,
                    max_targets INTEGER NOT NULL DEFAULT 10,
                    block_protected_assets INTEGER NOT NULL DEFAULT 1,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS runbooks (
                    runbook_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    incident_type TEXT NOT NULL,
                    version INTEGER NOT NULL DEFAULT 1,
                    enabled INTEGER NOT NULL DEFAULT 1,
                    trigger_condition_json TEXT NOT NULL DEFAULT '{}',
                    steps_json TEXT NOT NULL DEFAULT '[]',
                    safety_policy_json TEXT NOT NULL DEFAULT '{}',
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS runbook_executions (
                    execution_id TEXT PRIMARY KEY,
                    runbook_id TEXT NOT NULL,
                    incident_ref TEXT NULL,
                    started_at TEXT NOT NULL,
                    finished_at TEXT NULL,
                    status TEXT NOT NULL,
                    execution_log_json TEXT NOT NULL DEFAULT '{}',
                    FOREIGN KEY(runbook_id) REFERENCES runbooks(runbook_id)
                );

                CREATE INDEX IF NOT EXISTS soc_policies_scope_idx
                ON decision_policies(scope_type, scope_value);

                CREATE INDEX IF NOT EXISTS soc_candidates_status_created_idx
                ON improvement_candidates(status, created_at DESC);

                CREATE INDEX IF NOT EXISTS soc_candidates_source_status_idx
                ON improvement_candidates(source_product, status, created_at DESC);

                CREATE INDEX IF NOT EXISTS soc_candidates_filter_idx
                ON improvement_candidates(source_product, candidate_type, risk_level, status, created_at DESC);

                CREATE INDEX IF NOT EXISTS soc_eval_candidate_at_idx
                ON candidate_evaluations(candidate_id, evaluated_at DESC);

                CREATE INDEX IF NOT EXISTS soc_rollout_candidate_status_idx
                ON rollout_jobs(candidate_id, status, started_at DESC);

                CREATE INDEX IF NOT EXISTS soc_feedback_created_idx
                ON analyst_feedback(created_at DESC);

                CREATE INDEX IF NOT EXISTS soc_feedback_filter_idx
                ON analyst_feedback(source_product, feedback_type, created_by, created_at DESC);

                CREATE INDEX IF NOT EXISTS soc_feedback_grouping_idx
                ON analyst_feedback(source_product, source_ref, feedback_type);

                CREATE INDEX IF NOT EXISTS soc_audit_created_idx
                ON audit_logs(created_at DESC);

                CREATE INDEX IF NOT EXISTS soc_audit_action_created_idx
                ON audit_logs(action_type, created_at DESC);

                CREATE INDEX IF NOT EXISTS soc_sources_product_status_idx
                ON product_sources(product_name, status, updated_at DESC);

                CREATE INDEX IF NOT EXISTS soc_protected_asset_type_idx
                ON protected_assets(asset_type, asset_key);

                CREATE INDEX IF NOT EXISTS soc_runbooks_incident_enabled_idx
                ON runbooks(incident_type, enabled, updated_at DESC);

                CREATE INDEX IF NOT EXISTS soc_runbook_exec_runbook_status_idx
                ON runbook_executions(runbook_id, status, started_at DESC);
                """
            )
            candidate_columns = {
                row["name"] for row in conn.execute("PRAGMA table_info(improvement_candidates)").fetchall()
            }
            if "evidence_json" not in candidate_columns:
                conn.execute("ALTER TABLE improvement_candidates ADD COLUMN evidence_json TEXT NOT NULL DEFAULT '{}'")
            config_exists = conn.execute(
                "SELECT COUNT(*) AS c FROM safety_guard_config WHERE config_id = 'global'"
            ).fetchone()["c"]
            if int(config_exists) == 0:
                conn.execute(
                    """
                    INSERT INTO safety_guard_config (config_id, max_targets, block_protected_assets, updated_at)
                    VALUES ('global', 10, 1, ?)
                    """,
                    (utc_now(),),
                )

    def upsert_decision_policy(
        self,
        *,
        policy_id: str,
        scope_type: str,
        scope_value: str,
        decision_mode: str,
        severity_threshold: str | None,
        auto_allowed_actions: list[str] | None = None,
        auto_allowed_improvements: list[str] | None = None,
        freeze_enabled: bool = False,
    ) -> dict[str, Any]:
        if decision_mode not in VALID_DECISION_MODES:
            raise ValueError("invalid_decision_mode")
        now = utc_now()
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO decision_policies (
                    policy_id, scope_type, scope_value, decision_mode, severity_threshold,
                    auto_allowed_actions_json, auto_allowed_improvements_json, freeze_enabled, updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(policy_id) DO UPDATE SET
                    scope_type=excluded.scope_type,
                    scope_value=excluded.scope_value,
                    decision_mode=excluded.decision_mode,
                    severity_threshold=excluded.severity_threshold,
                    auto_allowed_actions_json=excluded.auto_allowed_actions_json,
                    auto_allowed_improvements_json=excluded.auto_allowed_improvements_json,
                    freeze_enabled=excluded.freeze_enabled,
                    updated_at=excluded.updated_at
                """,
                (
                    policy_id,
                    scope_type,
                    scope_value,
                    decision_mode,
                    severity_threshold,
                    json.dumps(auto_allowed_actions or []),
                    json.dumps(auto_allowed_improvements or []),
                    1 if freeze_enabled else 0,
                    now,
                ),
            )
        return self.get_decision_policy(policy_id)

    def get_decision_policy(self, policy_id: str) -> dict[str, Any]:
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM decision_policies WHERE policy_id = ?", (policy_id,)).fetchone()
        if row is None:
            raise KeyError(policy_id)
        return self._policy_row(row)

    def list_decision_policies(self) -> list[dict[str, Any]]:
        with self.connect() as conn:
            rows = conn.execute("SELECT * FROM decision_policies ORDER BY policy_id").fetchall()
        return [self._policy_row(row) for row in rows]

    def set_policy_mode(
        self,
        policy_id: str,
        *,
        decision_mode: str,
        severity_threshold: str | None = None,
        freeze_enabled: bool | None = None,
    ) -> dict[str, Any]:
        if decision_mode not in VALID_DECISION_MODES:
            raise ValueError("invalid_decision_mode")
        if (severity_threshold or "").lower() == "critical" and decision_mode != "human":
            raise ValueError("critical_requires_human_mode")
        now = utc_now()
        updates = ["decision_mode = ?", "updated_at = ?"]
        params: list[Any] = [decision_mode, now]
        if severity_threshold is not None:
            updates.append("severity_threshold = ?")
            params.append(severity_threshold)
        if freeze_enabled is not None:
            updates.append("freeze_enabled = ?")
            params.append(1 if freeze_enabled else 0)
        params.append(policy_id)
        with self.connect() as conn:
            cursor = conn.execute(
                f"UPDATE decision_policies SET {', '.join(updates)} WHERE policy_id = ?",
                params,
            )
        if cursor.rowcount <= 0:
            raise KeyError(policy_id)
        return self.get_decision_policy(policy_id)

    def create_candidate(
        self,
        *,
        candidate_id: str,
        source_product: str,
        source_kind: str,
        candidate_type: str,
        target_scope: str,
        target_ref: str,
        title: str,
        proposal: dict[str, Any],
        evidence: dict[str, Any],
        reason_summary: str,
        expected_benefit: dict[str, Any],
        risk_level: str,
        created_by_type: str,
        created_by: str,
    ) -> dict[str, Any]:
        now = utc_now()
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO improvement_candidates (
                    candidate_id, created_at, source_product, source_kind, candidate_type,
                    target_scope, target_ref, title, proposal_json, evidence_json, reason_summary, expected_benefit_json,
                    risk_level, status, created_by_type, created_by, decision_note, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'new', ?, ?, '', ?)
                """,
                (
                    candidate_id,
                    now,
                    source_product,
                    source_kind,
                    candidate_type,
                    target_scope,
                    target_ref,
                    title,
                    json.dumps(proposal),
                    json.dumps(evidence),
                    reason_summary,
                    json.dumps(expected_benefit),
                    risk_level,
                    created_by_type,
                    created_by,
                    now,
                ),
            )
        return self.get_candidate(candidate_id)

    def update_candidate(
        self,
        candidate_id: str,
        *,
        title: str | None = None,
        proposal: dict[str, Any] | None = None,
        evidence: dict[str, Any] | None = None,
        reason_summary: str | None = None,
        expected_benefit: dict[str, Any] | None = None,
        risk_level: str | None = None,
    ) -> dict[str, Any]:
        updates: list[str] = []
        params: list[Any] = []
        if title is not None:
            updates.append("title = ?")
            params.append(title)
        if proposal is not None:
            updates.append("proposal_json = ?")
            params.append(json.dumps(proposal))
        if evidence is not None:
            updates.append("evidence_json = ?")
            params.append(json.dumps(evidence))
        if reason_summary is not None:
            updates.append("reason_summary = ?")
            params.append(reason_summary)
        if expected_benefit is not None:
            updates.append("expected_benefit_json = ?")
            params.append(json.dumps(expected_benefit))
        if risk_level is not None:
            updates.append("risk_level = ?")
            params.append(risk_level)
        if not updates:
            return self.get_candidate(candidate_id)
        updates.append("updated_at = ?")
        params.append(utc_now())
        params.append(candidate_id)
        with self.connect() as conn:
            cursor = conn.execute(
                f"UPDATE improvement_candidates SET {', '.join(updates)} WHERE candidate_id = ?",
                params,
            )
        if cursor.rowcount <= 0:
            raise KeyError(candidate_id)
        return self.get_candidate(candidate_id)

    def update_candidate_status(self, candidate_id: str, status: str, decision_note: str = "") -> dict[str, Any]:
        if status not in VALID_CANDIDATE_STATUSES:
            raise ValueError("invalid_candidate_status")
        now = utc_now()
        with self.connect() as conn:
            cursor = conn.execute(
                """
                UPDATE improvement_candidates
                SET status = ?, decision_note = ?, updated_at = ?
                WHERE candidate_id = ?
                """,
                (status, decision_note, now, candidate_id),
            )
        if cursor.rowcount <= 0:
            raise KeyError(candidate_id)
        return self.get_candidate(candidate_id)

    def apply_approval_action(
        self,
        candidate_id: str,
        *,
        action: str,
        decision_note: str = "",
    ) -> dict[str, Any]:
        if action not in VALID_APPROVAL_ACTIONS:
            raise ValueError("invalid_approval_action")
        current = self.get_candidate(candidate_id)
        if current["status"] not in ALLOWED_APPROVAL_FROM:
            raise ValueError("invalid_approval_transition")
        next_status = APPROVAL_ACTION_TO_STATUS[action]
        return self.update_candidate_status(candidate_id, next_status, decision_note)

    def get_candidate(self, candidate_id: str) -> dict[str, Any]:
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM improvement_candidates WHERE candidate_id = ?", (candidate_id,)).fetchone()
        if row is None:
            raise KeyError(candidate_id)
        return self._candidate_row(row)

    def list_candidates(
        self,
        *,
        status: str | None = None,
        source_product: str | None = None,
        candidate_type: str | None = None,
        risk_level: str | None = None,
        limit: int = 200,
    ) -> list[dict[str, Any]]:
        sql = "SELECT * FROM improvement_candidates"
        params: list[Any] = []
        wheres: list[str] = []
        if status:
            wheres.append("status = ?")
            params.append(status)
        if source_product:
            wheres.append("source_product = ?")
            params.append(source_product)
        if candidate_type:
            wheres.append("candidate_type = ?")
            params.append(candidate_type)
        if risk_level:
            wheres.append("risk_level = ?")
            params.append(risk_level)
        if wheres:
            sql += " WHERE " + " AND ".join(wheres)
        sql += " ORDER BY created_at DESC LIMIT ?"
        params.append(max(1, min(limit, 1000)))
        with self.connect() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [self._candidate_row(row) for row in rows]

    def create_evaluation(
        self,
        *,
        evaluation_id: str,
        candidate_id: str,
        evaluation_type: str,
        dataset_ref: str | None,
        baseline_metrics: dict[str, Any],
        candidate_metrics: dict[str, Any],
        diff_metrics: dict[str, Any],
        verdict: str,
        evaluator_type: str,
        evaluator_name: str,
    ) -> dict[str, Any]:
        now = utc_now()
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO candidate_evaluations (
                    evaluation_id, candidate_id, evaluated_at, evaluation_type, dataset_ref,
                    baseline_metrics_json, candidate_metrics_json, diff_metrics_json,
                    verdict, evaluator_type, evaluator_name
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    evaluation_id,
                    candidate_id,
                    now,
                    evaluation_type,
                    dataset_ref,
                    json.dumps(baseline_metrics),
                    json.dumps(candidate_metrics),
                    json.dumps(diff_metrics),
                    verdict,
                    evaluator_type,
                    evaluator_name,
                ),
            )
        return self.get_evaluation(evaluation_id)

    def get_evaluation(self, evaluation_id: str) -> dict[str, Any]:
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM candidate_evaluations WHERE evaluation_id = ?", (evaluation_id,)).fetchone()
        if row is None:
            raise KeyError(evaluation_id)
        result = dict(row)
        result["baseline_metrics"] = json.loads(result.pop("baseline_metrics_json"))
        result["candidate_metrics"] = json.loads(result.pop("candidate_metrics_json"))
        result["diff_metrics"] = json.loads(result.pop("diff_metrics_json"))
        return result

    def list_evaluations(
        self,
        *,
        candidate_id: str | None = None,
        evaluation_type: str | None = None,
        verdict: str | None = None,
        limit: int = 200,
    ) -> list[dict[str, Any]]:
        sql = "SELECT * FROM candidate_evaluations"
        wheres: list[str] = []
        params: list[Any] = []
        if candidate_id:
            wheres.append("candidate_id = ?")
            params.append(candidate_id)
        if evaluation_type:
            wheres.append("evaluation_type = ?")
            params.append(evaluation_type)
        if verdict:
            wheres.append("verdict = ?")
            params.append(verdict)
        if wheres:
            sql += " WHERE " + " AND ".join(wheres)
        sql += " ORDER BY evaluated_at DESC LIMIT ?"
        params.append(max(1, min(limit, 1000)))
        with self.connect() as conn:
            rows = conn.execute(sql, params).fetchall()
        out: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            item["baseline_metrics"] = json.loads(item.pop("baseline_metrics_json"))
            item["candidate_metrics"] = json.loads(item.pop("candidate_metrics_json"))
            item["diff_metrics"] = json.loads(item.pop("diff_metrics_json"))
            out.append(item)
        return out

    def create_rollout_job(
        self,
        *,
        rollout_id: str,
        candidate_id: str,
        rollout_scope: dict[str, Any],
        current_stage: str,
        status: str,
        rollback_point: str | None = None,
    ) -> dict[str, Any]:
        now = utc_now()
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO rollout_jobs (
                    rollout_id, candidate_id, started_at, finished_at, rollout_scope_json,
                    current_stage, status, rollback_point, result_summary_json
                ) VALUES (?, ?, ?, NULL, ?, ?, ?, ?, '{}')
                """,
                (rollout_id, candidate_id, now, json.dumps(rollout_scope), current_stage, status, rollback_point),
            )
        return self.get_rollout_job(rollout_id)

    def update_rollout_job(
        self,
        rollout_id: str,
        *,
        current_stage: str,
        status: str,
        finished: bool = False,
        result_summary: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        finished_at = utc_now() if finished else None
        with self.connect() as conn:
            cursor = conn.execute(
                """
                UPDATE rollout_jobs
                SET current_stage = ?, status = ?, finished_at = COALESCE(?, finished_at), result_summary_json = ?
                WHERE rollout_id = ?
                """,
                (current_stage, status, finished_at, json.dumps(result_summary or {}), rollout_id),
            )
        if cursor.rowcount <= 0:
            raise KeyError(rollout_id)
        return self.get_rollout_job(rollout_id)

    def get_rollout_job(self, rollout_id: str) -> dict[str, Any]:
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM rollout_jobs WHERE rollout_id = ?", (rollout_id,)).fetchone()
        if row is None:
            raise KeyError(rollout_id)
        result = dict(row)
        result["rollout_scope"] = json.loads(result.pop("rollout_scope_json"))
        result["result_summary"] = json.loads(result.pop("result_summary_json"))
        return result

    def list_rollout_jobs(self, *, candidate_id: str | None = None, status: str | None = None, limit: int = 200) -> list[dict[str, Any]]:
        sql = "SELECT * FROM rollout_jobs"
        params: list[Any] = []
        wheres: list[str] = []
        if candidate_id:
            wheres.append("candidate_id = ?")
            params.append(candidate_id)
        if status:
            wheres.append("status = ?")
            params.append(status)
        if wheres:
            sql += " WHERE " + " AND ".join(wheres)
        sql += " ORDER BY started_at DESC LIMIT ?"
        params.append(max(1, min(limit, 1000)))
        with self.connect() as conn:
            rows = conn.execute(sql, params).fetchall()
        out: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            item["rollout_scope"] = json.loads(item.pop("rollout_scope_json"))
            item["result_summary"] = json.loads(item.pop("result_summary_json"))
            out.append(item)
        return out

    def advance_rollout_stage(self, rollout_id: str) -> dict[str, Any]:
        job = self.get_rollout_job(rollout_id)
        if job["status"] not in ROLLOUT_ACTIVE_STATUSES:
            raise ValueError("invalid_rollout_status")
        current = job["current_stage"]
        if current not in ROLLOUT_STAGE_ORDER:
            raise ValueError("invalid_rollout_stage")
        idx = ROLLOUT_STAGE_ORDER.index(current)
        if idx == len(ROLLOUT_STAGE_ORDER) - 1:
            return self.update_rollout_job(
                rollout_id,
                current_stage=current,
                status="completed",
                finished=True,
                result_summary={"message": "rollout completed"},
            )
        next_stage = ROLLOUT_STAGE_ORDER[idx + 1]
        return self.update_rollout_job(
            rollout_id,
            current_stage=next_stage,
            status="running",
            finished=False,
            result_summary={"message": f"advanced_to_{next_stage}"},
        )

    def rollback_rollout(self, rollout_id: str, *, reason: str) -> dict[str, Any]:
        job = self.get_rollout_job(rollout_id)
        if job["status"] in {"completed", "rolled_back"}:
            raise ValueError("rollback_not_allowed")
        return self.update_rollout_job(
            rollout_id,
            current_stage=job["current_stage"],
            status="rolled_back",
            finished=True,
            result_summary={"message": "rollback_executed", "reason": reason},
        )

    def create_feedback(
        self,
        *,
        feedback_id: str,
        source_product: str,
        source_ref: str,
        feedback_type: str,
        feedback_value: str,
        severity_override: str | None,
        comment: str | None,
        created_by: str,
    ) -> dict[str, Any]:
        now = utc_now()
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO analyst_feedback (
                    feedback_id, created_at, source_product, source_ref, feedback_type,
                    feedback_value, severity_override, comment, created_by
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    feedback_id,
                    now,
                    source_product,
                    source_ref,
                    feedback_type,
                    feedback_value,
                    severity_override,
                    comment,
                    created_by,
                ),
            )
        return self.get_feedback(feedback_id)

    def get_feedback(self, feedback_id: str) -> dict[str, Any]:
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM analyst_feedback WHERE feedback_id = ?", (feedback_id,)).fetchone()
        if row is None:
            raise KeyError(feedback_id)
        return dict(row)

    def list_feedback(
        self,
        *,
        source_product: str | None = None,
        feedback_type: str | None = None,
        created_by: str | None = None,
        limit: int = 200,
    ) -> list[dict[str, Any]]:
        sql = "SELECT * FROM analyst_feedback"
        wheres: list[str] = []
        params: list[Any] = []
        if source_product:
            wheres.append("source_product = ?")
            params.append(source_product)
        if feedback_type:
            wheres.append("feedback_type = ?")
            params.append(feedback_type)
        if created_by:
            wheres.append("created_by = ?")
            params.append(created_by)
        if wheres:
            sql += " WHERE " + " AND ".join(wheres)
        sql += " ORDER BY created_at DESC LIMIT ?"
        params.append(max(1, min(limit, 1000)))
        with self.connect() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [dict(row) for row in rows]

    def generate_candidates_from_feedback(
        self,
        *,
        min_hits: int = 3,
        created_by: str = "feedback-bot",
    ) -> list[dict[str, Any]]:
        if min_hits < 1:
            raise ValueError("invalid_min_hits")
        now = utc_now()
        with self.connect() as conn:
            rows = conn.execute(
                """
                SELECT source_product, source_ref, feedback_type, COUNT(*) AS c
                FROM analyst_feedback
                GROUP BY source_product, source_ref, feedback_type
                HAVING c >= ?
                ORDER BY c DESC
                """,
                (min_hits,),
            ).fetchall()
            existing_keys: set[tuple[str, str, str]] = set()
            if rows:
                products = sorted({str(row["source_product"]) for row in rows})
                feedback_types = sorted({f"feedback_{str(row['feedback_type'])}" for row in rows})
                product_chunk_size = 64
                type_chunk_size = 16
                for i in range(0, len(products), product_chunk_size):
                    product_chunk = products[i : i + product_chunk_size]
                    product_placeholders = ",".join(["?"] * len(product_chunk))
                    for j in range(0, len(feedback_types), type_chunk_size):
                        type_chunk = feedback_types[j : j + type_chunk_size]
                        type_placeholders = ",".join(["?"] * len(type_chunk))
                        existing_rows = conn.execute(
                            f"""
                            SELECT source_product, target_ref, candidate_type
                            FROM improvement_candidates
                            WHERE source_product IN ({product_placeholders})
                              AND candidate_type IN ({type_placeholders})
                            """,
                            [*product_chunk, *type_chunk],
                        ).fetchall()
                        for existing in existing_rows:
                            existing_keys.add(
                                (
                                    str(existing["source_product"]),
                                    str(existing["target_ref"]),
                                    str(existing["candidate_type"]),
                                )
                            )
            row_data = [
                {
                    "source_product": str(row["source_product"]),
                    "source_ref": str(row["source_ref"]),
                    "feedback_type": str(row["feedback_type"]),
                    "c": int(row["c"]),
                }
                for row in rows
            ]
            existing_items = [
                {
                    "source_product": source_product,
                    "target_ref": target_ref,
                    "candidate_type": candidate_type,
                }
                for source_product, target_ref, candidate_type in sorted(existing_keys)
            ]
            rust_plan = self._feedback_rust_plan(
                rows=row_data,
                existing=existing_items,
                min_hits=min_hits,
            )
            planned_rows = rust_plan if rust_plan is not None else row_data

            created_ids: list[str] = []
            for row in planned_rows:
                source_product = str(row["source_product"])
                source_ref = str(row["source_ref"])
                feedback_type = str(row["feedback_type"])
                hit_count = int(row["c"])
                dedupe_key = (source_product, source_ref, f"feedback_{feedback_type}")

                # Python fallback path still enforces dedupe.
                if rust_plan is None and dedupe_key in existing_keys:
                    continue

                candidate_id = f"cand-fb-{secrets.token_hex(8)}"
                title = f"Feedback-driven tuning for {source_ref}"
                proposal = {
                    "strategy": "feedback_driven_tuning",
                    "feedback_type": feedback_type,
                    "source_ref": source_ref,
                    "recommended_action": "reduce_score" if feedback_type == "false_positive" else "raise_score",
                }
                evidence = {"feedback_hits": hit_count, "source_ref": source_ref, "feedback_type": feedback_type}
                expected = {"false_positive_delta": -0.1 if feedback_type == "false_positive" else 0.0}
                conn.execute(
                    """
                    INSERT INTO improvement_candidates (
                        candidate_id, created_at, source_product, source_kind, candidate_type,
                        target_scope, target_ref, title, proposal_json, evidence_json, reason_summary,
                        expected_benefit_json, risk_level, status, created_by_type, created_by, decision_note, updated_at
                    ) VALUES (?, ?, ?, 'analyst_feedback', ?, 'rule', ?, ?, ?, ?, ?, ?, 'medium', 'new', 'program', ?, '', ?)
                    """,
                    (
                        candidate_id,
                        now,
                        source_product,
                        f"feedback_{feedback_type}",
                        source_ref,
                        title,
                        json.dumps(proposal),
                        json.dumps(evidence),
                        f"{feedback_type} reached threshold ({hit_count})",
                        json.dumps(expected),
                        created_by,
                        now,
                    ),
                )
                created_ids.append(candidate_id)
                existing_keys.add(dedupe_key)
        if not created_ids:
            return []
        placeholders = ",".join(["?"] * len(created_ids))
        with self.connect() as conn:
            rows = conn.execute(
                f"SELECT * FROM improvement_candidates WHERE candidate_id IN ({placeholders})",
                created_ids,
            ).fetchall()
        by_id = {row["candidate_id"]: self._candidate_row(row) for row in rows}
        return [by_id[candidate_id] for candidate_id in created_ids if candidate_id in by_id]

    @staticmethod
    def _feedback_rust_binary() -> Path:
        path = os.getenv("SOC_FEEDBACK_RUST_BIN", "").strip()
        if path:
            return Path(path)
        return Path(__file__).resolve().parents[2] / "rust_feedback_bench" / "target" / "release" / "rust_feedback_bench"

    @classmethod
    def _feedback_rust_plan(
        cls,
        *,
        rows: list[dict[str, Any]],
        existing: list[dict[str, str]],
        min_hits: int,
    ) -> list[dict[str, Any]] | None:
        enabled = os.getenv("SOC_FEEDBACK_RUST_ENABLED", "1").strip().lower()
        if enabled in {"0", "false", "off", "no"}:
            return None

        rust_bin = cls._feedback_rust_binary()
        if not rust_bin.exists():
            return None

        lines: list[str] = [f"CONFIG|1|{max(1, min_hits)}"]
        for row in rows:
            lines.append(
                "ROW|{}|{}|{}|{}".format(
                    cls._escape_pipe(str(row.get("source_product", ""))),
                    cls._escape_pipe(str(row.get("source_ref", ""))),
                    cls._escape_pipe(str(row.get("feedback_type", ""))),
                    int(row.get("c") or 0),
                )
            )
        for item in existing:
            lines.append(
                "EXISTING|{}|{}|{}".format(
                    cls._escape_pipe(str(item.get("source_product", ""))),
                    cls._escape_pipe(str(item.get("target_ref", ""))),
                    cls._escape_pipe(str(item.get("candidate_type", ""))),
                )
            )

        with NamedTemporaryFile("w", encoding="utf-8", suffix=".txt", delete=False) as fp:
            temp_path = Path(fp.name)
            fp.write("\n".join(lines))

        try:
            proc = subprocess.run(
                [str(rust_bin), "plan", str(temp_path)],
                text=True,
                capture_output=True,
                timeout=15,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            temp_path.unlink(missing_ok=True)
            return None
        temp_path.unlink(missing_ok=True)

        if proc.returncode != 0:
            return None

        out: list[dict[str, Any]] = []
        for raw_line in proc.stdout.splitlines():
            line = raw_line.strip()
            if not line:
                continue
            parts = line.split("|")
            if len(parts) != 5 or parts[0] != "CREATE":
                continue
            try:
                out.append(
                    {
                        "source_product": cls._unescape_pipe(parts[1]),
                        "source_ref": cls._unescape_pipe(parts[2]),
                        "feedback_type": cls._unescape_pipe(parts[3]),
                        "c": int(parts[4]),
                    }
                )
            except ValueError:
                continue
        return out

    @staticmethod
    def _escape_pipe(value: str) -> str:
        return value.replace("%", "%25").replace("|", "%7C").replace("\n", " ").replace("\r", " ")

    @staticmethod
    def _unescape_pipe(value: str) -> str:
        return value.replace("%7C", "|").replace("%25", "%")

    def create_audit_log(
        self,
        *,
        audit_id: str,
        actor_type: str,
        actor_name: str,
        action_type: str,
        target_type: str,
        target_ref: str,
        before: dict[str, Any] | None,
        after: dict[str, Any] | None,
        result: str,
    ) -> dict[str, Any]:
        now = utc_now()
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO audit_logs (
                    audit_id, created_at, actor_type, actor_name, action_type,
                    target_type, target_ref, before_json, after_json, result
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    audit_id,
                    now,
                    actor_type,
                    actor_name,
                    action_type,
                    target_type,
                    target_ref,
                    json.dumps(before or {}),
                    json.dumps(after or {}),
                    result,
                ),
            )
        return self.get_audit_log(audit_id)

    def create_source(
        self,
        *,
        source_id: str,
        product_name: str,
        source_type: str,
        base_url: str,
        auth_type: str,
        auth_secret_ref: str = "",
    ) -> dict[str, Any]:
        now = utc_now()
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO product_sources (
                    source_id, product_name, source_type, base_url, auth_type, auth_secret_ref,
                    status, last_seen_at, last_health_json, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, 'active', NULL, '{}', ?, ?)
                """,
                (
                    source_id,
                    product_name,
                    source_type,
                    base_url,
                    auth_type,
                    auth_secret_ref,
                    now,
                    now,
                ),
            )
        return self.get_source(source_id)

    def update_source(
        self,
        source_id: str,
        *,
        base_url: str | None = None,
        auth_type: str | None = None,
        auth_secret_ref: str | None = None,
        status: str | None = None,
    ) -> dict[str, Any]:
        updates: list[str] = []
        params: list[Any] = []
        if base_url is not None:
            updates.append("base_url = ?")
            params.append(base_url)
        if auth_type is not None:
            updates.append("auth_type = ?")
            params.append(auth_type)
        if auth_secret_ref is not None:
            updates.append("auth_secret_ref = ?")
            params.append(auth_secret_ref)
        if status is not None:
            updates.append("status = ?")
            params.append(status)
        if not updates:
            return self.get_source(source_id)
        updates.append("updated_at = ?")
        params.append(utc_now())
        params.append(source_id)
        with self.connect() as conn:
            cursor = conn.execute(f"UPDATE product_sources SET {', '.join(updates)} WHERE source_id = ?", params)
        if cursor.rowcount <= 0:
            raise KeyError(source_id)
        return self.get_source(source_id)

    def source_heartbeat(self, source_id: str, *, health_payload: dict[str, Any], seen_at: str | None = None) -> dict[str, Any]:
        seen = seen_at or utc_now()
        with self.connect() as conn:
            cursor = conn.execute(
                """
                UPDATE product_sources
                SET last_seen_at = ?, last_health_json = ?, updated_at = ?
                WHERE source_id = ?
                """,
                (seen, json.dumps(health_payload), seen, source_id),
            )
        if cursor.rowcount <= 0:
            raise KeyError(source_id)
        return self.get_source(source_id)

    def get_source(self, source_id: str) -> dict[str, Any]:
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM product_sources WHERE source_id = ?", (source_id,)).fetchone()
        if row is None:
            raise KeyError(source_id)
        item = dict(row)
        item["last_health"] = json.loads(item.pop("last_health_json"))
        return item

    def list_sources(self, *, product_name: str | None = None, status: str | None = None, limit: int = 200) -> list[dict[str, Any]]:
        sql = "SELECT * FROM product_sources"
        params: list[Any] = []
        where: list[str] = []
        if product_name:
            where.append("product_name = ?")
            params.append(product_name)
        if status:
            where.append("status = ?")
            params.append(status)
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY updated_at DESC LIMIT ?"
        params.append(max(1, min(limit, 1000)))
        with self.connect() as conn:
            rows = conn.execute(sql, params).fetchall()
        out: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            item["last_health"] = json.loads(item.pop("last_health_json"))
            out.append(item)
        return out

    def get_audit_log(self, audit_id: str) -> dict[str, Any]:
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM audit_logs WHERE audit_id = ?", (audit_id,)).fetchone()
        if row is None:
            raise KeyError(audit_id)
        result = dict(row)
        result["before"] = json.loads(result.pop("before_json"))
        result["after"] = json.loads(result.pop("after_json"))
        return result

    def list_audit_logs(self, *, action_type: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
        sql = "SELECT * FROM audit_logs"
        params: list[Any] = []
        if action_type:
            sql += " WHERE action_type = ?"
            params.append(action_type)
        sql += " ORDER BY created_at DESC LIMIT ?"
        params.append(max(1, min(limit, 2000)))
        with self.connect() as conn:
            rows = conn.execute(sql, params).fetchall()
        out: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            item["before"] = json.loads(item.pop("before_json"))
            item["after"] = json.loads(item.pop("after_json"))
            out.append(item)
        return out

    def command_center_summary(self) -> dict[str, Any]:
        with self.connect() as conn:
            policy_count = int(conn.execute("SELECT COUNT(*) AS c FROM decision_policies").fetchone()["c"])
            candidate_count = int(conn.execute("SELECT COUNT(*) AS c FROM improvement_candidates").fetchone()["c"])
            source_count = int(conn.execute("SELECT COUNT(*) AS c FROM product_sources").fetchone()["c"])
            source_active_count = int(
                conn.execute("SELECT COUNT(*) AS c FROM product_sources WHERE status = 'active'").fetchone()["c"]
            )
            protected_asset_count = int(conn.execute("SELECT COUNT(*) AS c FROM protected_assets").fetchone()["c"])
            audit_24h = int(
                conn.execute(
                    """
                    SELECT COUNT(*) AS c
                    FROM audit_logs
                    WHERE created_at >= datetime('now', '-1 day')
                    """
                ).fetchone()["c"]
            )
            candidate_rows = conn.execute(
                """
                SELECT status, COUNT(*) AS c
                FROM improvement_candidates
                GROUP BY status
                ORDER BY c DESC
                """
            ).fetchall()
            source_rows = conn.execute(
                """
                SELECT product_name, source_id, status, last_seen_at, last_health_json, updated_at
                FROM product_sources
                ORDER BY updated_at DESC
                LIMIT 20
                """
            ).fetchall()
            recent_audit_rows = conn.execute(
                """
                SELECT audit_id, created_at, actor_type, actor_name, action_type, target_type, target_ref, result
                FROM audit_logs
                ORDER BY created_at DESC
                LIMIT 20
                """
            ).fetchall()

        status_counts = {row["status"]: int(row["c"]) for row in candidate_rows}
        recent_sources: list[dict[str, Any]] = []
        for row in source_rows:
            item = dict(row)
            item["last_health"] = json.loads(item.pop("last_health_json"))
            recent_sources.append(item)

        return {
            "policy_count": policy_count,
            "candidate_count": candidate_count,
            "candidate_status_counts": status_counts,
            "source_count": source_count,
            "source_active_count": source_active_count,
            "protected_asset_count": protected_asset_count,
            "audit_24h": audit_24h,
            "recent_sources": recent_sources,
            "recent_audits": [dict(row) for row in recent_audit_rows],
        }

    def get_safety_guard_config(self) -> dict[str, Any]:
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM safety_guard_config WHERE config_id = 'global'").fetchone()
        if row is None:
            raise KeyError("global")
        item = dict(row)
        item["block_protected_assets"] = bool(item["block_protected_assets"])
        return item

    def upsert_safety_guard_config(self, *, max_targets: int, block_protected_assets: bool) -> dict[str, Any]:
        if max_targets < 1:
            raise ValueError("invalid_max_targets")
        now = utc_now()
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO safety_guard_config (config_id, max_targets, block_protected_assets, updated_at)
                VALUES ('global', ?, ?, ?)
                ON CONFLICT(config_id) DO UPDATE SET
                    max_targets = excluded.max_targets,
                    block_protected_assets = excluded.block_protected_assets,
                    updated_at = excluded.updated_at
                """,
                (max_targets, 1 if block_protected_assets else 0, now),
            )
        return self.get_safety_guard_config()

    def create_protected_asset(
        self,
        *,
        protected_id: str,
        asset_type: str,
        asset_key: str,
        reason: str = "",
    ) -> dict[str, Any]:
        now = utc_now()
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO protected_assets (protected_id, asset_type, asset_key, reason, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (protected_id, asset_type, asset_key, reason, now),
            )
        return self.get_protected_asset(protected_id)

    def list_protected_assets(self, *, asset_type: str | None = None, limit: int = 200) -> list[dict[str, Any]]:
        sql = "SELECT * FROM protected_assets"
        params: list[Any] = []
        if asset_type:
            sql += " WHERE asset_type = ?"
            params.append(asset_type)
        sql += " ORDER BY created_at DESC LIMIT ?"
        params.append(max(1, min(limit, 1000)))
        with self.connect() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [dict(row) for row in rows]

    def get_protected_asset(self, protected_id: str) -> dict[str, Any]:
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM protected_assets WHERE protected_id = ?", (protected_id,)).fetchone()
        if row is None:
            raise KeyError(protected_id)
        return dict(row)

    def delete_protected_asset(self, protected_id: str) -> None:
        with self.connect() as conn:
            cursor = conn.execute("DELETE FROM protected_assets WHERE protected_id = ?", (protected_id,))
        if cursor.rowcount <= 0:
            raise KeyError(protected_id)

    def is_protected_asset(self, asset_key: str) -> bool:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT 1 FROM protected_assets WHERE asset_key = ? LIMIT 1",
                (asset_key,),
            ).fetchone()
        return row is not None

    def validate_rollout_safety(self, *, candidate_id: str, rollout_scope: dict[str, Any]) -> None:
        cfg = self.get_safety_guard_config()
        max_targets = int(cfg["max_targets"])

        target_count = 1
        if isinstance(rollout_scope.get("target_refs"), list):
            target_count = len(rollout_scope["target_refs"])
        elif isinstance(rollout_scope.get("targets"), list):
            target_count = len(rollout_scope["targets"])
        elif isinstance(rollout_scope.get("target_count"), int):
            target_count = int(rollout_scope["target_count"])

        if target_count > max_targets:
            raise ValueError("blast_radius_exceeded")

        if bool(cfg["block_protected_assets"]):
            candidate = self.get_candidate(candidate_id)
            candidate_target = str(candidate.get("target_ref", "")).strip()
            if candidate_target and self.is_protected_asset(candidate_target):
                raise ValueError("protected_asset_blocked")

    def create_runbook(
        self,
        *,
        runbook_id: str,
        name: str,
        incident_type: str,
        trigger_condition: dict[str, Any],
        steps: list[dict[str, Any]],
        safety_policy: dict[str, Any],
        enabled: bool = True,
    ) -> dict[str, Any]:
        now = utc_now()
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO runbooks (
                    runbook_id, name, incident_type, version, enabled,
                    trigger_condition_json, steps_json, safety_policy_json, updated_at
                ) VALUES (?, ?, ?, 1, ?, ?, ?, ?, ?)
                """,
                (
                    runbook_id,
                    name,
                    incident_type,
                    1 if enabled else 0,
                    json.dumps(trigger_condition),
                    json.dumps(steps),
                    json.dumps(safety_policy),
                    now,
                ),
            )
        return self.get_runbook(runbook_id)

    def update_runbook(
        self,
        runbook_id: str,
        *,
        name: str | None = None,
        incident_type: str | None = None,
        trigger_condition: dict[str, Any] | None = None,
        steps: list[dict[str, Any]] | None = None,
        safety_policy: dict[str, Any] | None = None,
        enabled: bool | None = None,
    ) -> dict[str, Any]:
        updates: list[str] = []
        params: list[Any] = []
        if name is not None:
            updates.append("name = ?")
            params.append(name)
        if incident_type is not None:
            updates.append("incident_type = ?")
            params.append(incident_type)
        if trigger_condition is not None:
            updates.append("trigger_condition_json = ?")
            params.append(json.dumps(trigger_condition))
        if steps is not None:
            updates.append("steps_json = ?")
            params.append(json.dumps(steps))
        if safety_policy is not None:
            updates.append("safety_policy_json = ?")
            params.append(json.dumps(safety_policy))
        if enabled is not None:
            updates.append("enabled = ?")
            params.append(1 if enabled else 0)
        if not updates:
            return self.get_runbook(runbook_id)
        updates.append("version = version + 1")
        updates.append("updated_at = ?")
        params.append(utc_now())
        params.append(runbook_id)
        with self.connect() as conn:
            cursor = conn.execute(
                f"UPDATE runbooks SET {', '.join(updates)} WHERE runbook_id = ?",
                params,
            )
        if cursor.rowcount <= 0:
            raise KeyError(runbook_id)
        return self.get_runbook(runbook_id)

    def get_runbook(self, runbook_id: str) -> dict[str, Any]:
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM runbooks WHERE runbook_id = ?", (runbook_id,)).fetchone()
        if row is None:
            raise KeyError(runbook_id)
        return self._runbook_row(row)

    def list_runbooks(self, *, incident_type: str | None = None, enabled: bool | None = None, limit: int = 200) -> list[dict[str, Any]]:
        sql = "SELECT * FROM runbooks"
        wheres: list[str] = []
        params: list[Any] = []
        if incident_type:
            wheres.append("incident_type = ?")
            params.append(incident_type)
        if enabled is not None:
            wheres.append("enabled = ?")
            params.append(1 if enabled else 0)
        if wheres:
            sql += " WHERE " + " AND ".join(wheres)
        sql += " ORDER BY updated_at DESC LIMIT ?"
        params.append(max(1, min(limit, 1000)))
        with self.connect() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [self._runbook_row(row) for row in rows]

    def create_runbook_execution(
        self,
        *,
        execution_id: str,
        runbook_id: str,
        incident_ref: str | None,
        status: str = "running",
        execution_log: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        now = utc_now()
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO runbook_executions (
                    execution_id, runbook_id, incident_ref, started_at, finished_at, status, execution_log_json
                ) VALUES (?, ?, ?, ?, NULL, ?, ?)
                """,
                (
                    execution_id,
                    runbook_id,
                    incident_ref,
                    now,
                    status,
                    json.dumps(execution_log or {}),
                ),
            )
        return self.get_runbook_execution(execution_id)

    def update_runbook_execution(
        self,
        execution_id: str,
        *,
        status: str,
        execution_log: dict[str, Any] | None = None,
        finished: bool = False,
    ) -> dict[str, Any]:
        finished_at = utc_now() if finished else None
        with self.connect() as conn:
            cursor = conn.execute(
                """
                UPDATE runbook_executions
                SET status = ?, execution_log_json = ?, finished_at = COALESCE(?, finished_at)
                WHERE execution_id = ?
                """,
                (status, json.dumps(execution_log or {}), finished_at, execution_id),
            )
        if cursor.rowcount <= 0:
            raise KeyError(execution_id)
        return self.get_runbook_execution(execution_id)

    def get_runbook_execution(self, execution_id: str) -> dict[str, Any]:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT * FROM runbook_executions WHERE execution_id = ?",
                (execution_id,),
            ).fetchone()
        if row is None:
            raise KeyError(execution_id)
        item = dict(row)
        item["execution_log"] = json.loads(item.pop("execution_log_json"))
        return item

    def list_runbook_executions(
        self,
        *,
        runbook_id: str | None = None,
        status: str | None = None,
        limit: int = 200,
    ) -> list[dict[str, Any]]:
        sql = "SELECT * FROM runbook_executions"
        wheres: list[str] = []
        params: list[Any] = []
        if runbook_id:
            wheres.append("runbook_id = ?")
            params.append(runbook_id)
        if status:
            wheres.append("status = ?")
            params.append(status)
        if wheres:
            sql += " WHERE " + " AND ".join(wheres)
        sql += " ORDER BY started_at DESC LIMIT ?"
        params.append(max(1, min(limit, 1000)))
        with self.connect() as conn:
            rows = conn.execute(sql, params).fetchall()
        out: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            item["execution_log"] = json.loads(item.pop("execution_log_json"))
            out.append(item)
        return out

    @staticmethod
    def _policy_row(row: sqlite3.Row) -> dict[str, Any]:
        result = dict(row)
        result["auto_allowed_actions"] = json.loads(result.pop("auto_allowed_actions_json"))
        result["auto_allowed_improvements"] = json.loads(result.pop("auto_allowed_improvements_json"))
        result["freeze_enabled"] = bool(result["freeze_enabled"])
        return result

    @staticmethod
    def _candidate_row(row: sqlite3.Row) -> dict[str, Any]:
        result = dict(row)
        result["proposal"] = json.loads(result.pop("proposal_json"))
        evidence_json = result.pop("evidence_json", "{}")
        result["evidence"] = json.loads(evidence_json or "{}")
        result["expected_benefit"] = json.loads(result.pop("expected_benefit_json"))
        return result

    @staticmethod
    def _runbook_row(row: sqlite3.Row) -> dict[str, Any]:
        item = dict(row)
        item["enabled"] = bool(item["enabled"])
        item["trigger_condition"] = json.loads(item.pop("trigger_condition_json"))
        item["steps"] = json.loads(item.pop("steps_json"))
        item["safety_policy"] = json.loads(item.pop("safety_policy_json"))
        return item
