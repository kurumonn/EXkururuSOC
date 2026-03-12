from __future__ import annotations

from fastapi import FastAPI

from .routers import (
    candidates_router,
    evaluations_rollouts_router,
    health_router,
    policies_decision_router,
    safety_runbooks_feedback_router,
    sources_dashboard_router,
)

app = FastAPI(title="EXkururuSOC", version="0.1.0")

app.include_router(health_router)
app.include_router(policies_decision_router)
app.include_router(candidates_router)
app.include_router(evaluations_rollouts_router)
app.include_router(safety_runbooks_feedback_router)
app.include_router(sources_dashboard_router)
