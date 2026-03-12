from __future__ import annotations

import pytest
from fastapi import HTTPException

from exkururusoc.routers.safety_runbooks_feedback import (
    FeedbackAutoCandidateRequest,
    FeedbackCreateRequest,
    create_feedback,
    generate_auto_candidates_from_feedback,
)


def test_auto_candidates_requires_admin_token(setup_env) -> None:
    with pytest.raises(HTTPException) as exc:
        generate_auto_candidates_from_feedback(
            FeedbackAutoCandidateRequest(min_hits=1, created_by="bot"),
            x_admin_token=None,
        )
    assert exc.value.status_code == 401


def test_auto_candidates_creates_once_and_then_dedups(setup_env) -> None:
    for i in range(3):
        create_feedback(
            FeedbackCreateRequest(
                source_product="exkururuipros",
                source_ref="RULE-XYZ",
                feedback_type="false_positive",
                feedback_value="confirmed",
                severity_override="low",
                comment=f"noise-{i}",
                created_by="analyst-a",
            ),
            x_admin_token="test-admin-token",
        )

    first = generate_auto_candidates_from_feedback(
        FeedbackAutoCandidateRequest(min_hits=3, created_by="feedback-bot"),
        x_admin_token="test-admin-token",
    )
    assert first["created_count"] == 1
    assert len(first["items"]) == 1
    assert first["items"][0]["target_ref"] == "RULE-XYZ"

    second = generate_auto_candidates_from_feedback(
        FeedbackAutoCandidateRequest(min_hits=3, created_by="feedback-bot"),
        x_admin_token="test-admin-token",
    )
    assert second["created_count"] == 0
    assert second["items"] == []
