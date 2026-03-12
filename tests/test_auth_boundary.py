from __future__ import annotations

import os

import pytest
from fastapi import HTTPException

from exkururusoc import app_context
from exkururusoc.routers.policies_decision import list_policies


def test_protected_api_requires_admin_token(setup_env) -> None:
    with pytest.raises(HTTPException) as exc:
        list_policies(x_admin_token=None)
    assert exc.value.status_code == 401


def test_admin_token_not_configured_returns_503(setup_env) -> None:
    os.environ["SOC_API_ADMIN_TOKEN"] = ""
    os.environ["SOC_ALLOW_INSECURE_NO_AUTH"] = "0"
    app_context._storage = None
    with pytest.raises(HTTPException) as exc:
        list_policies(x_admin_token=None)
    assert exc.value.status_code == 503
    assert exc.value.detail == "admin_token_not_configured"
