from __future__ import annotations

import os
from pathlib import Path

import pytest
from exkururusoc import app_context


@pytest.fixture()
def setup_env(tmp_path: Path) -> None:
    db_path = tmp_path / "soc_test.db"
    os.environ["SOC_DB_PATH"] = str(db_path)
    os.environ["SOC_API_ADMIN_TOKEN"] = "test-admin-token"
    os.environ["SOC_ALLOW_INSECURE_NO_AUTH"] = "0"
    app_context._storage = None
    yield
    app_context._storage = None


@pytest.fixture()
def admin_headers() -> dict[str, str]:
    return {"X-Admin-Token": "test-admin-token"}
