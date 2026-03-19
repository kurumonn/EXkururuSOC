# exkururuSOC

[Japanese README](README.md)
[4-stack demo note](README.4stack.md)

EXkururuSOC is the lightweight orchestration layer of the EXkururu stack.
The public repository keeps the product surface that is valuable to show publicly: policy workflow, rollout
control, feedback intake, and local startup.

This README is for public distribution. It does not include secrets or private operational know-how.

## Public scope

- Lightweight FastAPI control plane
- Policy, candidate, evaluation, rollout, runbook, and feedback APIs
- Standalone startup for local development
- Source heartbeat and management surface

Production heuristics, tuning values, and operational decision logic are intentionally excluded from the
public distribution.

## Not included in the public release

- Production admin tokens, source tokens, certificates, and target URLs
- Private runbooks, operational procedures, and recovery playbooks
- Scoring thresholds, evaluation criteria, and rollout decision details
- Customer data, live operational logs, adjustment notes, and secret corpora
- Private external integrations and fixed values used only for internal validation

## Quick Start

```bash
cd /path/to/exkururuSOC
python3 -m venv .venv
./.venv/bin/pip install -e ".[dev]"
PYTHONPATH=src ./.venv/bin/python scripts/migrate.py
./.venv/bin/pytest -q
./.venv/bin/uvicorn exkururusoc.api:app --host 127.0.0.1 --port 8820
```

Docker is the easiest way to run this package.

```bash
cd /path/to/exkururuSOC
cp .env.example .env
docker compose -f docker-compose.yaml up --build
```

Open `http://127.0.0.1:8820` after startup.

## Public environment variables

- `SOC_API_ADMIN_TOKEN`
- `SOC_ENV`
- `SOC_LOG_LEVEL`
- `SOC_DB_PATH`
- `SOC_ALLOW_INSECURE_NO_AUTH`
- `SOC_SOURCE_REQUIRE_NONCE` (default: `1`)
- `SOC_SOURCE_SIGNATURE_MAX_SKEW_SEC` (default: `300`)
- `SOC_SOURCE_REPLAY_TTL_SEC` (default: `310`)
- `SOC_REPLAY_BACKEND` (`auto` / `redis` / `memory`, default: `auto`)
- `SOC_REDIS_URL` (set this to enable the shared replay cache)
- `SOC_REPLAY_FALLBACK_TO_MEMORY` (default: `1`)
- `SOC_REPLAY_CACHE_MAX_ITEMS` (default: `200000`)

When `SOC_REPLAY_BACKEND=redis` and `SOC_REDIS_URL` are set, replay checks use Redis as a shared cache.
If Redis fails, the code falls back to in-memory replay tracking when `SOC_REPLAY_FALLBACK_TO_MEMORY=1`.

For `auth_type=signed_required`, the signature is computed over the exact raw request body bytes.
