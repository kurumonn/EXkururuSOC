# exkururuSOC

[Japanese README](README.md)
[4-stack demo note](README.4stack.md)

EXkururuSOC is the lightweight orchestration layer of the EXkururu stack.
The public repository keeps the product surface that is valuable to show publicly: policy workflow, rollout
control, feedback intake, and local startup.

## Public scope

- Lightweight FastAPI control plane
- Policy, candidate, evaluation, rollout, runbook, and feedback APIs
- Standalone startup for local development
- Source heartbeat and management surface

Production heuristics, tuning values, and operational decision logic are intentionally excluded from the
public distribution.

## Quick Start

```bash
cd /path/to/exkururuSOC
python3 -m venv .venv
./.venv/bin/pip install -e .
PYTHONPATH=src ./.venv/bin/python scripts/migrate.py
./.venv/bin/uvicorn exkururusoc.api:app --host 127.0.0.1 --port 8820
```

## Public environment variables

- `SOC_API_ADMIN_TOKEN`
- `SOC_ENV`
- `SOC_LOG_LEVEL`
- `SOC_DB_PATH`
- `SOC_ALLOW_INSECURE_NO_AUTH`
