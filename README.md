# exkururuSOC

[English README](README.en.md)
[4-stack demo note](README.4stack.md)

EXkururuSOC is the lightweight orchestration layer for operating the EXkururu security products together.
The public repository keeps the control-plane surface that is useful to evaluate openly: policy workflow,
candidate lifecycle, rollout API, and integration-facing endpoints.

## Public scope

- Lightweight FastAPI control plane
- Policy, candidate, evaluation, rollout, runbook, and feedback APIs
- Standalone local startup
- Source heartbeat and integration-facing management surface

Implementation details that encode production tuning, scoring thresholds, or operational feedback heuristics
are intentionally excluded from the public distribution.

## Architecture role

```text
Signals from IPS / EDR / XDR
            |
            v
      EXkururuSOC
  policy / review / rollout
            |
            v
 Controlled decisions back to products
```

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

## API highlights

- `GET /healthz`
- `GET /api/v1/command-center`
- `GET /api/v1/policies`
- `GET /api/v1/candidates`
- `POST /api/v1/evaluations`
- `POST /api/v1/rollouts`
- `GET /api/v1/runbooks`
- `POST /api/v1/feedback`

## Security

- Keep secrets and production source references out of the repository.
- Use public settings for development only.
- Put shared environments behind TLS termination and authenticated reverse proxies.

