#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "${ROOT_DIR}"

if [ ! -d ".venv" ]; then
  python3 -m venv .venv
fi

./.venv/bin/pip install -e . >/dev/null
exec ./.venv/bin/uvicorn exkururusoc.api:app --host 127.0.0.1 --port 8820
