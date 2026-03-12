#!/usr/bin/env bash
set -euo pipefail

# 4-stack minimal demo:
# 1) EDR suspicious process sample
# 2) IPROS suspicious outbound sample
# 3) XDR incident creation
# 4) SOC candidate/evaluation/rollout

XDR_BASE="${XDR_BASE:-http://127.0.0.1:8810}"
SOC_BASE="${SOC_BASE:-http://127.0.0.1:8820}"
XDR_API_ADMIN_TOKEN="${XDR_API_ADMIN_TOKEN:-}"
SOC_API_ADMIN_TOKEN="${SOC_API_ADMIN_TOKEN:-}"
AUTO_START="${AUTO_START:-0}"
XDR_ROOT="${XDR_ROOT:-/home/kurumonn/exkururuXDR}"
SOC_ROOT="${SOC_ROOT:-/home/kurumonn/exkururuSOC}"
XDR_START_CMD="${XDR_START_CMD:-./.venv/bin/uvicorn exkururuxdr.api:app --app-dir src --host 127.0.0.1 --port 8810}"
SOC_START_CMD="${SOC_START_CMD:-./scripts/run_dev.sh}"

if [[ -z "$XDR_API_ADMIN_TOKEN" ]]; then
  echo "XDR_API_ADMIN_TOKEN is required" >&2
  exit 1
fi
if [[ -z "$SOC_API_ADMIN_TOKEN" ]]; then
  echo "SOC_API_ADMIN_TOKEN is required" >&2
  exit 1
fi

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing command: $1" >&2
    exit 1
  fi
}

wait_health() {
  local url="$1"
  for _ in $(seq 1 40); do
    if curl -fsS "$url" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.25
  done
  return 1
}

start_if_needed() {
  local name="$1"
  local base="$2"
  local root="$3"
  local cmd="$4"
  local health="$base/healthz"
  if curl -fsS "$health" >/dev/null 2>&1; then
    return 0
  fi
  if [[ "$AUTO_START" != "1" ]]; then
    echo "$name is not running: $base" >&2
    echo "Start command example:" >&2
    echo "  cd $root && $cmd" >&2
    return 1
  fi
  echo "starting $name..." >&2
  (
    cd "$root"
    nohup bash -lc "$cmd" >/tmp/demo_4stack_${name}.log 2>&1 &
  )
  if ! wait_health "$health"; then
    echo "failed to start $name (log: /tmp/demo_4stack_${name}.log)" >&2
    return 1
  fi
  return 0
}

need_cmd curl
need_cmd python3

json_get() {
  local json="$1"
  local key="$2"
  JSON_INPUT="$json" JSON_KEY="$key" python3 - <<'PY'
import json
import os

data = json.loads(os.environ["JSON_INPUT"])
key = os.environ["JSON_KEY"]
cur = data
for part in key.split("."):
    if part.isdigit():
        cur = cur[int(part)]
    else:
        cur = cur[part]
if isinstance(cur, (dict, list)):
    print(json.dumps(cur, ensure_ascii=False))
else:
    print(cur)
PY
}

echo "[0/6] health check"
start_if_needed "xdr" "$XDR_BASE" "$XDR_ROOT" "$XDR_START_CMD"
start_if_needed "soc" "$SOC_BASE" "$SOC_ROOT" "$SOC_START_CMD"

RUN_ID="$(date +%s)"
EDR_SOURCE_KEY="demo-edr-$RUN_ID"
IPROS_SOURCE_KEY="demo-ipros-$RUN_ID"
INCIDENT_KEY="demo-incident-$RUN_ID"

echo "[1/6] create XDR sources"
EDR_SOURCE_JSON="$(curl -fsS -X POST "$XDR_BASE/api/v1/sources" \
  -H "Authorization: Bearer $XDR_API_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"source_key\":\"$EDR_SOURCE_KEY\",\"product\":\"exkururuedr\",\"display_name\":\"Demo EDR $RUN_ID\",\"trust_mode\":\"legacy\",\"allow_event_ingest\":true}")"
IPROS_SOURCE_JSON="$(curl -fsS -X POST "$XDR_BASE/api/v1/sources" \
  -H "Authorization: Bearer $XDR_API_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"source_key\":\"$IPROS_SOURCE_KEY\",\"product\":\"exkururuipros\",\"display_name\":\"Demo IPROS $RUN_ID\",\"trust_mode\":\"legacy\",\"allow_event_ingest\":true}")"

EDR_SOURCE_TOKEN="$(json_get "$EDR_SOURCE_JSON" token)"
IPROS_SOURCE_TOKEN="$(json_get "$IPROS_SOURCE_JSON" token)"

echo "[2/6] ingest EDR suspicious process"
curl -fsS -X POST "$XDR_BASE/api/v1/events/single" \
  -H "X-Source-Key: $EDR_SOURCE_KEY" \
  -H "X-Source-Token: $EDR_SOURCE_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{
    \"schema_version\":\"common_security_event_v1\",
    \"event_id\":\"demo-edr-$RUN_ID-001\",
    \"time\":\"2026-03-11T10:00:00Z\",
    \"product\":\"exkururuedr\",
    \"category\":\"process\",
    \"event_type\":\"SUSPICIOUS_PROCESS\",
    \"severity\":\"high\",
    \"score\":92,
    \"labels\":[\"powershell\",\"encoded-command\"],
    \"src_ip\":\"192.0.2.10\",
    \"dst_ip\":null
  }" >/dev/null

echo "[3/6] ingest IPROS suspicious outbound"
curl -fsS -X POST "$XDR_BASE/api/v1/events/single" \
  -H "X-Source-Key: $IPROS_SOURCE_KEY" \
  -H "X-Source-Token: $IPROS_SOURCE_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{
    \"schema_version\":\"common_security_event_v1\",
    \"event_id\":\"demo-ipros-$RUN_ID-001\",
    \"time\":\"2026-03-11T10:00:10Z\",
    \"product\":\"exkururuipros\",
    \"category\":\"network\",
    \"event_type\":\"SUSPICIOUS_OUTBOUND\",
    \"severity\":\"high\",
    \"score\":88,
    \"labels\":[\"c2-like\",\"outbound-anomaly\"],
    \"src_ip\":\"192.0.2.10\",
    \"dst_ip\":\"203.0.113.50\"
  }" >/dev/null

echo "[4/6] create XDR incident"
INCIDENT_JSON="$(curl -fsS -X POST "$XDR_BASE/api/v1/incidents" \
  -H "Authorization: Bearer $XDR_API_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{
    \"incident_key\":\"$INCIDENT_KEY\",
    \"title\":\"EDR + IPROS correlated suspicious behavior\",
    \"severity\":\"high\",
    \"summary\":\"suspicious process + suspicious outbound\",
    \"first_seen\":\"2026-03-11T10:00:00Z\",
    \"last_seen\":\"2026-03-11T10:00:10Z\",
    \"events\":[
      {\"event_id\":\"demo-edr-$RUN_ID-001\",\"source_key\":\"$EDR_SOURCE_KEY\"},
      {\"event_id\":\"demo-ipros-$RUN_ID-001\",\"source_key\":\"$IPROS_SOURCE_KEY\"}
    ]
  }")"
INCIDENT_ID="$(json_get "$INCIDENT_JSON" id)"

echo "[5/6] SOC candidate/evaluation/rollout"
CANDIDATE_JSON="$(curl -fsS -X POST "$SOC_BASE/api/v1/candidates" \
  -H "X-Admin-Token: $SOC_API_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{
    \"source_product\":\"exkururuxdr\",
    \"source_kind\":\"incident\",
    \"candidate_type\":\"policy_tuning\",
    \"target_scope\":\"workspace\",
    \"target_ref\":\"demo\",
    \"title\":\"block suspicious outbound after process anomaly\",
    \"proposal\":{\"action\":\"block\",\"rule\":\"outbound_anomaly_after_proc\"},
    \"evidence\":{\"incident_key\":\"$INCIDENT_KEY\",\"incident_id\":$INCIDENT_ID},
    \"reason_summary\":\"cross-product suspicious chain\",
    \"expected_benefit\":{\"defense_delta\":0.2},
    \"risk_level\":\"medium\",
    \"created_by_type\":\"human\",
    \"created_by\":\"demo-script\"
  }")"
CANDIDATE_ID="$(json_get "$CANDIDATE_JSON" candidate_id)"

curl -fsS -X POST "$SOC_BASE/api/v1/candidates/$CANDIDATE_ID/approval" \
  -H "X-Admin-Token: $SOC_API_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"action":"approve","decision_note":"demo approve","reviewer":"soc_admin"}' >/dev/null

curl -fsS -X POST "$SOC_BASE/api/v1/evaluations" \
  -H "X-Admin-Token: $SOC_API_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{
    \"candidate_id\":\"$CANDIDATE_ID\",
    \"evaluation_type\":\"replay\",
    \"baseline_metrics\":{\"attack_defense_rate\":0.95},
    \"candidate_metrics\":{\"attack_defense_rate\":0.98},
    \"diff_metrics\":{\"attack_defense_rate\":0.03},
    \"verdict\":\"pass\",
    \"evaluator_type\":\"human\",
    \"evaluator_name\":\"soc_admin\"
  }" >/dev/null

ROLLOUT_JSON="$(curl -fsS -X POST "$SOC_BASE/api/v1/rollouts" \
  -H "X-Admin-Token: $SOC_API_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{
    \"candidate_id\":\"$CANDIDATE_ID\",
    \"rollout_scope\":{\"workspace\":\"demo\",\"stage\":\"canary\"},
    \"rollback_point\":\"demo-rollback-$RUN_ID\"
  }")"
ROLLOUT_ID="$(json_get "$ROLLOUT_JSON" rollout_id)"

echo "[6/6] done"
echo "incident_key=$INCIDENT_KEY"
echo "incident_id=$INCIDENT_ID"
echo "candidate_id=$CANDIDATE_ID"
echo "rollout_id=$ROLLOUT_ID"
