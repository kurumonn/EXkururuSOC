# exkururuSOC

[英語版 README](README.en.md)  
[4製品デモ概要](README.4stack.md)

EXkururuSOC は、EXkururu 系セキュリティ製品をまとめて運用するための軽量オーケストレーション層です。  
この公開リポジトリでは、ポリシー運用、候補管理、評価、ロールアウト、連携向け API といった制御プレーンの表面を公開しています。

この README は公開配布用の案内です。内部運用の秘密情報や評価ノウハウは含めません。

## 公開範囲

- 軽量 FastAPI 制御プレーン
- Policy / Candidate / Evaluation / Rollout / Runbook / Feedback API
- 単体ローカル起動
- Source heartbeat と統合管理の受け口

本番チューニング、スコアリング閾値、運用上のフィードバック判断ロジックは公開版から除外しています。

## 公開しないもの

- 本番の admin token、source token、証明書、接続先 URL
- 内部 runbook、private な運用手順、復旧手順の詳細
- スコアリング閾値、評価基準、ロールアウト判定の細部
- 顧客データ、実運用ログ、調整ノート、再現用の秘密コーパス
- private な外部連携先や検証用の固定値

## 役割

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

## クイックスタート

```bash
cd /path/to/exkururuSOC
python3 -m venv .venv
./.venv/bin/pip install -e ".[dev]"
./.venv/bin/python scripts/migrate.py
./.venv/bin/pytest -q
./.venv/bin/uvicorn exkururusoc.api:app --host 127.0.0.1 --port 8820
```

Docker で起動する場合は `docker-compose.yaml` が一番簡単です。

```bash
cd /path/to/exkururuSOC
cp .env.example .env
docker compose -f docker-compose.yaml up --build
```

起動後は `http://127.0.0.1:8820` を開きます。

## 公開している環境変数

- `SOC_API_ADMIN_TOKEN`
- `SOC_ENV`
- `SOC_LOG_LEVEL`
- `SOC_DB_PATH`
- `SOC_ALLOW_INSECURE_NO_AUTH`
- `SOC_SOURCE_REQUIRE_NONCE` (既定: `1`)
- `SOC_SOURCE_SIGNATURE_MAX_SKEW_SEC` (既定: `300`)
- `SOC_SOURCE_REPLAY_TTL_SEC` (既定: `310`)
- `SOC_REPLAY_BACKEND` (`auto` / `redis` / `memory`, 既定: `auto`)
- `SOC_REDIS_URL` (`redis://...` を指定した場合に共有 replay cache を使用)
- `SOC_REPLAY_FALLBACK_TO_MEMORY` (既定: `1`)
- `SOC_REPLAY_CACHE_MAX_ITEMS` (既定: `200000`)

## 主な API

- `GET /healthz`
- `GET /api/v1/command-center`
- `GET /api/v1/policies`
- `GET /api/v1/candidates`
- `POST /api/v1/evaluations`
- `POST /api/v1/rollouts`
- `GET /api/v1/runbooks`
- `POST /api/v1/feedback`

## セキュリティ方針

- 秘密情報や本番 source 参照はリポジトリに含めない
- 公開設定は開発用の最小値として扱う
- 共用環境では TLS 終端と認証付きリバースプロキシの背後に配置する

`auth_type=signed_required` の source heartbeat では
`X-Source-Timestamp / X-Source-Nonce / X-Source-Signature`
を要求し、短期 replay を拒否します。署名対象は送信された raw body そのものです。
`SOC_REPLAY_BACKEND=redis` と `SOC_REDIS_URL` を設定すると、replay 判定は Redis 共有キャッシュを使います。
Redis 障害時は `SOC_REPLAY_FALLBACK_TO_MEMORY=1` の場合にメモリ退避します。
