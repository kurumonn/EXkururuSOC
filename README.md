# exkururuSOC

[英語版 README](README.en.md)  
[4製品デモ概要](README.4stack.md)

EXkururuSOC は、EXkururu 系セキュリティ製品をまとめて運用するための軽量オーケストレーション層です。  
この公開リポジトリでは、ポリシー運用、候補管理、評価、ロールアウト、連携向け API といった制御プレーンの表面を公開しています。

## 公開範囲

- 軽量 FastAPI 制御プレーン
- Policy / Candidate / Evaluation / Rollout / Runbook / Feedback API
- 単体ローカル起動
- Source heartbeat と統合管理の受け口

本番チューニング、スコアリング閾値、運用上のフィードバック判断ロジックは公開版から除外しています。

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
./.venv/bin/pip install -e .
PYTHONPATH=src ./.venv/bin/python scripts/migrate.py
./.venv/bin/uvicorn exkururusoc.api:app --host 127.0.0.1 --port 8820
```

## 公開している環境変数

- `SOC_API_ADMIN_TOKEN`
- `SOC_ENV`
- `SOC_LOG_LEVEL`
- `SOC_DB_PATH`
- `SOC_ALLOW_INSECURE_NO_AUTH`

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
