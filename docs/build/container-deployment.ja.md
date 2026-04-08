# Container Deployment

この手順は、次のような container 前提の配置向けです。

- ECS
- AKS
- GKE
- Azure Container Apps
- 一般的な Docker / Kubernetes 環境

## Build の選択肢

実務上は 2 通りです。

### 1. repository の Dockerfile をそのまま使う

```bash
docker build -f coraza/Dockerfile -t tukuyomi:local .
```

この方法では、管理UIを build して Go バイナリへ埋め込んだ image を作れます。

### 2. 設定と rules まで baked-in した deployment Dockerfile を使う

sample:

- [Dockerfile.example](Dockerfile.example)

build:

```bash
docker build -f docs/build/Dockerfile.example -t tukuyomi:deploy .
```

`/app/conf` と `/app/rules` を含んだ self-contained image にしたい場合はこちらが向いています。

repo 上で手順どおりの smoke を再実行したい場合は、次を使います。

```bash
make container-deployment-smoke
```

## 実行時 path

最低限必要な path:

- `/app/conf`
- `/app/rules`
- `/app/logs`

設定を image に焼かない場合は、これらを platform 側で mount してください。

補足:

- `conf/log-output.json` は無ければ初回起動時に生成されます
- `conf/crs-disabled.conf` は空で開始できます
- `Dockerfile.example` には `/app/conf` と `/app/rules` 前提の file path env が設定済みです

## 最低限見直す環境変数

- `WAF_APP_URL`
- `WAF_RULES_FILE`
- `WAF_BYPASS_FILE`
- `WAF_API_KEY_PRIMARY`
- `WAF_API_KEY_SECONDARY`
- `WAF_ADMIN_SESSION_SECRET`
- `WAF_ADMIN_SESSION_TTL_SEC`
- `WAF_UI_BASEPATH`
- `WAF_API_BASEPATH`
- `WAF_ADMIN_EXTERNAL_MODE`
- `WAF_ADMIN_TRUSTED_CIDRS`
- `WAF_TRUSTED_PROXY_CIDRS`
- `WAF_COUNTRY_HEADER_NAMES`
- `WAF_FORWARD_INTERNAL_RESPONSE_HEADERS`
- `WAF_LOG_OUTPUT_FILE`
- `WAF_CRS_ENABLE`
- `WAF_CRS_SETUP_FILE`
- `WAF_CRS_RULES_DIR`
- `WAF_CRS_DISABLED_FILE`
- `WAF_STORAGE_BACKEND`
- `WAF_DB_DRIVER`
- `WAF_DB_DSN` または `WAF_DB_PATH`

## 典型的な通信経路

cloud では通常:

`client -> ALB/nginx/ingress -> tukuyomi container -> app container/service`

です。前段がある場合は、`WAF_TRUSTED_PROXY_CIDRS` をその前段だけに限定してください。
`WAF_TRUSTED_PROXY_CIDRS` は forwarded header の信頼境界だけを決めます。admin reachability は別です:

- `[web]` の既定 posture は `WAF_ADMIN_EXTERNAL_MODE=api_only_external`
- `WAF_ADMIN_TRUSTED_CIDRS` に入った trusted/private な直結 peer は管理UI/APIの両方へ到達可能
- untrusted external は認証付き管理APIだけへ到達可能
- remote admin API が不要なら `WAF_ADMIN_EXTERNAL_MODE=deny_external` を使う
- front proxy / LB が private ではない source IP で tukuyomi に接続する場合は、その直結 peer range を `WAF_ADMIN_TRUSTED_CIDRS` へ設定して埋め込み管理UIを通してください

## Secret Handling

- `WAF_API_KEY_PRIMARY`, `WAF_API_KEY_SECONDARY`, `WAF_ADMIN_SESSION_SECRET`, `WAF_DB_DSN`, `WAF_FP_TUNER_API_KEY` は platform 側の secret store や runtime env 注入で渡してください
- 埋め込み管理UIに build-time admin secret は不要です
- browser user は 1 回 sign in すると same-origin session cookie を受け取ります
- CLI / 自動化は従来どおり `X-API-Key` を使えます

## Notes

- 埋め込み管理UIは image build 時に生成され、runtime では build しません
- `make container-deployment-smoke` は unauthenticated session 状態、login/logout、invalid session 拒否、CSRF 強制まで検証します
- runtime で policy file を変更したい場合は、`/app/conf` と `/app/rules` を mount してください
- 複数ノード運用では `db + mysql` を推奨します
