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

- [Dockerfile.example](/home/ky491/git/vril/tukuyomi/docs/build/Dockerfile.example)

build:

```bash
docker build -f docs/build/Dockerfile.example -t tukuyomi:deploy .
```

`/app/conf` と `/app/rules` を含んだ self-contained image にしたい場合はこちらが向いています。

## 実行時 path

最低限必要な path:

- `/app/conf`
- `/app/rules`
- `/app/logs`

設定を image に焼かない場合は、これらを platform 側で mount してください。

補足:

- `conf/log-output.json` は無ければ初回起動時に生成されます
- `conf/crs-disabled.conf` は空で開始できます

## 最低限見直す環境変数

- `WAF_APP_URL`
- `WAF_API_KEY_PRIMARY`
- `WAF_UI_BASEPATH`
- `WAF_API_BASEPATH`
- `WAF_TRUSTED_PROXY_CIDRS`
- `WAF_COUNTRY_HEADER_NAMES`
- `WAF_FORWARD_INTERNAL_RESPONSE_HEADERS`
- `WAF_LOG_OUTPUT_FILE`
- `WAF_STORAGE_BACKEND`
- `WAF_DB_DRIVER`
- `WAF_DB_DSN` または `WAF_DB_PATH`

## 典型的な通信経路

cloud では通常:

`client -> ALB/nginx/ingress -> tukuyomi container -> app container/service`

です。前段がある場合は、`WAF_TRUSTED_PROXY_CIDRS` をその前段だけに限定してください。

## Notes

- 埋め込み管理UIは image build 時に生成され、runtime では build しません
- `VITE_API_KEY` は管理UI向けの build-time 値です
- runtime で policy file を変更したい場合は、`/app/conf` と `/app/rules` を mount してください
- 複数ノード運用では `db + mysql` を推奨します
