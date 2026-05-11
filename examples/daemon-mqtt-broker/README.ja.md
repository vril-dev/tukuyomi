[English](README.md) | [日本語](README.ja.md)

# Daemon Runtime App: MQTT Broker Skeleton

この example は、**daemon** Runtime App 用の最小ソースツリーです。IoT Gateway
で、ベンダー製 MQTT broker や broker 相当の制御 daemon を Center から配備し、
Gateway 側で監視する構成を想定しています。

同梱のスクリプトはプレースホルダーです。MQTT broker は実装しておらず、
ネットワークポートも開きません。実運用では `app/bin/sample-broker-daemon` を
broker バイナリ、または起動用ラッパーに置き換えてください。
ログには `listen=127.0.0.1:1883` が出ますが、これはサンプル設定値の表示だけ
です。このスクリプトはそのアドレスで bind / listen しません。

## Runtime Apps の設定値

Runtime App を次の内容で作成します。

| Field | Value |
| --- | --- |
| Mode | `daemon` |
| Name | `mqtt-broker` |
| App Root | `./data/runtime-sites/mqtt-broker/app` |
| Command | `bin/sample-broker-daemon` |
| Args | `config/broker.env.example` |
| Restart policy | `on-failure` |
| Persistent paths | `state` |

daemon Runtime App は HTTP リスナー、generated proxy target、route を自動生成
しません。daemon が HTTP の管理エンドポイントを持つ場合は、明示的な upstream
と route で公開してください。MQTT の待ち受けポートを持つ場合は、MQTT Traffic
Control を導入するまで、専用のローカルネットワークまたは VLAN 側に閉じて運用
してください。

## Gateway へ配置する

```bash
mkdir -p data/runtime-sites/mqtt-broker
cp -a examples/daemon-mqtt-broker/app data/runtime-sites/mqtt-broker/
chmod +x data/runtime-sites/mqtt-broker/app/bin/sample-broker-daemon
```

Runtime App を保存したあと、Center の **Runtime App Deploy** から current
source を採用します。以後アップロードする package は、archive root に `app/`
ディレクトリを含めます。

## Center へアップロードする package を作る

```bash
cd examples/daemon-mqtt-broker
zip -r mqtt-broker-package.zip app
```

Center の Runtime App Deploy 画面で、`mqtt-broker` app に対して zip をアップ
ロードします。Gateway 側では次の場所へ配備されます。

```text
data/app-deployments/mqtt-broker/current/app
```

`state` persistent path は次の安定ディレクトリへの symlink として配置されます。

```text
data/app-deployments/mqtt-broker/persistent/state
```
