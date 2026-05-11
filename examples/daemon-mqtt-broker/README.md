[English](README.md) | [日本語](README.ja.md)

# Daemon Runtime App: MQTT Broker Skeleton

This example is a minimal source tree for a **daemon** Runtime App. It is meant
for IoT gateway deployments where a vendor MQTT broker or broker-like control
daemon is deployed by Center, then supervised by Gateway.

The included script is only a placeholder daemon. It does not implement MQTT
and does not open a network port. Replace `app/bin/sample-broker-daemon` with
your broker binary or startup wrapper before using this layout for real traffic.

## Runtime Apps fields

Create a Runtime App with these fields:

| Field | Value |
| --- | --- |
| Mode | `daemon` |
| Name | `mqtt-broker` |
| App Root | `./data/runtime-sites/mqtt-broker/app` |
| Command | `bin/sample-broker-daemon` |
| Args | `config/broker.env.example` |
| Restart policy | `on-failure` |
| Persistent paths | `state` |

Daemon Runtime Apps do not create HTTP listeners, generated proxy targets, or
routes. If your daemon exposes an HTTP control endpoint, publish it through an
explicit upstream and route. If it exposes MQTT, keep that listener on a
dedicated local/VLAN segment until MQTT Traffic Control is introduced.

## Stage locally

```bash
mkdir -p data/runtime-sites/mqtt-broker
cp -a examples/daemon-mqtt-broker/app data/runtime-sites/mqtt-broker/
chmod +x data/runtime-sites/mqtt-broker/app/bin/sample-broker-daemon
```

After saving the Runtime App, use Center **Runtime App Deploy** to adopt the
current source. Future packages should contain the `app/` directory at the
archive root.

## Package for Center upload

```bash
cd examples/daemon-mqtt-broker
zip -r mqtt-broker-package.zip app
```

Upload the zip from Center Runtime App Deploy for the `mqtt-broker` app. The
Gateway will deploy it under:

```text
data/app-deployments/mqtt-broker/current/app
```

The `state` persistent path is mounted as a symlink to:

```text
data/app-deployments/mqtt-broker/persistent/state
```
