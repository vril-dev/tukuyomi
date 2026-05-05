# Chapter 17. Remote SSH

This chapter covers **Remote SSH**, the Center-managed maintenance path for
reaching an approved Gateway without opening an inbound SSH port on the
Gateway. It builds on Chapter 16: Remote SSH is a per-device capability, so the
Gateway must be registered with Center and the device must be approved first.

Remote SSH is intended for short operational interventions: checking logs,
inspecting local state, restarting a local service, or collecting evidence
during an incident. It is not a general remote job runner, file-transfer
system, or permanent shell service.

## 17.1 When to use it

Use Remote SSH when all of the following are true:

- The Gateway is managed by Center.
- Direct inbound access to the Gateway is unavailable or intentionally closed.
- An operator needs a short-lived interactive maintenance session.
- The action is authorized by the device policy and has a recorded reason.

Do not enable it as a default convenience feature on every deployment. Remote
SSH is powerful because it reaches a shell on the Gateway. Keep it disabled
unless the operational model needs it.

## 17.2 Security model

The design keeps authority split across Center, Gateway, and the operator
session.

| Boundary | Control |
|---|---|
| Center | Remote SSH service must be enabled. The device must be approved. The per-device policy must allow Remote SSH. |
| Gateway | Remote SSH must be enabled locally. The pending session signature must verify against the pinned Center signing key. |
| Operator | A reason and TTL are required. Web Terminal and CLI sessions use one-time operator keys. |
| Session | TTL, idle timeout, per-device session limit, audit fields, and explicit termination bound the session lifetime. |

Gateway connects **outbound** to Center. The Gateway does not expose an inbound
SSH listener for Center or the operator.

The embedded Gateway SSH server rejects port forwarding, SFTP, SCP, agent
forwarding, and arbitrary SSH subsystems. If the Gateway process runs as root,
the embedded server refuses to start a shell unless `run_as_user` is set.

## 17.3 Center and Gateway configuration

Remote SSH is disabled by default. Enable the Center service first:

```json
{
  "remote_ssh": {
    "center": {
      "enabled": true,
      "max_ttl_sec": 900,
      "idle_timeout_sec": 300,
      "max_sessions_total": 16,
      "max_sessions_per_device": 1
    }
  }
}
```

Each Gateway must also trust the Center signing key:

```json
{
  "remote_ssh": {
    "gateway": {
      "enabled": true,
      "center_signing_public_key": "ed25519:REPLACE_WITH_CENTER_PUBLIC_KEY",
      "center_tls_ca_bundle_file": "conf/center-ca.pem",
      "center_tls_server_name": "center.example.local",
      "embedded_server": {
        "enabled": true,
        "shell": "/bin/sh",
        "working_dir": "/",
        "run_as_user": "tukuyomi"
      }
    }
  }
}
```

For Center-protected installs and previews, the bootstrap path writes the same
trust settings into the Gateway config. For manual deployments, fetch the
Center signing public key from:

```text
/center-api/remote-ssh/signing-key
```

## 17.4 Center UI workflow

Open `Device Approvals`, choose the Gateway, and select `Manage`. The selected
device menu includes `Remote SSH`.

![Center Remote SSH screen](../../images/ui-samples/28-center-remote-ssh.png)

The page has three operator areas:

- **Policy**: enable or disable Remote SSH for this Gateway, set maximum TTL,
  set the run-as user, and require a reason.
- **Web terminal**: open an interactive browser terminal through the Remote SSH
  relay.
- **CLI handoff**: copy a `tukuyomi remote-ssh` command for operators who need
  local SSH tooling.

For Web Terminal:

1. Confirm the Center service is ON.
2. Enable the device policy.
3. Enter a reason.
4. Choose TTL seconds.
5. Set `Scrollback rows` if the default browser-side terminal history is too
   small or too large.
6. Click `Open terminal`.

Center creates a pending session immediately. The browser WebSocket opens, then
waits for the Gateway to pick up the session during the next signed status
poll. With a 30 second polling interval, a wait near one polling interval can
be normal. A wait far beyond that should be treated as a fault.

## 17.5 CLI handoff

The CLI path is still supported:

```bash
export TUKUYOMI_ADMIN_TOKEN="$TOKEN"
tukuyomi remote-ssh \
  --center "https://center.example.com" \
  --center-ca-bundle "conf/center-ca.pem" \
  --center-server-name "center.example.local" \
  --device "$DEVICE" \
  --reason "maintenance"
```

The command prints the exact local `ssh` command and keeps the relay open while
the SSH session is active. The CLI path is useful for emergency workflows,
automation, and environments where browser terminals are not appropriate.

## 17.6 Session history and termination

The Sessions table shows recent Remote SSH sessions for the selected Gateway.
For pending or active sessions, the status cell includes a termination control.
Terminating a session closes any paired Web Terminal or CLI relay and releases
the device session limit.

The Web Terminal `Scrollback rows` value is only browser display history. It is
not a server-side recording. If a deployment requires command recording or
full terminal capture, design that as a separate audit feature instead of
assuming scrollback is evidence.

## 17.7 Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `Open terminal` waits for a while before connecting | Normal until the Gateway's next Center status poll. Confirm the polling interval and `Last seen` time. |
| Terminal never connects | Check Center service, device approval, device policy, Gateway Remote SSH local config, and Center signing key trust. |
| Session closes unexpectedly | Check TTL, idle timeout, explicit termination, and Gateway logs. |
| CLI refuses HTTP Center URL | HTTPS is required by default. Use HTTP only for local tests with the explicit insecure flag. |
| Gateway refuses to start shell as root | Set `remote_ssh.gateway.embedded_server.run_as_user`. |

## 17.8 Recap

- Remote SSH provides short-lived maintenance access without inbound Gateway
  SSH exposure.
- Web Terminal is the normal Center UI path; CLI handoff remains for advanced
  and emergency workflows.
- Center policy, Gateway local config, one-time keys, TTL, idle timeout, and
  audit fields bound the session.
- Browser scrollback is display history, not an audit recording.

## 17.9 Bridge to the next chapter

Part VI ends here. Part VII covers performance and regression validation.
Chapter 18 explains the benchmark commands, smoke-test matrix, release-binary
smoke, and the confidence ladder used before release.
