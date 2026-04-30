[English](device-auth-enrollment.md) | [日本語](device-auth-enrollment.ja.md)

# IoT / Edge Device Enrollment

This document covers the current Tukuyomi Gateway to Tukuyomi Center device
enrollment workflow.

The current implementation registers a Gateway-owned device identity with
Center approval. It does not mean every Web/VPS deployment should enable IoT /
Edge mode; leave it off unless the deployment needs edge/device-oriented
controls.

## Roles

- Center issues enrollment tokens and approves or rejects pending device
  enrollment requests.
- Gateway owns the local device identity, private key, and enrollment request.
- The enrollment token is a temporary registration secret. Gateway sends it once
  to Center and does not store it locally.

## Operator Flow

1. Start or open Center.
2. Open `Device Approvals`.
3. Create an enrollment token with `Create enrollment token`.
4. Copy the token immediately. Center does not show the full token again.
5. Open Gateway `Options`.
6. Enable `IoT / Edge Mode`.
7. Save the mode and restart Gateway so the running process loads
   `edge.enabled=true`.
8. In `Center Enrollment`, enter the Center URL and enrollment token.
9. Leave `Device ID` empty unless you need a stable operator-chosen ID.
10. Keep `Key ID` as `default` unless you intentionally manage multiple keys.
11. Submit `Request Center approval`.
12. Return to Center `Device Approvals`.
13. Approve or reject the pending device.

After the request is sent, Gateway status moves to `pending` until Center
approval is completed.

When `edge.enabled=true` and device approval is required, Gateway public proxy
traffic is locked unless the local Center status is `approved`. A pending,
rejected, revoked, product-changed, failed, unknown, or missing identity returns
`503` on the proxy request path. Normal Web/VPS deployments keep
`IoT / Edge Mode` off and are not affected.

After approving a device in Center, Gateway refreshes the local cached status by
polling Center. The default interval is 30 seconds and is controlled by
`edge.device_auth.status_refresh_interval_sec`; set it to `0` only when you want
manual refresh behavior. You can also run `Check Center status` from Gateway
`Options > Center Enrollment` to refresh immediately. This same signed status
path is used later for approval revocation and product ID/token switching:
Center owns the current authorization state, and Gateway locks the proxy for any
non-`approved` status after it refreshes that state.

## Preview URLs

For fleet preview, keep both preview databases if you need to preserve Gateway
settings and Center tokens/approvals across restarts:

```bash
GATEWAY_PREVIEW_PERSIST=1 CENTER_PREVIEW_PERSIST=1 make fleet-preview-up
```

When Gateway runs inside the preview container, do not use
`http://localhost:9092` as the Center URL. Inside the Gateway container,
`localhost` points back to Gateway itself.

Use the host-reachable Center URL instead:

```text
http://host.docker.internal:9092
```

If the Docker runtime does not provide `host.docker.internal`, configure the
preview/container host-gateway mapping or use a reachable Center address.

## Center URL Rules

Gateway accepts an HTTP or HTTPS Center URL with no userinfo credentials. The
path must be empty, `/`, or `/v1/enroll`; Gateway normalizes the enrollment
request to Center `/v1/enroll`.

Use HTTPS outside local preview or other trusted test networks.

## Identity and Fingerprint

Gateway generates an Ed25519 key pair when no local identity exists. The private
key is stored in the Gateway DB. The public key is sent to Center in the
enrollment request.

`Public key fingerprint` is:

```text
Ed25519 public key
 -> x509 PKIX DER
 -> SHA-256
 -> lowercase hex
```

It is the SHA-256 hash of the PKIX DER public key bytes, not the raw Ed25519
32-byte public key.

## Local Identity Constraints

Gateway currently owns one local device identity. If a local identity already
exists, a later enrollment request must use the same `Device ID` and `Key ID`;
otherwise Gateway rejects the request to avoid silently replacing the device
private key.

## Token Handling

- Treat enrollment tokens as secrets.
- Prefer short-lived or low-use tokens for factory or rollout batches.
- Revoke tokens after the rollout window closes.
- Revoking an enrollment token also revokes registered devices that were
  approved through that token. Center keeps those devices as audit records with
  status `revoked`; Gateway locks proxy traffic after the next `Check Center
  status`. Pending enrollment requests from that token are rejected at the same
  time, so they cannot be approved later.
- Gateway stores the Center URL and local identity state, but not the enrollment
  token.
- Enrollment tokens are registration-time proof only. Runtime authorization is
  the Center device status cached by Gateway.

## Status Polling

Gateway never calls Center on each proxied request. The request path checks the
local cached device status only. The background poller updates that cache on a
bounded interval when all of the following are true:

- `edge.enabled=true`
- `edge.device_auth.enabled=true`
- `edge.device_auth.status_refresh_interval_sec > 0`
- a local device identity exists
- the local identity has a Center URL

The poller performs one immediate pass at startup and is woken immediately after
a successful enrollment request, so a newly enrolled Gateway does not wait for
the first interval before its initial Center status check.

Use a short interval for interactive approval/revocation workflows. Use a longer
interval if many Gateways report to one Center.

## Troubleshooting

- `connect: connection refused` with `localhost:9092`: Gateway is trying to
  reach itself inside the container. Use `host.docker.internal:9092` or another
  reachable Center address.
- `edge device authentication is not enabled in the running process`: save
  `IoT / Edge Mode`, then restart Gateway.
- `enrollment token is required`: paste a Center-created token into Gateway
  `Center Enrollment`.
- `invalid enrollment token`: the token is wrong, revoked, expired, exhausted,
  or belongs to a different Center database.
- `local device identity already exists with a different device_id/key_id`: use
  the existing local identity values or reset the local Gateway identity state
  intentionally.

There is no `make` command for enrollment yet. The current supported operator
entrypoint is Gateway `Options > Center Enrollment` or the admin API behind that
screen.
