# Chapter 15. HTTP/3 and TLS

Chapter 14 framed the current listener-topology decision. This chapter
covers **what TLS and HTTP/3 do on top of that single listener**:

1. Enabling built-in TLS termination and the available options.
2. Site-managed ACME (Let's Encrypt automatic certificate refresh).
3. Built-in HTTP/3 and `Alt-Svc` behavior.
4. What the HTTP/3 public-entry smoke checks.

## 15.1 Built-in TLS termination

tukuyomi has **built-in TLS termination**. You can use `tukuyomi`
itself as a direct HTTPS entrypoint without staging nginx or an ALB
in front.

Configure TLS in the `server` block of DB `app_config`:

```json
{
  "server": {
    "listen_addr": ":9443",
    "http3": {
      "enabled": true,
      "alt_svc_max_age_sec": 86400
    },
    "tls": {
      "enabled": true,
      "cert_file": "/etc/tukuyomi/tls/fullchain.pem",
      "key_file":  "/etc/tukuyomi/tls/privkey.pem",
      "min_version": "tls1.2",
      "redirect_http": true,
      "http_redirect_addr": ":9080"
    }
  }
}
```

Key points:

- `server.tls.enabled=false` is the **default**.
- `server.http3.enabled=true` requires built-in TLS.
- HTTP/3 uses **the same numeric port as `server.listen_addr` over
  UDP**.
- `server.tls.redirect_http=true` adds a plain HTTP listener on
  `http_redirect_addr`.
- ACME auto TLS is selected per-site with `tls.mode=acme`. The ACME
  account key, challenge tokens, and certificate cache live under
  the **`acme/` namespace of `persistent_storage`**.
- Because ACME HTTP-01 is used, **port 80 must reach
  `server.tls.http_redirect_addr`**.
- Let's Encrypt `staging` / `production` is selected per-site under
  the ACME environment.
- `paths.site_config_file` defaults to `conf/sites.json`. In the
  DB-backed runtime this is **a seed / export path for an empty DB**,
  not the live source of truth (Chapter 13).

## 15.2 Inbound timeout boundary

This is loosely related to TLS, but if you publish HTTPS / HTTP/3 as
a direct entrypoint you should understand the **inbound timeout
boundary**:

- The public HTTP/1.1 data-plane listener is handled by the Tukuyomi
  native HTTP/1.1 server. The admin listener, the HTTP redirect
  listener, and the HTTP/3 helper remain separate control / edge
  helpers.
- `server.read_header_timeout_sec` covers the **request line and
  headers only**.
- `server.read_timeout_sec` is the inbound read budget for **the
  request line + headers + body in total**.
- `server.write_timeout_sec` is the **upper bound on response
  write**. A slow client does not hold a data-plane goroutine open
  forever; the connection is closed.
- `server.idle_timeout_sec` is the **upper bound on keep-alive idle
  between requests**.
- `server.graceful_shutdown_timeout_sec` is the upper bound on
  draining live connections during deploy / reload. **After the
  budget, force-close.**
- The TLS public listener **advertises HTTP/1.1** on this native
  server path. HTTP/3 is handled on a **dedicated HTTP/3 listener**
  even when enabled.

## 15.3 Site-managed ACME

Site-managed ACME picks **`tls.mode=acme`** per-site on the `Sites`
screen. `production` and `staging` choose Let's Encrypt's production
or staging CA, and the account email is optional.

![Sites screen](../../images/ui-samples/16-sites.png)

When you use ACME:

- Because HTTP-01 challenge is used, **port 80 must reach
  `server.tls.http_redirect_addr`**.
- The certificate cache, ACME account key, and challenge tokens are
  stored under the **`acme/` namespace of `persistent_storage`**.
- For single-node VPS / on-prem, **back up
  `persistent_storage.local.base_dir`** (default `data/persistent`).
- For replicated or node-replacement scenarios, use **the S3 backend
  or a shared mount**. Azure Blob / GCS are fail-closed until a
  provider adapter ships.

This is the persistent byte storage discussion from Chapter 3 §3.5
revisited, this time from the angle of "where does the ACME
certificate live?".

## 15.4 Built-in HTTP/3

A typical HTTP/3-enabled configuration:

```json
{
  "server": {
    "listen_addr": ":443",
    "http3": {
      "enabled": true,
      "alt_svc_max_age_sec": 86400
    },
    "tls": {
      "enabled": true,
      "cert_file": "/etc/tukuyomi/tls/fullchain.pem",
      "key_file":  "/etc/tukuyomi/tls/privkey.pem",
      "redirect_http": true,
      "http_redirect_addr": ":80"
    }
  }
}
```

Behavioral points:

- HTTP/3 uses **the same numeric port as `listen_addr` over UDP**.
  For `:443`, that means **opening both TCP/443 and UDP/443**.
- The TLS public listener handles HTTP/2 / HTTP/1.1; HTTP/3 is
  served on a **dedicated listener**.
- HTTPS responses include `Alt-Svc`. `alt_svc_max_age_sec` controls
  the advertise TTL.
- HTTP/3 **does not guarantee QUIC connection continuity across
  process replacement** (Chapter 4 §4.4). Client reconnects can
  occur during task / pod swap.

When enabling built-in HTTP/3 on a container deployment, **open both
TCP and UDP** on the listener port (Chapter 4 §4.11).

## 15.5 HTTP/3 public-entry smoke

Because HTTP/3 is sensitive to environment, tukuyomi provides a
**dedicated smoke command**:

```bash
make http3-public-entry-smoke
```

### 15.5.1 What it checks

The smoke spins up a temporary local runtime with:

- **The built binary**
- **Built-in TLS enabled**
- **Built-in HTTP/3 enabled**
- A temporary self-signed certificate for `127.0.0.1` and `localhost`
- A local echo upstream for routed traffic

It verifies:

- **The HTTPS listener is healthy.**
- **The HTTPS response carries `Alt-Svc`.**
- Routed proxy traffic flows through the HTTPS entry.
- **`/tukuyomi-api/status` returns
  `server_http3_enabled=true` and `server_http3_advertised=true`.**
- **An actual HTTP/3 request over UDP succeeds** against the live
  runtime.

### 15.5.2 Why it is a dedicated command

This smoke is **deliberately not** part of `make smoke` /
`make deployment-smoke` / `make ci-local`, because it depends on:

- **TLS runtime startup**
- **UDP availability on the local host**
- **A temporary self-signed certificate**
- **A Go-based HTTP/3 probe**

It is valuable for release readiness and operator validation, but it
has too much environmental dependency to live in the fast smoke
suite.

### 15.5.3 Prerequisites

- Go toolchain
- Docker is **not** required.
- `curl`, `jq`, `python3`, `rsync`, `install`
- Local UDP loopback is available.

### 15.5.4 Recommended timing

Run it after any of:

- Changes under `server.http3.*`.
- Changes to built-in TLS listener behavior.
- Changes to how `Alt-Svc` is handled.
- Startup-time changes that could affect the HTTPS / HTTP/3 listener
  pair.

It is also a good fit before announcing **`tukuyomi` as a direct
HTTPS / HTTP/3 entrypoint**. Smoke usually passes in a setup with a
fronting LB; for direct exposure it pays to run this once.

## 15.6 Recap

- Enable built-in TLS with `server.tls.enabled=true`. TLS is required
  for `http3.enabled=true`. HTTP/3 uses **the same numeric port over
  UDP**.
- ACME auto TLS is per-site via `tls.mode=acme`, **port 80 forwarding
  is required** for HTTP-01, certificate cache lives under the
  `acme/` namespace of `persistent_storage`.
- Inbound timeouts are bounded by **five settings**:
  `read_header_timeout_sec` / `read_timeout_sec` /
  `write_timeout_sec` / `idle_timeout_sec` /
  `graceful_shutdown_timeout_sec`.
- For direct HTTP/3 exposure, **open both TCP and UDP**.
- Validate HTTP/3 via the dedicated **`make http3-public-entry-smoke`**.
  Do not mix it into the fast smoke suite.

## 15.7 Bridge to the next chapter

Part VI has one more chapter. Chapter 16 covers an optional feature
that is OFF by default in normal Web / VPS deployments — **IoT / Edge
device enrollment (`device-auth-enrollment`)**. It is the procedure
for deployments that require a device identity approved by Tukuyomi
Center.
