# Chapter 18. Benchmark and the regression matrix

Part VII begins. This chapter consolidates the **benchmark and
regression-check frameworks** tukuyomi ships with:

- The roles and inputs of `make bench-proxy` /
  `make bench-waf` / `make bench-full`.
- The **regression matrix** of the `make smoke` family — what each
  command guarantees.
- The **confidence ladder** that ties commands to "how much
  reassurance you actually need".
- `make release-binary-smoke` for verifying the public release
  tarball.

This is the chapter that lives behind every "benchmark with `make
bench`" instruction earlier in the book.

## 18.1 Benchmark — what these commands are for

tukuyomi's benchmarks exist to provide a **controlled local baseline
for comparing proxy / WAF behavior**.

| Command | Purpose | Output |
|---|---|---|
| `make bench` | Backwards-compatible alias for `make bench-proxy` | Proxy tuning artifacts |
| `make bench-proxy` | Compare proxy transport presets | `proxy-benchmark-summary.*` |
| `make bench-waf` | Compare WAF allow / block inspection scenarios | `waf-benchmark-summary.*` |
| `make bench-full` | Run proxy and WAF benchmarks in sequence | Both sets of artifacts |

This is **not** a faithful reproduction of production capacity. It is
a **controlled local baseline**. Even so, it is enough for:

- Comparing presets on the same host.
- Comparing artifacts across branches at identical settings.
- Pre-release confirmation that no large regression has slipped in.

### 18.1.1 What `make bench-proxy` does

`make bench` and `make bench-proxy` wrap
`./scripts/benchmark_proxy_tuning.sh`, which runs:

- **A temporary benchmark-only config / SQLite DB** (default).
- The local `tukuyomi` compose stack.
- **A concurrency-capable Go upstream mock**
  (`scripts/benchmark_upstream.go`), launched temporarily.
- Applies the proxy preset via `/tukuyomi-api/proxy-rules`.
- Unless `BENCH_PROXY_MODE=proxy-only` is set, measures **the normal
  proxy listener path including WAF inspection**.
- A warm-up.
- Load with **ApacheBench (`ab`)** against the target path.
- **CPU / heap / allocation profiles** when `BENCH_PROFILE=1`.
- On exit, restores proxy rules, rate-limit rules, the temporarily
  disabled request-security guard files, and the temporary
  proxy-only WAF bypass to their original state.

The upstream mock is a **Go HTTP server** rather than Python's
`http.server` so that it does not serialize at high concurrency.

### 18.1.2 What `make bench-waf` does

`make bench-waf` wraps `./scripts/benchmark_waf.sh`. It does similar
preparation as the proxy side, then measures WAF scenarios. The
defaults are:

| Scenario | Expected status | Purpose |
|---|---:|---|
| `allow` | `200` | A benign request that should pass WAF inspection. |
| `block-xss` | `403` | An encoded XSS query that CRS should block. |

The script **probes each scenario for the expected status before
measurement**, then runs ApacheBench.

This is **not a replacement for `make gotestwaf`**. **Broad attack
corpora and false-positive regressions remain the responsibility of
GoTestWAF.** This command is for **"throughput / latency on a path
that includes WAF inspection has not regressed"**.

### 18.1.3 When to run

Recommended timing:

- After changes to proxy transport (`force_http2`, buffering,
  timeouts, response compression).
- Before a release where runtime path changes might affect throughput
  or latency.
- When comparing presets on the same machine.

### 18.1.4 Standard commands

A simple check:

```bash
make bench
```

A standard recipe for changes that may affect both proxy transport
and WAF inspection:

```bash
BENCH_REQUESTS=600 \
WARMUP_REQUESTS=100 \
BENCH_CONCURRENCY=1,10,50 \
BENCH_DISABLE_RATE_LIMIT=1 \
make bench-full
```

`BENCH_PROXY_MODE=current` (the default) is **the path closest to
production: proxy + WAF inspection**. Use
`BENCH_PROXY_MODE=proxy-only` only when you want to profile the proxy
hot path on its own.

### 18.1.5 Prerequisites

- Docker and Docker Compose are available.
- `ab` is installed locally.
- `curl`, `jq`, Go are available.
- The host load is **stable enough for comparison**.

For branch comparison, run on **the same host, the same concurrency,
and the same request count**.

### 18.1.6 Major input parameters

| Variable | Default | Meaning |
|---|---|---|
| `BENCH_REQUESTS` | `120` via Makefile, `600` via direct script | Request count per preset / concurrency. Use `>=600` for decision-grade runs. |
| `WARMUP_REQUESTS` | `20` via Makefile, `100` via direct script | Warm-up request count before measurement. |
| `BENCH_CONCURRENCY` | `1,10,50` | Comma-separated list of concurrencies. |
| `BENCH_PATH` | `/bench` | The path requested through `tukuyomi`. |
| `BENCH_TIMEOUT_SEC` | `30` | ApacheBench timeout. |
| `BENCH_DISABLE_RATE_LIMIT` | `1` | Whether to temporarily disable rate-limit rules during measurement. |
| `BENCH_DISABLE_REQUEST_GUARDS` | `1` | Whether to temporarily disable bot-defense / semantic / IP-reputation. |
| `BENCH_ACCESS_LOG_MODE` | `full` | `access_log_mode` for proxy rules. |
| `BENCH_CLIENT_KEEPALIVE` | `1` | When `1`, passes `-k` to ApacheBench. |
| `BENCH_PROXY_MODE` | `current` | `current` includes WAF inspection. `proxy-only` temporarily bypasses WAF inspection on `BENCH_PATH`. |
| `BENCH_PROXY_ENGINE` | `tukuyomi_proxy` | Temporarily rewrites `proxy.engine.mode` in the benchmark config (only `tukuyomi_proxy` is supported). |
| `BENCH_ISOLATED_RUNTIME` | `1` | Use a temporary config / DB under `data/tmp/bench`. |
| `BENCH_PROFILE` | `0` | When `1`, capture pprof CPU / heap / allocation artifacts. |
| `BENCH_MAX_FAIL_RATE_PCT` | unset | Per-row fail gate. |
| `BENCH_MIN_RPS` | unset | Per-row minimum-RPS gate. |
| `WAF_BENCH_SCENARIOS` | `allow,block-xss` | Scenarios `make bench-waf` runs. |

### 18.1.7 Canonical output

The canonical output for the proxy benchmark is two files (plus an
optional profile):

- Markdown summary:
  `data/tmp/reports/proxy/proxy-benchmark-summary.md`
- Machine-readable JSON:
  `data/tmp/reports/proxy/proxy-benchmark-summary.json`
- Optional raw profiles:
  `data/tmp/reports/proxy/proxy-benchmark-*.pprof`

For the WAF benchmark:

- Markdown summary:
  `data/tmp/reports/proxy/waf-benchmark-summary.md`
- Machine-readable JSON:
  `data/tmp/reports/proxy/waf-benchmark-summary.json`

These are the canonical artifacts for **branch comparison**, **release
note summaries**, **tuning discussions**, and **automation that does
not want to parse Markdown**.

### 18.1.8 Hot-path logging and profile capture

The framework's request log is **disabled by default** because it
overlaps the proxy's product access log. Enable
`observability.request_log.enabled=true` only for ad hoc
investigation. **For performance benchmarks, keep it `false`.**

Profile capture is also disabled by default. To capture, pass
`BENCH_PROFILE=1`. The pprof server is **opt-in and binds to loopback
inside the container only**; it is never exposed on the public proxy
port. **Raw `.pprof` files are local-investigation artifacts and are
not committed**.

### 18.1.9 Threshold policy

Thresholds are **opt-in, not mandatory**:

```bash
BENCH_MAX_FAIL_RATE_PCT=0.5 \
BENCH_MIN_RPS=300 \
BENCH_CONCURRENCY=10,50 \
BENCH_DISABLE_RATE_LIMIT=1 \
make bench
```

Rules:

- Use `BENCH_MAX_FAIL_RATE_PCT` to fail on instability.
- For `make bench-waf`, `BENCH_MAX_FAIL_RATE_PCT` gates the
  unexpected-response-family rate in addition to the pre-measurement
  exact-status probe.
- Use `BENCH_MIN_RPS` only against a known local baseline.
- **Do not transplant the same `BENCH_MIN_RPS` to a different
  machine.**
- To include rate limit / request guards, set
  `BENCH_DISABLE_RATE_LIMIT=0` /
  `BENCH_DISABLE_REQUEST_GUARDS=0` and **note that condition in the
  review**.
- Treat single runs at `BENCH_REQUESTS<600` as **smoke data**.
  Decisions need either `BENCH_REQUESTS>=600` or **the median of three
  or more runs at identical settings**.

### 18.1.10 Why benchmarks are not in the regular CI

`make bench` is **not** wired into `ci-local` or the regular GitHub
CI for these reasons:

- High sensitivity to host noise.
- Variability in container startup and local tool versions.
- `ab` is not assumed to be on every developer / runner.
- The script mutates runtime proxy rules and, by default, temporarily
  disables rate-limit and request-security guards.

This is **a performance baseline for humans to read**, not a
deterministic unit test.

### 18.1.11 Current presets

| Preset | Key settings | Use case |
|---|---|---|
| `balanced` | `force_http2=false`, `disable_compression=false`, `buffer_request_body=false`, `flush_interval_ms=0` | General-purpose default |
| `low-latency` | `force_http2=false`, `disable_compression=true`, `buffer_request_body=false`, `flush_interval_ms=0` | Latency-sensitive API / SSE |
| `buffered-guard` | `force_http2=false`, `buffer_request_body=true`, `max_response_buffer_bytes=1048576`, `flush_interval_ms=0` | Emphasizes buffer control and response-size cap |

## 18.2 The regression matrix — what each command guarantees

Where benchmarks are about performance, the `make smoke` family is
about **behavioral correctness**:

| Command | Purpose | When to use |
|---|---|---|
| `make smoke` | Fast admin / routed-proxy regression against the standard compose stack | Daily commits, before config changes |
| `make deployment-smoke` | Reproduces the binary / systemd and sample-container flows from `docs/build` | After touching `docs/build`, packaging, or runtime layout |
| `make release-binary-smoke` | Builds / extracts the public tarball and runs bundle-local Docker smoke | Before publishing binary artifacts |
| `make http3-public-entry-smoke` | Verifies the built-in HTTPS + HTTP/3 listener on a live runtime | After TLS / HTTP/3 listener changes, or before announcing direct H3 ingress |
| `make smoke-extended` | `smoke` + `deployment-smoke` | When both runtime and deployment docs are touched, or before a release |
| `make ci-local` | `check` + `smoke` | A local baseline before opening a PR |
| `make ci-local-extended` | `check` + `smoke-extended` | A stronger local pass before release / packaging |
| `make gotestwaf` | WAF effectiveness and false-positive regressions | Before a release, or after CRS / request-inspection changes |
| `make bench` / `make bench-proxy` | Proxy transport throughput / latency baseline | After proxy transport tuning |
| `make bench-waf` | WAF allow / block throughput / latency baseline | After WAF inspection / CRS / bypass / logging changes |
| `make bench-full` | Performance baseline for both proxy and WAF | Before releases that may move performance |

### 18.2.1 The assurance matrix

A single table summarizes "what each command directly guarantees".
`yes` means directly checked, `partial` means indirectly covered,
`no` means not covered by routine automation.

| Concern | `make smoke` | `deployment-smoke` | `release-binary-smoke` | `http3-public-entry-smoke` | `smoke-extended` | `ci-local` | `ci-local-extended` | `gotestwaf` |
|---|---|---|---|---|---|---|---|---|
| Admin login emits a signed session cookie | yes | yes | yes | no | yes | yes | yes | no |
| Logged-in session status retrievable | yes | yes | yes | no | yes | yes | yes | no |
| Logout invalidates browser auth | yes | yes | yes | no | yes | yes | yes | no |
| CSRF token attached to session-mutating admin API | yes | yes | yes | no | yes | yes | yes | no |
| Reach the embedded admin UI | yes | yes | no | no | yes | yes | yes | no |
| Routed proxy host / path / query / header rewrite | yes | yes | yes | yes | yes | yes | yes | no |
| Client-facing gzip response compression | yes | yes | yes | no | yes | yes | yes | no |
| Built-in HTTPS listener starts with manual cert | no | no | no | yes | no | no | no | no |
| HTTPS response carries `Alt-Svc` | no | no | no | yes | no | no | no | no |
| Actual HTTP/3 over UDP request succeeds | no | no | no | yes | no | no | no | no |
| Deterministic WAF block against release fixture | no | no | yes | no | no | no | no | yes |
| Validity of the binary / systemd deployment guide | no | yes | no | no | yes | no | yes | no |
| Validity of the container deployment guide | no | yes | no | no | yes | no | yes | no |
| release-binary runtime layout / writable paths | no | no | yes | no | no | no | no | no |
| WAF effectiveness against a broader attack suite | no | no | no | no | no | no | no | yes |

> Benchmark targets are **deliberately excluded** from this
> deterministic assurance matrix. They emit artifacts a human reads
> and can fail at arbitrary thresholds, but they are not a regular
> CI gate.

### 18.2.2 What each command actually does

Brief notes on the major commands:

- **`make smoke`**: the fastest regression for the standard compose
  stack — admin UI, login → session cookie, `/auth/session` /
  `/auth/logout`, CSRF token, proxy validate / dry-run / apply, gzip.
  Does **not** check deployment guides / release-binary / GoTestWAF /
  HTTP/3.
- **`make deployment-smoke`**: walks the `docs/build/` procedure for
  real, including staged binary / systemd / sample container start
  and split-mode listener separation. The `make smoke`-equivalent
  admin / proxy / gzip checks also pass.
- **`make smoke-extended`**: `smoke` + `deployment-smoke`. Use when
  you want the runtime and operator docs aligned in one pass.
- **`make release-binary-smoke`**: builds the public tarball,
  extracts it, runs `setup.sh` / `smoke.sh` from inside the bundle.
  This is the top-level command that **verifies "does it work when
  someone downloads the public artifact?"**.
- **`make http3-public-entry-smoke`**: validates the built-in HTTPS +
  HTTP/3 listener on a live runtime (covered in detail in Chapter 15).
- **`make ci-local`**: `make check` (Go tests / UI tests / compose
  config validation) + `make smoke`. The minimum bar before a PR.
- **`make ci-local-extended`**: everything in `ci-local` + `smoke-extended`.
  Use before tagging, packaging, or deployment-doc changes.
- **`make gotestwaf`**: confirms the current WAF setting **blocks
  true-positive attacks above the threshold**, and where required
  retains the **false-positive / bypass thresholds**. The report goes
  under `data/tmp/gotestwaf/`.
- **`make bench` / `make bench-proxy` / `make bench-waf` /
  `make bench-full`**: see §17.1.

## 18.3 Release-binary smoke — verifying the public artifact

For the public-facing tarball, there is a dedicated top-level smoke:

```bash
make release-binary-smoke VERSION=v0.8.1
```

Optional variables:

- `RELEASE_BINARY_SMOKE_ARCH=amd64|arm64`
- `RELEASE_BINARY_SMOKE_SKIP_BUILD=1`
- `RELEASE_BINARY_SMOKE_KEEP_EXTRACTED=1`
- `RELEASE_BINARY_SMOKE_ALLOW_CROSS_ARCH=1`

### 18.3.1 vs. `make deployment-smoke`

The two have different roles:

- **`deployment-smoke`**: validates the `docs/build/` operator guide
  using repo-local staged runtime and sample containers.
- **`release-binary-smoke`**: builds **the public tarball**, extracts
  it, runs `testenv/release-binary/setup.sh` from inside the bundle,
  starts a bundle-local Docker smoke, and runs `./smoke.sh`.

In other words, `release-binary-smoke` is the top-level command for
**"does it work when someone downloads the public artifact?"**.

### 18.3.2 What it checks

From the unpacked public bundle:

- The release tarball contains the required runtime files.
- The bundle-local setup script can prepare writable runtime
  directories.
- The bundle-local Docker smoke environment builds and starts.
- **Admin login / session status / logout invalidation** work from
  the unpacked artifact.
- **Protected-host traffic** flows.
- **Client-facing gzip** works from the public artifact.
- **A deterministic WAF block** fires from the public artifact.

### 18.3.3 Multi-arch policy

The local release-binary smoke targets **host-native artifacts** by
default:

- `amd64` host: typically `RELEASE_BINARY_SMOKE_ARCH=amd64`.
- `arm64` host: typically `RELEASE_BINARY_SMOKE_ARCH=arm64`.
- Non-native artifacts are validated on suitable hardware / release
  hosts / dedicated CI for that arch.

To deliberately try cross-arch locally, pass:

```bash
RELEASE_BINARY_SMOKE_ALLOW_CROSS_ARCH=1
```

This override is **best-effort**. There is no guarantee that Docker,
the unpacked binary, and the local host can handle the artifact
without additional emulation.

## 18.4 Recommended confidence ladder

The mapping from intent to commands:

| Confidence level | Commands |
|---|---|
| Quick runtime sanity | `make smoke` |
| Local CI baseline | `make ci-local` |
| Deployment-docs validity | `make deployment-smoke` |
| Public binary artifact validity | `make release-binary-smoke VERSION=vX.Y.Z` |
| Release readiness without WAF corpus | `make ci-local-extended` |
| Release readiness with WAF corpus | `make ci-local-extended && make gotestwaf` |
| Proxy performance comparison | `make bench-proxy` |
| WAF performance comparison | `make bench-waf` |
| Combined performance comparison | `make bench-full` |
| Direct HTTPS / HTTP/3 entry readiness | `make http3-public-entry-smoke` |
| Public binary release readiness | `make ci-local-extended && make gotestwaf && make release-binary-smoke VERSION=vX.Y.Z` |

## 18.5 Gaps not yet covered by routine validation

What is currently outside routine validation:

- **A complete multi-arch public-tarball smoke from a single
  workstation.**
  - `release-binary-smoke` is host-native by default. Non-native
    artifacts need **suitable hardware / release hosts / dedicated CI
    per arch** instead.

This is a future improvement. Today the practical decision is to
**verify production releases on appropriate hardware**, which we
state explicitly here.

## 18.6 Recap

- Performance comparison is **`make bench-proxy` / `make bench-waf` /
  `make bench-full`**. Not production reproduction — **a controlled
  side-by-side baseline**.
- Behavioral validity is the **regression matrix of the `make smoke`
  family**, used as a dictionary indexed by what you want to verify.
- The public tarball itself is verified via
  **`make release-binary-smoke`**.
- "How much reassurance do you need?" maps to the **confidence
  ladder**.

## 18.7 Bridge to the next chapter

One chapter remains in Part VII. Chapter 19 covers the **static
fast-path evaluation**: why a generic zero-copy / cache replay is
not adopted, the bounded fast-paths already in place, and the
conditions for reopening.
