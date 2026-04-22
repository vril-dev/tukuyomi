# tukuyomi Release-Binary Smoke

This document defines the top-level smoke for public release tarballs.

## Command

```bash
make release-binary-smoke VERSION=v0.8.1
```

Optional variables:

- `RELEASE_BINARY_SMOKE_ARCH=amd64|arm64`
- `RELEASE_BINARY_SMOKE_SKIP_BUILD=1`
- `RELEASE_BINARY_SMOKE_KEEP_EXTRACTED=1`
- `RELEASE_BINARY_SMOKE_ALLOW_CROSS_ARCH=1`

## What it does

`make release-binary-smoke` is distinct from `make deployment-smoke`.

- `deployment-smoke`
  - validates the operator guides under `docs/build/`
  - uses repo-local staged runtime and sample container paths
- `release-binary-smoke`
  - builds the public tarball
  - extracts that tarball
  - runs the bundle's own `testenv/release-binary/setup.sh`
  - starts the bundle-local Docker smoke environment
  - runs the bundle-local `./smoke.sh`

That makes it the correct top-level command for "would the public release artifact itself work if someone downloaded it?"

## What it validates

The extracted public bundle proves:

- the release tarball contains the expected runtime files
- the bundle-local setup script can stage writable runtime directories
- the bundle-local Docker smoke environment builds and boots
- admin login, session status, and logout invalidation work from the extracted artifact
- routed protected-host traffic works
- client-facing gzip still works from the public artifact
- the deterministic WAF block still triggers from the public artifact

## Recommended use

For release readiness, run:

```bash
make ci-local-extended
make gotestwaf
make release-binary-smoke VERSION=v0.8.1
```

## Multi-arch policy

Local release-binary smoke is defined as host-native by default.

- `amd64` hosts should normally smoke `RELEASE_BINARY_SMOKE_ARCH=amd64`
- `arm64` hosts should normally smoke `RELEASE_BINARY_SMOKE_ARCH=arm64`
- non-native artifact validation should happen on matching hardware, a release host, or dedicated CI that is explicitly responsible for that architecture

If you intentionally want to try a cross-arch local run, set:

```bash
RELEASE_BINARY_SMOKE_ALLOW_CROSS_ARCH=1
```

That override is best-effort only. It does not promise that Docker, the extracted binary, or the local host will support the non-native artifact without additional emulation setup.

## Related docs

- regression matrix: [regression-matrix.md](regression-matrix.md)
- binary/systemd deployment: [binary-deployment.md](../build/binary-deployment.md)
