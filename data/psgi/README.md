# PSGI Runtime Data

This directory is reserved for operator-built Perl/Starman runtime bundles and materialized PSGI process state.

- `binaries/<runtime_id>/`: built runtime bundle, wrappers, `runtime.json`, and `modules.json`
- `runtime/<vhost_name>/`: generated per-vhost process metadata, pid, and logs

Build a runtime with `make psgi-build VER=5.38` or `make psgi-build RUNTIME=perl538`.
