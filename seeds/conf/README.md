# Runtime Config Seed Bundle

`make db-import` imports `config-bundle.json` when an operator-supplied runtime
file is missing or empty. The priority is:

1. configured runtime file such as `conf/proxy.json`
2. configured bundle file, or bundled `seeds/conf/config-bundle.json`
3. legacy per-domain seed file under `seeds/conf`
4. built-in compatibility default

Use this bundle as production seed material before the first DB import. After
DB bootstrap, normalized DB rows are the runtime authority.

The `admin_users` bundle domain seeds the initial admin login users when
`admin_users` is empty. Preview import uses this same domain; there is no
separate preview admin-user seed. Seeded users must keep
`must_change_password=true` so the first login is forced to rotate the password.

`conf/config.json` remains the bootstrap source for DB connection settings and
is not replaced by this directory.

When running the binary from a different working directory, set
`WAF_DB_IMPORT_SEED_BUNDLE_FILE` to the bundle path. `WAF_DB_IMPORT_SEED_CONF_DIR`
is still accepted for legacy per-domain seed files.
