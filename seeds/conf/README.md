# Runtime Config Seeds

`make db-import` imports these files when the operator-supplied runtime file is
missing or empty. The priority is:

1. configured runtime file such as `conf/proxy.json`
2. bundled seed file under `seeds/conf`
3. built-in compatibility default

Use these files as production seed material before the first DB import. After
DB bootstrap, normalized DB rows are the runtime authority.

`admin-users.json` seeds the initial admin login users when `admin_users` is
empty. Preview import uses this same seed file; there is no separate preview
admin-user seed. Seeded users must keep `must_change_password=true` so the
first login is forced to rotate the password.

`conf/config.json` remains the bootstrap source for DB connection settings and
is not seeded from this directory.

When running the binary from a different working directory, set
`WAF_DB_IMPORT_SEED_CONF_DIR` to the directory that contains these files.
