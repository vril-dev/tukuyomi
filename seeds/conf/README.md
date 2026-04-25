# Runtime Config Seeds

`make db-import` imports these files when the operator-supplied runtime file is
missing or empty. The priority is:

1. configured runtime file such as `conf/proxy.json`
2. bundled seed file under `seeds/conf`
3. built-in compatibility default

Use these files as production seed material before the first DB import. After
DB bootstrap, normalized DB rows are the runtime authority.

`conf/config.json` remains the bootstrap source for DB connection settings and
is not seeded from this directory.

When running the binary from a different working directory, set
`WAF_DB_IMPORT_SEED_CONF_DIR` to the directory that contains these files.
