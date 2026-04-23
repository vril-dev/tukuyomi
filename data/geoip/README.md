`data/geoip/` is now legacy/import-only material.

DB-backed runtime stores managed GeoIP country assets and update state in the
runtime database. The `Options` page uploads and replaces DB-backed assets.

- legacy import source: `data/geoip/country.mmdb`
- legacy import source: `data/geoip/GeoIP.conf`
- legacy import source: `data/geoip/update-status.json`

These files are read only during explicit import workflows such as
`make db-import`.

Generic release bundles do not need persistent GeoIP runtime files.
