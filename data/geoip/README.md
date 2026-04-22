`data/geoip/` keeps managed GeoIP artifacts such as `country.mmdb`,
`GeoIP.conf`, and `update-status.json`.

The `Options` page uploads and replaces:

- `data/geoip/country.mmdb`
- `data/geoip/GeoIP.conf`

when request country resolution and managed updates are enabled.

Only this `README.md` is intended to ship in generic release bundles. The
actual managed artifacts remain operator-owned runtime files.
