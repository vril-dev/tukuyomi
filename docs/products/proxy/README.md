# tukuyomi-proxy

[English](README.md) | [Japanese](README.ja.md)

`tukuyomi-proxy` is the general-purpose single-binary WAF and reverse proxy in the Tukuyomi family. It keeps the core Coraza + CRS security controls, adds built-in route management and admin UI, and does not require `nginx` in front of it.

## Best Fit

- Single-binary or lightweight container deployments
- API gateway and reverse proxy use cases
- Operators who want TLS termination, routing, and WAF controls in one runtime

## Highlights

- Coraza WAF + OWASP CRS
- Built-in admin UI and route editor
- Core controls: IP reputation, bot defense, semantic security, rate limiting, country block
- File-backed and DB-backed policy/runtime data paths

## Public Distribution

- Latest public binary: [`v0.7.6`](https://github.com/vril-dev/tukuyomi-releases/releases/tag/v0.7.6)
- Family-wide releases index: [`tukuyomi-releases`](https://github.com/vril-dev/tukuyomi-releases/releases)
- GitHub auto-generated source archives on that release page belong to `tukuyomi-releases`, not to the private build repository for `tukuyomi-proxy`

## Related Docs

- Family overview: [`../../../README.md`](../../../README.md)
- Product comparison: [`../../product-comparison.md`](../../product-comparison.md)

Detailed runtime and configuration docs ship with the binary bundle.
