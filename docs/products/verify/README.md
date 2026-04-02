# tukuyomi-verify

[English](README.md) | [Japanese](README.ja.md)

`tukuyomi-verify` is the external verification and reporting tool for Tukuyomi WAF products. It consumes exported `verify-manifest` data, runs browser and HTTP scenarios, and emits machine-readable and human-readable verification reports.

## Best Fit

- Release validation before publishing a WAF product
- Regression checks against exported `verify-manifest` data
- Teams that need HTML, JSON, and CI-friendly verification outputs

## Highlights

- Browser and HTTP runner based verification
- Manifest-driven checks for `tukuyomi`, `tukuyomi-proxy`, and `tukuyomi-edge`
- HTML, JSON, JUnit, and CI summary outputs
- External verifier role with no required runtime dependency from `[web]`

## Public Distribution

- Latest public binary: [`v0.1.5`](https://github.com/vril-dev/tukuyomi-releases/releases/tag/v0.1.5)
- Family-wide releases index: [`tukuyomi-releases`](https://github.com/vril-dev/tukuyomi-releases/releases)

## Related Docs

- Family overview: [`../../../README.md`](../../../README.md)
- Product comparison: [`../../product-comparison.md`](../../product-comparison.md)

Detailed report and UI docs ship with the binary bundle.
