# tukuyomi-edge

[English](README.md) | [Japanese](README.ja.md)

`tukuyomi-edge` is the device-oriented single-binary ingress security gateway in the Tukuyomi family. It keeps the same core L7 controls as `tukuyomi` and `tukuyomi-proxy`, then adds device identity and edge-focused operational features.

## Best Fit

- IoT and branch deployments that prefer `systemd + single binary`
- Edge nodes that need built-in routing and policy enforcement
- Fleets that later connect to a central control plane

## Highlights

- Coraza WAF + OWASP CRS
- Built-in admin UI and route editor
- Device authentication and center-linked operations
- Experimental host-side hardening alongside normal L7 controls

## Public Distribution

- Latest public binary: [`v0.12.6`](https://github.com/vril-dev/tukuyomi-releases/releases/tag/v0.12.6)
- Family-wide releases index: [`tukuyomi-releases`](https://github.com/vril-dev/tukuyomi-releases/releases)

## Related Docs

- Family overview: [`../../../README.md`](../../../README.md)
- Product comparison: [`../../product-comparison.md`](../../product-comparison.md)

Detailed operational docs and screenshots ship with the binary bundle.
