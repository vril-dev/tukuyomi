# tukuyomi-center

[English](README.md) | [Japanese](README.ja.md)

`tukuyomi-center` is the control-plane service for `tukuyomi-edge` fleets. It manages device enrollment, heartbeat verification, and approved policy or release distribution from a single binary service.

## Best Fit

- Operators managing multiple `tukuyomi-edge` nodes
- Environments that need signed device enrollment and heartbeat checks
- Rollouts that require approved policy and binary release assignment

## Highlights

- Device enrollment and persistent registry management
- Signed heartbeat verification with replay and skew checks
- Approved policy and release distribution workflow
- API-first control plane for edge fleets

## Public Distribution

- Latest public binary: [`v0.6.4`](https://github.com/vril-dev/tukuyomi-releases/releases/tag/v0.6.4)
- Family-wide releases index: [`tukuyomi-releases`](https://github.com/vril-dev/tukuyomi-releases/releases)

## Related Docs

- Family overview: [`../../../README.md`](../../../README.md)
- Product comparison: [`../../product-comparison.md`](../../product-comparison.md)

Detailed API and operations docs ship with the binary bundle.
