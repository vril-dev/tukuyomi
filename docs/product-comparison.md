# Product Comparison

This matrix compares the three runtime products in the `tukuyomi` family:

- `tukuyomi`
- `tukuyomi-proxy`
- `tukuyomi-edge`

Legend:

- `○`: first-class or native
- `△`: partial, delegated, or conditional
- `×`: out of scope

Notes:

- `single binary` describes runtime shape, not whether Docker images also exist.
- `DB / multi-node` means shared-store scale-out inside the product itself, not external control-plane integration.
- `host hardening` means host-level L3/L4 tuning or firewall management, not upstream CDN / ISP DDoS protection.

| Feature | `tukuyomi` | `tukuyomi-proxy` | `tukuyomi-edge` |
| --- | --- | --- | --- |
| WAF engine (Coraza / CRS) | ○ | ○ | ○ |
| Reverse proxy | ○ (built-in app proxy; often fronted by `nginx` / LB) | ○ (built-in) | ○ (built-in) |
| Single binary runtime | △ (local binary supported; front proxy / LB still typical) | ○ | ○ |
| Primary deployment shape | ○ Docker / compose or local binary | △ Docker or single binary | ○ host / `systemd` |
| Route / upstream management | × | ○ | ○ |
| Dynamic runtime policy update | ○ | ○ | ○ |
| Embedded admin UI | ○ | ○ | ○ |
| Log / status UI | ○ | ○ | ○ |
| Cache control | ○ (internal response cache + optional front cache) | ○ (internal cache + rules) | ○ (internal cache + rules) |
| Bypass rules | ○ | ○ | ○ |
| IP reputation | ○ | ○ | ○ |
| Bot defense | ○ | ○ | ○ |
| Semantic security | ○ | ○ | ○ |
| Rate limit | ○ | ○ | ○ |
| Country control | ○ | ○ | ○ |
| Device authentication | × | × | ○ |
| Center / device identity flow | × | × | ○ |
| WebSocket support | △ (proxy pass-through) | △ (upgrade pass-through) | △ (upgrade pass-through) |
| TLS termination / ACME | △ (front proxy / LB managed) | ○ | ○ |
| Notifications | ○ | ○ | ○ |
| DB / MySQL shared store | ○ | ○ | × |
| Multi-node operation | ○ | ○ | × |
| Host-level hardening (L3/L4) | × | × | △ (experimental) |
