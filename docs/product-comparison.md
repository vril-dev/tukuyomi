# Product Comparison

This matrix reflects the post-integration product layout.

`tukuyomi-proxy` is no longer treated as a separate current product. Its proxy,
routing, cache, WAF tuning, PHP-FPM, and scheduled-task capabilities are now part
of `tukuyomi`. The historical `tukuyomi-proxy` binary releases remain archived in
`tukuyomi-releases`.

Legend:

- `○`: first-class or native
- `△`: partial, delegated, planned, or conditional
- `×`: out of scope

| Feature | `tukuyomi` | `tukuyomi-edge` | `tukuyomi-center` | `tukuyomi-verify` |
| --- | --- | --- | --- | --- |
| Primary role | WAF / reverse proxy / API gateway | Device-side edge runtime | Center-side management | External verification |
| WAF engine (Coraza / CRS) | ○ | ○ | × | △ validates behavior |
| Reverse proxy and routing | ○ | ○ | × | × |
| Backend pools / load balancing | ○ | △ | × | × |
| Built-in admin UI/API | ○ | ○ | ○ | ○ report UI/API surface |
| Runtime policy updates | ○ | ○ | ○ | × |
| False-positive tuner | ○ | △ | × | △ validates output |
| Cache / bypass rules | ○ | ○ | × | △ tests scenarios |
| Rate / country / bot / semantic / IP reputation controls | ○ | ○ | × | △ tests scenarios |
| Static hosting / PHP-FPM option | ○ | × | × | × |
| Scheduled tasks | ○ | △ | △ | × |
| Single binary runtime | ○ | ○ | ○ | ○ |
| Docker / container deployment | ○ | △ | △ | ○ |
| Shared DB / multi-node operation | ○ | △ | ○ | × |
| Device identity and center link | × | ○ | ○ | △ consumes manifests |
| Verification manifest export | ○ | ○ | ○ | ○ consumes manifests |
| Product distribution state | Current canonical product | Planned / archive-dependent | Separate publication planned | Distribution under review |

## Naming

- Use `tukuyomi` for current WAF/proxy documentation, binaries, service examples, and source repository references.
- Use `tukuyomi-proxy` only when referring to archived historical releases or migration notes.
- The runtime engine value `tukuyomi_proxy` is a config value and is not a product name.
