Managed bypass override rules live here.

- runtime path: `conf/rules/*.conf`
- reference from `waf-bypass.json` via `extra_rule`
- files here are operator-managed overrides, not part of the base WAF rule set
- shipped sample: `conf/rules/search-endpoint.conf`
- paired bypass sample: `conf/waf-bypass.sample.json`
