[English](README.md) | [日本語](README.ja.md)

# [proxy] minimal preset

Use this preset when you want the embedded admin UI and a single default upstream without custom route rules.

Before first real use, change:
- `.env` API key values
- `config.json` admin trusted CIDRs if you expose the admin API
- `seed/proxy.json` upstream target and any protected host routing you need

Apply and validate with:

```bash
make preset-apply PRESET=minimal
make preset-check PRESET=minimal
```
