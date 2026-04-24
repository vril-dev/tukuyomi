[English](README.md) | [日本語](README.ja.md)

# [proxy] minimal preset

Use this preset when you want the embedded admin UI and a single default upstream without custom route rules.

Before first real use, change:
- `.env` API key values
- admin trusted CIDRs in DB app config if you expose the admin API
- optional `conf/proxy.json` if you want to override the built-in minimal upstream seed before `make db-import`

Apply and validate with:

```bash
make preset-apply PRESET=minimal
make preset-check PRESET=minimal
```
