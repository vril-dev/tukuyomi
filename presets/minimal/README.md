[English](README.md) | [日本語](README.ja.md)

# [web] minimal preset

Use this preset when you want the smallest local WAF stack with one upstream app behind `nginx + coraza`.

Before first real use, change:
- `WAF_APP_URL`
- `WAF_API_KEY_PRIMARY`
- `WAF_ADMIN_SESSION_SECRET`

Apply and validate with:

```bash
make preset-apply PRESET=minimal
make preset-check PRESET=minimal
```
