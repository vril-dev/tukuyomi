[English](README.md) | [日本語](README.ja.md)

# [web] minimal preset

この preset は、`nginx + coraza` の背後に 1 つの upstream app を置く最小の local WAF stack を使いたい時に使います。

最初に実運用で使う前に、次を変更してください。
- `WAF_APP_URL`
- `WAF_API_KEY_PRIMARY`
- `WAF_ADMIN_SESSION_SECRET`

適用と検証:

```bash
make preset-apply PRESET=minimal
make preset-check PRESET=minimal
```
