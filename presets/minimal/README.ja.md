[English](README.md) | [日本語](README.ja.md)

# [proxy] minimal preset

この preset は、embedded admin UI と 1 つの default upstream を custom route rule なしで使いたい時に使います。

最初に実運用で使う前に、次を変更してください。
- `.env` の API key 値
- admin API を公開する場合は `config.json` の admin trusted CIDR
- upstream target と必要な protected host routing は `seed/proxy.json`

適用と検証:

```bash
make preset-apply PRESET=minimal
make preset-check PRESET=minimal
```
