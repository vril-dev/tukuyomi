# はじめに

本書は、Coraza + OWASP CRS WAF を中核に据えた application-edge control plane
**tukuyomi** を、自分の手で導入し、運用していくための日本語ガイドです。

tukuyomi は、リバースプロキシ、WAF、リクエスト境界のセキュリティ制御、optional な
PHP-FPM / PSGI Runtime Apps、scheduled jobs、Center 承認付きの IoT / Edge デバイス
登録までを **1 つのバイナリ** に束ねた製品です。Web の前段に置く WAF・リバースプロキシ
として動かすのはもちろん、PHP / Perl の Runtime Apps と scheduled jobs を同じ
バイナリで管理できる構造になっています。

## 本書の対象読者

- Web サービスの前段に WAF とリバースプロキシを導入・運用する立場のエンジニア
- single-binary で構造化された WAF + reverse proxy 製品を求めている方
- 自社サービスで PHP-FPM / PSGI 系アプリケーションを動かしており、その実行レイヤと
  edge を 1 つにまとめたい方
- IoT / Edge ゲートウェイで「中央承認付きのデバイス identity」を必要としている方

Linux、Docker、HTTP/HTTPS、TLS、systemd、リバースプロキシの基本的な概念は既知のものと
して話を進めます。Coraza や OWASP CRS の事前知識は不要です。

## 本書の前提となる tukuyomi のバージョン

本書は **tukuyomi v1.2.0** を起点に書いています。

以後のリリースで設定 key 名や Make ターゲット名が変わった場合は、上流リポジトリの
`docs/releases/` 配下に置かれているリリースノートと、`README.ja.md` の最新版を
一次情報として優先してください。

## 本書の読み方

第I部から第VII部まで、順に読み進めれば、初回の検証から本番運用、性能評価、回帰検証
までの一連の流れを通り抜けられる構成にしています。

すでに tukuyomi を導入済みで、特定のトピックだけ知りたいという読者は、目次から該当の
章へ直接ジャンプしてください。各章は、概要 → 仕組み → 設定例 → 運用上の注意 という
流れに揃えてあるので、章単位での読み切りが可能です。

巻末の **付録A 運用リファレンス** は、`data/conf/config.json` と DB `app_config_*`
の全 block を一覧した辞書代わりのリファレンスです。具体的な設定 key を引きたいときは、
本文よりも先に付録Aを参照する方が早い場合があります。

## 表記について

- 「です・ます」調で統一しています。
- `tukuyomi` のソース／設定ファイル／DB テーブル名／Make ターゲット名は、上流
  リポジトリと同じ綴りをそのまま使います。たとえば `Proxy Rules > Backend Pools`、
  `make crs-install`、`waf_events` テーブル、というふうに、原語のまま登場します。
- 必要に応じて初出時に日本語訳を併記しますが、通読時の検索性を優先して、本文中では
  英語表記をそのまま使います。

それでは本編へ進みます。最初の第1章では、tukuyomi がどのような立ち位置の製品で、
何を 1 つのバイナリに束ねているのかを概観します。
