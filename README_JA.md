# cross-poster-sdk

[![CI](https://github.com/takaodev/cross-poster-sdk/actions/workflows/ci.yml/badge.svg)](https://github.com/takaodev/cross-poster-sdk/actions/workflows/ci.yml)
[![npm version](https://img.shields.io/npm/v/cross-poster-sdk.svg)](https://www.npmjs.com/package/cross-poster-sdk)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

> **X（Twitter）、Mastodon、Bluesky（AT Protocol）、Misskey、Meta Threads に対応したゼロ依存マルチSNSクロスポストSDK。DNSリバインディング完全耐性を持つSSRF防御と、AES-256-GCM 資格情報暗号化エンベロープを内蔵。**

[English README is available here](./README.md)

---

## 💡 なぜ `cross-poster-sdk` なのか？

分散型SNS（Mastodon, Misskey）と中央集権型SNS（X, Bluesky, Threads）を横断してクロスポストするシステムを構築する場合、深刻なセキュリティリスクと複雑さに直面します：

1. **悪意あるインスタンスURLによる SSRF ＆ クラウド認証情報窃取**:
   ユーザーが自由に入力できるインスタンスドメイン（`https://my-instance.com`）が悪意を持って内部ネットワークやクラウドのメタデータエンドポイント（`169.254.169.254`）に向けられていた場合、サーバーの機密情報や IAM 認証情報が即座に奪われます。
2. **DNS リバインディング攻撃（TOCTOU）の脅威**:
   URL検証時に正規のパブリックIPを返し、HTTP接続確立時のミリ秒で内部IP（`127.0.0.1` や `169.254.169.254`）を返すDNSリバインディング攻撃に対し、一般的な `fetch()` や `axios` では防御が極めて困難です。
3. **API仕様と文字数計算の断片化**:
   X (全角2/半角1/URL23), Bluesky (Grapheme Clusters), Mastodon (Code points) など、各社で異なる文字数制限やスレッド構造の処理。

`cross-poster-sdk` はこれらをゼロ依存で完全に解決します：

- **DNSリバインディング完全耐性を持つ SSRF 防御**:
  プライベートIP、リンクローカル、CGNAT、ループバック、クラウドメタデータ、IPv4射影IPv6、6to4を完全遮断。DNS解決した安全なIPアドレスを **Node.js の TLS ソケットの `lookup` コールバックに直接ピン留め** するため、DNSのTTL改ざんによるすり替えが物理的に不可能です。
- **統一 5-Network アダプター**:
  `postToService` / `deleteFromService` の単一インターフェースで、5大SNSへの投稿・削除を網羅。
- **各社仕様に忠実な文字数カウンター ＆ 自動スレッド分割**:
  各SNS固有のカウントロジックに基づき、長文を最適な文末境界で分割して `(1/3)`, `(2/3)` などのナンバリングを付与し、連鎖スレッド投稿（`postThreadToService`）を実行。
- **AES-256-GCM 資格情報エンベロープ**:
  データベースに保存する OAuth トークンや App パスワードを `v1.<iv>.<tag>.<ciphertext>` 形式で安全に認証暗号化。
- **外部依存ゼロ (Zero Dependencies)**:
  Node.js 標準組み込みモジュール（`node:https`, `node:dns`, `node:net`, `node:crypto`）のみで完結。

---

## 📦 インストール

```bash
npm install cross-poster-sdk
```

要件: Node.js `>= 18.0.0`

---

## 🚀 クイックスタート

### 1. 単一投稿と削除

```typescript
import { postToService, deleteFromService } from 'cross-poster-sdk';

// 1. Bluesky へ投稿
const bskyResult = await postToService(
  {
    service: 'bluesky',
    credentials: {
      username: 'handle.bsky.social',
      appPassword: 'xxxx-xxxx-xxxx-xxxx',
    },
  },
  'cross-poster-sdk からこんにちは！ 🚀'
);
console.log('Bluesky Post URI:', bskyResult.remoteId);

// 2. カスタム Mastodon または Misskey インスタンスへ安全に投稿（SSRF保護済み）
const mastodonResult = await postToService(
  {
    service: 'mastodon',
    instanceUrl: 'https://mastodon.social',
    credentials: { accessToken: 'YOUR_MASTODON_TOKEN' },
  },
  'Mastodonへのステータス投稿'
);

// 3. 投稿の削除
await deleteFromService(
  {
    service: 'bluesky',
    credentials: { username: 'handle.bsky.social', appPassword: 'xxxx-xxxx-xxxx-xxxx' },
  },
  bskyResult.remoteId!
);
```

---

### 2. スマート長文スレッド分割 ＆ 連鎖投稿

各SNSの文字数上限に合わせて自動分割し、直前の投稿にリプライする形でスレッドを連続投稿します：

```typescript
import {
  countServiceCharacters,
  splitPostIntoThreads,
  postThreadToService,
} from 'cross-poster-sdk';

const longText = `長文のアナウンス記事です...（非常に長い本文）...`;

// 1. 各SNS固有の文字数重みを正確に測定
const weight = countServiceCharacters('x', longText);

// 2. ナンバリングインジケータ付きで安全な長さに分割
const threads = splitPostIntoThreads('x', longText, { numbering: true });
// -> ['段落1... (1/3)', '段落2... (2/3)', '段落3... (3/3)']

// 3. 前の投稿へ自動リプライしながら一括連鎖投稿
const results = await postThreadToService(
  { service: 'x', credentials: { accessToken: 'token' } },
  threads
);
console.log('スレッド投稿完了！親ツイートID:', results[0].remoteId);
```

---

### 3. トークン暗号化エンベロープ

データベースにアクセストークンを保存する際、平文ではなく AES-256-GCM 認証暗号化エンベロープとして保護します：

```typescript
import { encryptCredentials, decryptCredentials } from 'cross-poster-sdk';

const secretKey = Buffer.from(process.env.APP_SECRET_KEY!, 'hex'); // 32バイト

// 暗号化エンベロープを作成: "v1.<iv>.<tag>.<ciphertext>"
const envelope = encryptCredentials({ accessToken: 'user-secret-oauth-token' }, secretKey);

// 復号（改ざんや破損時は安全に例外スロー）
const creds = decryptCredentials(envelope, secretKey);
```

---

### 4. ドライラン（シミュレーション）モード

API のレートリミットを消費せずに、ローカルテストやデバッグを実行できます：

```typescript
const dryResult = await postToService(
  { service: 'x', credentials: {} },
  'テストメッセージ',
  { dryRun: true }
);

console.log(dryResult);
// -> { remoteId: 'dry_x_04a8b792-...', simulated: true }
```

---

## 🛡️ SSRF 防御の仕組み

```
ユーザー指定URL (例: https://custom-community.net)
     │
     ▼
[URL形式検証] ── HTTPS 必須 / Basic認証情報の混入を禁止
     │
[DNS名前解決] ── 全IPアドレスを取得
     │
[IP範囲検証]  ── 以下の危険なIPブロックを完全遮断:
                 • 127.0.0.0/8 (ループバック)
                 • 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 (プライベートIP)
                 • 169.254.0.0/16 (リンクローカル / クラウドメタデータ)
                 • 100.64.0.0/10 (CGNAT)
                 • ::1, fe80::/10, fc00::/7 (IPv6 ループバック/ローカル)
                 • ::ffff:0:0/96 (IPv4射影IPv6)
                 • 内部ホスト名 (*.internal, metadata.google.internal 等)
     │
     ▼
[IPピン留め]  ── 検証を通過した IP を TLS ソケットの lookup フックに直接固定
                 接続確立時の DNS 再問い合わせを発生させないため
                 DNSリバインディング攻撃は成立しません。
```

---

## 📄 ライセンス

MIT License © 2026 takaodev
