結論から 👇

- **いまの構成（Django は AdminInitiateAuth でサーバ側ログイン、フロントは Hosted UI を使う想定）なら**
  **`callback_urls` は“フロントエンド”のリダイレクト先**を入れます。
  **バックエンド `http://localhost:8000/...` は不要**です。

- 開発環境（Next.js/NextAuth 想定）の例

  ```hcl
  # terraform.tfvars
  callback_urls = [
    "http://localhost:3000/api/auth/callback/cognito"  # NextAuthのデフォルト
  ]
  logout_urls = [
    "http://localhost:3000/"
  ]
  ```

  > NextAuth（Auth.js）を使う場合、デフォルトのコールバックは
  > `http://<frontend-origin>/api/auth/callback/<provider>`
  > （ここでは `<provider>=cognito` としてます）

---

# なぜフロント URL なの？

- **Hosted UI（OAuth2 / PKCE）を使うとき**は、Cognito がユーザー認証後に**ブラウザをどこへ戻すか**を指定します。
  返す先＝**認可コードを受け取ってトークン交換するエンドポイント**で、通常は**フロントのルート**（NextAuth のコールバック）です。
- 逆に、**Django が AdminInitiateAuth（email/password）で直接ログイン**するフローは**OAuth2 リダイレクトを使いません**。
  この“サーバ用クライアント”には `callback_urls` 設定自体が不要です（Terraform でも分けてあります）。

---

# もし「バックエンドでコード受け取りたい」なら

- その場合は**Django 側に `/auth/cognito/callback` のようなコールバック API**を実装し、
  そこで `authorization_code` を受け取って**サーバからトークン交換**します。
- そのときは `callback_urls = ["http://localhost:8000/auth/cognito/callback"]` のように**バックエンド URL**を登録します。
  （← 今のサンプルにはこのエンドポイント実装は入れていません）

---

# よくあるハマり

- **URL は完全一致**（スキーム・ホスト・ポート・パス・末尾スラッシュまで）。`/callback` と `/callback/` は別物。
- **`http` が許されるのは localhost のみ**。本番は `https://`。
- **ワイルドカード不可**。環境ごとに URL を列挙します（例：開発/ステージ/本番）。

---

# まとめ（あなたの環境用のそのままコピペ）

- フロント：`http://localhost:3000`（Next.js/NextAuth）
- バックエンド：`http://localhost:8000`（Django/Ninja）

**Terraform (`infra/tf/terraform.tfvars`)**

```hcl
callback_urls = [
  "http://localhost:3000/api/auth/callback/cognito"
]
logout_urls = [
  "http://localhost:3000/"
]
```

この設定で、Hosted UI → 認可コード → **Next.js 側で受け取り** → 以降は取得した JWT を `Authorization: Bearer` で Django に投げる、という流れになります。
