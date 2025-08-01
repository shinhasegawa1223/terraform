以下、それぞれのデータソースが **どう動いているか**、**何をしているか** をより細かく噛み砕いて解説します。

---

## 1. `data "aws_caller_identity" "current" {}`

### 🔍 何をしているか

- Terraform の実行時に、現在の AWS 認証情報（`~/.aws/credentials` や環境変数で指定しているクレデンシャル）で
  **“いまログインしている AWS アカウント”** の情報を AWS STS（Security Token Service）経由で取得します。

### 🛠️ 返ってくる主な値

- `account_id` … AWS アカウント番号（例: `123456789012`）
- `arn` … 現在使っている認証情報の ARN（例: `arn:aws:iam::123456789012:user/you`）
- `user_id` … IAM ユーザーまたはロールの一意 ID

### ✅ 何に使うか

Terraform の中でハードコーディングせずに **自動的に**アカウント ID を埋め込むために使います。
具体例：

```hcl
# ポリシー内で ECR リポジトリの ARN を動的に組み立てる
"Resource": "arn:aws:ecr:${var.aws_region}:${data.aws_caller_identity.current.account_id}:repository/${var.repository_name}"
```

> これがあると、`123456789012` の部分をいちいち手入力しなくて済み、
> アカウントを切り替えて `terraform apply` しても常に正しい ARN が生成されます。

---

## 2. `data "aws_iam_openid_connect_provider" "github" { ... }`

### 🔍 何をしているか

- すでに AWS IAM に登録されている **OIDC プロバイダー** （ここでは GitHub Actions 用のプロバイダー）を参照し、
  そのメタ情報（ARN やクライアント ID、サムプリントなど）を読み込みます。

### 🛠️ 返ってくる主な値

- `arn` … プロバイダーの ARN（例: `arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com`）
- `client_id_list` … そのプロバイダーを使えるクライアント ID の一覧（通常は `sts.amazonaws.com`）
- `thumbprint_list` … SSL/TLS 証明書の検証に使うサムプリント

### ✅ 何に使うか

IAM ロールの **信頼ポリシー** (`assume_role_policy`) の中で、“どのフェデレーテッド ID プロバイダー” からのトークンを受け入れるかを示すのに使います：

```hcl
resource "aws_iam_role" "github_ecr_push" {
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = {
        Federated = data.aws_iam_openid_connect_provider.github.arn  # ← ここ
      }
      Action    = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringLike = {
          # GitHub の main ブランチから発行されたトークンに限定
          "token.actions.githubusercontent.com:sub"
            = "repo:${var.github_owner}/${var.github_repo}:ref:refs/heads/main"
        }
      }
    }]
  })
}
```

- `Principal.Federated` に OIDC プロバイダーの ARN を書くことで、
  「このロールは GitHub Actions の OIDC トークンを持つワークフローだけ引き受けて良いよ」という設定になります。

---

## 🔄 まとめ：なぜ “data” なのか？

- **`resource`**：Terraform が **作成**／**管理** する実体
- **`data`**：Terraform が既存のリソースから **読み取るだけ** の実体

今回の２つはどちらも「Terraform から既存の情報を呼び出したいだけ」なので `data` ブロックを使っています。

- `aws_caller_identity` → 実行環境のアカウント情報
- `aws_iam_openid_connect_provider` → すでに AWS に登録済みの OIDC プロバイダー情報

これらを使って、

1. ポリシーのリソース ARN（アカウント ID 部分）を自動生成
2. IAM ロールの信頼元（フェデレーテッドプロバイダー）を正しく設定

ができるわけですね。

---

### ✏️ 補足：もし “登録済み” の OIDC プロバイダーがない場合

```hcl
resource "aws_iam_openid_connect_provider" "github" {
  url             = "https://token.actions.githubusercontent.com"
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = ["6938fd4d98bab03faadb97b34396831e3780aea1"]
}
```

のように **`resource`** で作成してしまえば、
同じく `aws_iam_openid_connect_provider.github.arn` を参照できます。

---

以上で、

- **`aws_caller_identity.current`** が “アカウント情報を取ってくる”
- **`aws_iam_openid_connect_provider.github`** が “GitHub Actions の OIDC プロバイダー情報を取ってくる”

という役割と、その **具体的な使いみち** がクリアになったかと思います！
他にも不明点があればどうぞ。
