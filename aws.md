以下、それぞれのブロックが何をしているのか、順を追って詳しく解説します。

---

## 1. `provider "aws"`

```hcl
provider "aws" {
  region = var.aws_region
}
```

- **役割**：Terraform に使う AWS プロバイダーを初期化します。
- **`region`**：AWS API を叩く際のデフォルトリージョン（例：`ap-northeast-1`）を `variables.tf` の `var.aws_region` から受け取ります。

> **ポイント**：複数リージョンを使いたい場合は、プロバイダーを別名で複数定義するか、各リソースで `provider = aws.some_alias` と指定します。

---

## 2. データソース：`aws_caller_identity` と `aws_iam_openid_connect_provider`

```hcl
data "aws_caller_identity" "current" {}

data "aws_iam_openid_connect_provider" "github" {
  url = "https://token.actions.githubusercontent.com"
}
```

1. **`aws_caller_identity.current`**

   - 実行中の AWS 認証情報が属する **アカウント ID**、ユーザー ARN、ユーザー名 等を返します。
   - 本構成では主に `${data.aws_caller_identity.current.account_id}` を参照し、ポリシーで指定するリソース ARN（`arn:aws:ecr:リージョン:アカウントID:repository/◯◯`）を動的に組み立てるために使います。

2. **`aws_iam_openid_connect_provider.github`**

   - すでに AWS に登録済みの OIDC プロバイダー（ここでは GitHub Actions のトークン発行元）を参照します。
   - `url = "https://token.actions.githubusercontent.com"` で指定されたプロバイダー情報を読み込み、その ARN を取得。
   - 取得した ARN（`data.aws_iam_openid_connect_provider.github.arn`）を IAM ロールの信頼ポリシーで使い、GitHub Actions のワークフローだけがそのロールを引き受けられるようにします。

> **代替**：もし手動で OIDC プロバイダーを登録していない／Terraform で `resource "aws_iam_openid_connect_provider"` を自前定義したい場合は、そのリソース名から ARN を参照しても OK です。

---

## 3. IAM ロール：`aws_iam_role.github_ecr_push`

```hcl
resource "aws_iam_role" "github_ecr_push" {
  name = "github-actions-ecr-push-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Federated = data.aws_iam_openid_connect_provider.github.arn
      }
      Action = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringLike = {
          "token.actions.githubusercontent.com:sub" =
            "repo:${var.github_owner}/${var.github_repo}:ref:refs/heads/main"
        }
      }
    }]
  })
}
```

- **リソース名**：`github-actions-ecr-push-role`
- **`assume_role_policy` の中身**：

  1. **`Principal.Federated`**

     - GitHub Actions の OIDC プロバイダー ARN を指定。
     - これにより “Web ID トークン” を使ったフェデレーテッド認証が可能となります。

  2. **`Action`**

     - `sts:AssumeRoleWithWebIdentity`：OIDC トークンを使ってロールを取得する際に必要なアクション。

  3. **`Condition.StringLike`**

     - トークンの `sub`（サブジェクト）クレームが `repo:OWNER/REPO:ref:refs/heads/main` と一致する場合に限定。
     - → GitHub リポジトリの `main` ブランチ上で実行されたワークフローだけ許可、というセキュリティ制御になります。

> **ポイント**：
>
> - `var.github_owner` / `var.github_repo` はそれぞれ GitHub の所有者・リポジトリ名を変数から渡すようにします。
> - 必要に応じてブランチやタグを変えたり、複数のリポジトリを許可したりできます。

---

## 4. IAM ポリシー：`aws_iam_policy.ecr_push_policy`

```hcl
resource "aws_iam_policy" "ecr_push_policy" {
  name        = "GitHubActionsECRPushPolicy"
  description = "Allow GitHub Actions to push Docker images to ECR"
  policy      = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["ecr:GetAuthorizationToken"]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "ecr:BatchCheckLayerAvailability",
          "ecr:CompleteLayerUpload",
          "ecr:GetDownloadUrlForLayer",
          "ecr:InitiateLayerUpload",
          "ecr:PutImage",
          "ecr:UploadLayerPart",
          "ecr:DescribeRepositories",
          "ecr:CreateRepository"
        ]
        Resource = "arn:aws:ecr:${var.aws_region}:${data.aws_caller_identity.current.account_id}:repository/${var.repository_name}"
      }
    ]
  })
}
```

- **Statement 1**

  - `ecr:GetAuthorizationToken` を全リソースに対して許可
  - Docker CLI 等で ECR へのログインに必要なトークンを取得するアクション

- **Statement 2**

  - 実際にイメージのレイヤーアップロード／プッシュ／リポジトリ作成などの一式アクションを許可
  - **`Resource`** に `"arn:aws:ecr:<リージョン>:<アカウントID>:repository/<リポジトリ名>"` を指定

    - アカウント ID は `data.aws_caller_identity.current.account_id` から取得
    - `var.repository_name` でリポジトリ名を変数化

> **補足**：
>
> - `ecr:CreateRepository` を許可しているので、もしリポジトリが存在しなければ GitHub Actions 実行時に自動作成されます。
> - プロダクション向けには「既存リポジトリへのプッシュのみ許可」など、権限を絞り込むことも検討してください。

---

## 5. ポリシーをロールにアタッチ：`aws_iam_role_policy_attachment`

```hcl
resource "aws_iam_role_policy_attachment" "attach_ecr_push" {
  role       = aws_iam_role.github_ecr_push.name
  policy_arn = aws_iam_policy.ecr_push_policy.arn
}
```

- **`role`**: 先ほど作成した `github_ecr_push` ロールを指定
- **`policy_arn`**: 作成した ECR プッシュ用ポリシーの ARN (`aws_iam_policy.ecr_push_policy.arn`) を指定
- これで、GitHub Actions が引き受けるロールに「ECR へのログイン＆プッシュ権限」が付与されます。

---

### 全体のフロー

1. **Terraform apply** で

   - AWS 側に OIDC プロバイダー（既存）を参照 → IAM ロールを作成
   - ECR への読み書き権限を定義したポリシーを作成 → ロールへアタッチ

2. **Terraform output** から

   - `iam_role_arn`（ロール ARN）
   - `repository_url`（ECR リポジトリ URL）
     を取得し、GitHub Secrets に登録。

3. **GitHub Actions** で

   - `configure-aws-credentials` → `role-to-assume` にロール ARN を渡し、OIDC で安全に認証
   - `amazon-ecr-login` → ECR へログイン
   - Docker ビルド & プッシュ → Terraform で作った ECR リポジトリにイメージを配置

---

以上がそれぞれのブロックの目的と、相互にどうつながっているかの詳細説明になります。疑問点があればお気軽にどうぞ！
