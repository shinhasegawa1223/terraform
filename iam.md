ほぼ問題ありませんが、`aws_iam_openid_connect_provider` を Terraform 管理下で作成するなら、同じプロバイダーを参照する `data` ブロックは不要です。リソースを作ったのであれば、以降はそのリソースの ARN を直接使いましょう。

---

### 修正版 iam.tf

```hcl
provider "aws" {
  region = var.aws_region
}

# 1) 実行中の AWS アカウント ID を取得
data "aws_caller_identity" "current" {}

# 2) GitHub Actions の OIDC プロバイダーを Terraform で作成
resource "aws_iam_openid_connect_provider" "github" {
  url             = "https://token.actions.githubusercontent.com"
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = [
    # 2025年時点の GitHub のルート CA SHA1 サムプリント
    "6938fd4d98bab03faadb97b34396831e3780aea1"
  ]
}

# 3) GitHub Actions 用に ECR プッシュ権限を持つ IAM ロールを作成
resource "aws_iam_role" "github_ecr_push" {
  name = "github-actions-ecr-push-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = {
          # ここで data ではなく resource の ARN を参照
          Federated = aws_iam_openid_connect_provider.github.arn
        }
        Action = "sts:AssumeRoleWithWebIdentity"
        Condition = {
          StringLike = {
            # main ブランチのワークフロー実行のみ許可
            "token.actions.githubusercontent.com:sub" =
              "repo:${var.github_owner}/${var.github_repo}:ref:refs/heads/main"
          }
        }
      }
    ]
  })
}

# 4) ECR プッシュ用ポリシー
resource "aws_iam_policy" "ecr_push_policy" {
  name        = "GitHubActionsECRPushPolicy"
  description = "Allow GitHub Actions to push Docker images to ECR"
  policy      = jsonencode({
    Version   = "2012-10-17"
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

# 5) ポリシーをロールにアタッチ
resource "aws_iam_role_policy_attachment" "attach_ecr_push" {
  role       = aws_iam_role.github_ecr_push.name
  policy_arn = aws_iam_policy.ecr_push_policy.arn
}
```

#### ポイントまとめ

- **`resource "aws_iam_openid_connect_provider"`** を作成したら、以降は `aws_iam_openid_connect_provider.github.arn` を使う。
- 同じ URL を参照する `data "aws_iam_openid_connect_provider"` は削除してください。
- `data "aws_caller_identity"` はそのまま、動的にアカウント ID を取得するのに使います。

これで、Terraform 管理下で OIDC プロバイダーを作成し、その ARN を IAM ロールの信頼ポリシーに組み込む一連の流れがスッキリ整理できます。
