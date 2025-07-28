provider "aws" {
  region = var.aws_region
}

# 現在の AWS アカウント ID を取得
data "aws_caller_identity" "current" {}

# GitHub Actions OIDC プロバイダー (AWS 側の登録は手動 or 別リソースで)
data "aws_iam_openid_connect_provider" "github" {
  url = "https://token.actions.githubusercontent.com"
}

# GitHub Actions 用に ECR プッシュ権限を持つ IAM ロールを作成
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
          # main ブランチからのワークフロー実行を許可
          "token.actions.githubusercontent.com:sub" = "repo:${var.github_owner}/${var.github_repo}:ref:refs/heads/main"
        }
      }
    }]
  })
}

# ECR プッシュ用ポリシー
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

# ロールにポリシーをアタッチ
resource "aws_iam_role_policy_attachment" "attach_ecr_push" {
  role       = aws_iam_role.github_ecr_push.name
  policy_arn = aws_iam_policy.ecr_push_policy.arn
}
