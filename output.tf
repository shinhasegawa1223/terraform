output "repository_url" {
  description = "ECR リポジトリの URL"
  value       = aws_ecr_repository.backend.repository_url
}

output "iam_role_arn" {
  description = "GitHub Actions が引き受ける IAM ロールの ARN"
  value       = aws_iam_role.github_ecr_push.arn
}
