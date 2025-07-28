variable "aws_region" {
  description = "AWS リージョン"
  type        = string
  default     = "ap-northeast-1"
}

variable "repository_name" {
  description = "ECR リポジトリ名"
  type        = string
}

variable "github_owner" {
  description = "GitHub リポジトリのオーナー（ユーザー or 組織）"
  type        = string
}

variable "github_repo" {
  description = "GitHub リポジトリ名"
  type        = string
}
