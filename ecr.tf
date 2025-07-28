provider "aws" {
  region = var.aws_region
}

resource "aws_ecr_repository" "backend" {
  name                 = var.repository_name
  image_tag_mutability = "MUTABLE"

  encryption_configuration {
    encryption_type = "AES256"
  }

  # ライフサイクルポリシー例（不要なら削除可）
  lifecycle_policy {
    policy = jsonencode({
      rules = [{
        rulePriority = 1
        description  = "Keep only last 10 images"
        selection = {
          tagStatus = "any"
          countType = "imageCountMoreThan"
          countNumber = 10
        }
        action = { type = "expire" }
      }]
    })
  }
}
