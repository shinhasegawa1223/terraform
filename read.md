セットアップ手順の概要
上記 Terraform を適用して、

repository_url （例: 123456789012.dkr.ecr.ap-northeast-1.amazonaws.com/my-backend）

iam_role_arn
を取得

GitHub リポジトリの Secrets に登録

AWS_REGION → Terraform の aws_region と合わせる

AWS_ROLE_TO_ASSUME → Terraform 出力の iam_role_arn

ECR_REPOSITORY_NAME → Terraform で指定した repository_name

push-backend-to-ecr.yml を .github/workflows/ にコミット。

backend/ 以下のコードを main ブランチにプッシュすると、自動で Docker イメージがビルドされ ECR にプッシュされます。

---

GitHub Actions で使う Secrets は以下の３つを登録すれば足ります。

AWS_ROLE_TO_ASSUME

Terraform の output "iam_role_arn" で取得できる IAM ロールの ARN

例：arn:aws:iam::123456789012:role/github-actions-ecr-push-role

AWS_REGION

Terraform の var.aws_region と同じ値

例：ap-northeast-1

ECR_REPOSITORY_NAME

Terraform の var.repository_name と同じリポジトリ名

例：my-backend
