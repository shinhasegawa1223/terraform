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
