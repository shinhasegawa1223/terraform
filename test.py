# settings.py の先頭に置く
import os
import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError
from functools import lru_cache
import logging

logger = logging.getLogger(__name__)

# ───────────────
# ※ローカルでアクセスキーを使う場合（本番は IAM ロールを使うので不要）：
# 環境変数で渡す方法の例（例: .env ファイルや shell でエクスポート）
# export AWS_ACCESS_KEY_ID=あなたのアクセスキー
# export AWS_SECRET_ACCESS_KEY=あなたのシークレット
# export AWS_DEFAULT_REGION=ap-northeast-1
# export USE_SSM=true             # SSM を使いたいとき（デフォルト true）
# ───────────────

# 取得したい Parameter Store のマッピング
PARAMS = {
    "API_URL": "/test/api_url",
    "S3_BUCKET": "/test/s3_bukket",
}

@lru_cache(maxsize=1)
def _fetch_ssm_params(names: dict[str, str]) -> dict[str, str]:
    """SSM から値を取得（失敗しても例外を投げる）"""
    client = boto3.client(
        "ssm",
        config=Config(retries={"max_attempts": 2, "mode": "standard"})
    )
    out: dict[str, str] = {}
    for env_key, param_name in names.items():
        resp = client.get_parameter(Name=param_name, WithDecryption=True)
        out[env_key] = resp["Parameter"]["Value"]
    return out

def load_ssm_if_enabled():
    """
    環境変数が既にあればそれを優先。
    USE_SSM が "true" のときだけ SSM から取りに行く。
    失敗しても既存 env を壊さず継続。
    """
    if os.environ.get("USE_SSM", "true").lower() != "true":
        logger.debug("SSM を使わない設定なので既存の環境変数を使う")
        return

    try:
        fetched = _fetch_ssm_params(PARAMS)
    except (ClientError, BotoCoreError) as e:
        logger.warning("SSM 取得失敗、既存 env を使う: %s", e)
        return
    except Exception as e:
        logger.error("予期しないエラーで SSM 取得失敗: %s", e)
        return

    for key, val in fetched.items():
        if os.environ.get(key) in (None, ""):
            os.environ[key] = val
            logger.debug("SSM から %s を設定", key)
        else:
            logger.debug("既存の %s を保持", key)

# 実行（最初に一度だけ）
load_ssm_if_enabled()

# 以降普通に使う
API_URL = os.environ.get("API_URL")
S3_BUCKET = os.environ.get("S3_BUCKET")
