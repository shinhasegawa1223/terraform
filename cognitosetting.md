了解！**Django + Ninja API**で、**Cognito に email / password でログイン**する最小構成を示します。
（サーバー側から呼ぶので、\*\*AdminInitiateAuth（ADMIN_NO_SRP_AUTH）\*\*を使うのが一番シンプル。これを使うには _アプリクライアント側で「Enable username password auth for admin APIs」_ を有効にしておきます。）

---

## 1) 事前準備（超要点）

- Cognito User Pool の App client:

  - 「**Enable username password auth for admin APIs**」をオン（= ADMIN_NO_SRP_AUTH が使える）
  - （任意）Client secret を発行している場合は後述の `SECRET_HASH` 計算が必要

- 環境変数（例）

  - `AWS_REGION=ap-northeast-1`
  - `COGNITO_USER_POOL_ID=ap-northeast-1_XXXXXXX`
  - `COGNITO_APP_CLIENT_ID=xxxxxxxxxxxxxxxxxxxxxx`
  - `COGNITO_APP_CLIENT_SECRET=yyyyyyyyyyyyyyyyyyyy`（_secret を使う場合のみ_）

- 実行環境の IAM（ECS 等の**タスクロール**）に最低限の権限

  ```json
  {
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Allow",
        "Action": [
          "cognito-idp:AdminInitiateAuth",
          "cognito-idp:AdminRespondToAuthChallenge",
          "cognito-idp:InitiateAuth",
          "cognito-idp:RespondToAuthChallenge",
          "cognito-idp:RevokeToken",
          "cognito-idp:GlobalSignOut",
          "cognito-idp:GetUser"
        ],
        "Resource": "*"
      }
    ]
  }
  ```

---

## 2) 必要パッケージ

```bash
pip install django-ninja boto3 python-jose[cryptography] httpx
```

---

## 3) 実装（Django Ninja ルーター）

> これだけで「メール＋パスワードでログイン → トークン返却」、
> 追加で「NEW_PASSWORD_REQUIRED（初回 PW 変更）」「MFA」もハンドリング可。

```python
# app/api/auth/router.py
import base64, hmac, hashlib, os, time
from typing import Optional, Literal

import boto3
from django.http import JsonResponse
from ninja import Router, Schema

router = Router(tags=["auth"])

AWS_REGION = os.environ["AWS_REGION"]
USER_POOL_ID = os.environ["COGNITO_USER_POOL_ID"]
CLIENT_ID = os.environ["COGNITO_APP_CLIENT_ID"]
CLIENT_SECRET = os.environ.get("COGNITO_APP_CLIENT_SECRET")  # 任意

cognito = boto3.client("cognito-idp", region_name=AWS_REGION)


# ==== Schemas ====
class LoginIn(Schema):
    email: str
    password: str


class LoginOut(Schema):
    access_token: Optional[str] = None
    id_token: Optional[str] = None
    refresh_token: Optional[str] = None
    expires_in: Optional[int] = None
    token_type: Optional[str] = None
    # チャレンジ時
    challenge: Optional[Literal["NEW_PASSWORD_REQUIRED", "SMS_MFA", "SOFTWARE_TOKEN_MFA"]] = None
    session: Optional[str] = None  # 次の呼び出しに必要


class NewPasswordIn(Schema):
    email: str
    new_password: str
    session: str  # login で返した session をクライアント保持


class MfaIn(Schema):
    email: str
    code: str
    session: str


class RefreshIn(Schema):
    refresh_token: str


class SimpleOK(Schema):
    ok: bool


# ==== Helpers ====
def _secret_hash(username: str) -> Optional[str]:
    """
    Client secret を使っている場合のみ必要。
    SECRET_HASH = Base64( HMAC_SHA256( client_secret, username + client_id ) )
    """
    if not CLIENT_SECRET:
        return None
    digest = hmac.new(
        CLIENT_SECRET.encode("utf-8"),
        (username + CLIENT_ID).encode("utf-8"),
        hashlib.sha256,
    ).digest()
    return base64.b64encode(digest).decode()


def _tokens_from_result(result: dict) -> LoginOut:
    auth_result = result.get("AuthenticationResult", {})
    return LoginOut(
        access_token=auth_result.get("AccessToken"),
        id_token=auth_result.get("IdToken"),
        refresh_token=auth_result.get("RefreshToken"),
        expires_in=auth_result.get("ExpiresIn"),
        token_type=auth_result.get("TokenType"),
    )


# ==== Endpoints ====

@router.post("/login", response={200: LoginOut, 400: dict})
def login(request, payload: LoginIn):
    """
    メール + パスワードで Cognito へログイン（ADMIN_NO_SRP_AUTH）。
    App Client 側で「Enable username password auth for admin APIs」を有効化しておくこと。
    """
    params = {
        "AuthFlow": "ADMIN_NO_SRP_AUTH",
        "UserPoolId": USER_POOL_ID,
        "ClientId": CLIENT_ID,
        "AuthParameters": {
            "USERNAME": payload.email,
            "PASSWORD": payload.password,
        },
    }
    sh = _secret_hash(payload.email)
    if sh:
        params["AuthParameters"]["SECRET_HASH"] = sh

    try:
        result = cognito.admin_initiate_auth(**params)

        # そのまま成功
        if "AuthenticationResult" in result:
            return 200, _tokens_from_result(result)

        # チャレンジ（初回PW変更 or MFA）
        challenge_name = result.get("ChallengeName")
        if challenge_name in ("NEW_PASSWORD_REQUIRED", "SMS_MFA", "SOFTWARE_TOKEN_MFA"):
            return 200, LoginOut(challenge=challenge_name, session=result["Session"])

        # 想定外のチャレンジ
        return 400, {"message": f"Unsupported challenge: {challenge_name}"}

    except cognito.exceptions.NotAuthorizedException as e:
        return 400, {"message": "Invalid email or password"}
    except cognito.exceptions.UserNotFoundException:
        return 400, {"message": "User not found"}
    except Exception as e:
        return 400, {"message": f"Login failed: {e}"}


@router.post("/new-password", response={200: LoginOut, 400: dict})
def respond_new_password(request, payload: NewPasswordIn):
    """
    NEW_PASSWORD_REQUIRED チャレンジ応答
    """
    args = {
        "UserPoolId": USER_POOL_ID,
        "ClientId": CLIENT_ID,
        "ChallengeName": "NEW_PASSWORD_REQUIRED",
        "Session": payload.session,
        "ChallengeResponses": {
            "USERNAME": payload.email,
            "NEW_PASSWORD": payload.new_password,
        },
    }
    sh = _secret_hash(payload.email)
    if sh:
        args["ChallengeResponses"]["SECRET_HASH"] = sh

    try:
        res = cognito.admin_respond_to_auth_challenge(**args)
        if "AuthenticationResult" in res:
            return 200, _tokens_from_result(res)
        return 400, {"message": "Failed to complete challenge"}
    except Exception as e:
        return 400, {"message": f"Challenge error: {e}"}


@router.post("/mfa", response={200: LoginOut, 400: dict})
def mfa_verify(request, payload: MfaIn):
    """
    SMS_MFA / SOFTWARE_TOKEN_MFA チャレンジ応答
    """
    args = {
        "UserPoolId": USER_POOL_ID,
        "ClientId": CLIENT_ID,
        "ChallengeName": "SMS_MFA",  # SOFTWARE_TOKEN_MFA の場合は適宜置換
        "Session": payload.session,
        "ChallengeResponses": {
            "USERNAME": payload.email,
            "SMS_MFA_CODE": payload.code,  # 仮に SMS_MFA の例
        },
    }
    sh = _secret_hash(payload.email)
    if sh:
        args["ChallengeResponses"]["SECRET_HASH"] = sh

    try:
        res = cognito.admin_respond_to_auth_challenge(**args)
        if "AuthenticationResult" in res:
            return 200, _tokens_from_result(res)
        return 400, {"message": "Failed to complete MFA"}
    except Exception as e:
        return 400, {"message": f"MFA error: {e}"}


@router.post("/refresh", response={200: LoginOut, 400: dict})
def refresh(request, payload: RefreshIn):
    """
    リフレッシュトークンで再発行
    """
    auth_params = {"REFRESH_TOKEN": payload.refresh_token}
    sh = _secret_hash("dummy")  # SECRET_HASH が必要なクライアントの場合は USERNAME が要る仕様だが、
                                # リフレッシュでは未使用なのでダミーにする or 省略（secretなし推奨）
    try:
        if CLIENT_SECRET:
            res = cognito.admin_initiate_auth(
                UserPoolId=USER_POOL_ID,
                ClientId=CLIENT_ID,
                AuthFlow="REFRESH_TOKEN_AUTH",
                AuthParameters=auth_params,
            )
        else:
            # secret なしなら通常の InitiateAuth でも可
            res = cognito.initiate_auth(
                ClientId=CLIENT_ID,
                AuthFlow="REFRESH_TOKEN_AUTH",
                AuthParameters=auth_params,
            )
        if "AuthenticationResult" in res:
            return 200, _tokens_from_result(res)
        return 400, {"message": "Could not refresh token"}
    except Exception as e:
        return 400, {"message": f"Refresh error: {e}"}


@router.post("/logout", response={200: SimpleOK, 400: dict})
def logout(request, access_token: str):
    """
    ログアウト（アクセストークンを無効化）
    """
    try:
        cognito.global_sign_out(AccessToken=access_token)
        return 200, SimpleOK(ok=True)
    except Exception as e:
        return 400, {"message": f"Logout error: {e}"}
```

**ルーター登録**

```python
# app/api/__init__.py など
from ninja import NinjaAPI
from app.api.auth.router import router as auth_router

api = NinjaAPI()
api.add_router("/auth", auth_router)
```

---

## 4) よくある詰まりポイント（ここ大事）

- **AdminInitiateAuth がエラー**
  → App client で「Enable username password auth for admin APIs」を有効化したか？
  → タスク**実行ロール**ではなく、**タスクロール**に cognito-idp 権限を付けたか？
- **Client secret を使う場合**
  → `SECRET_HASH` を正しく計算し、`USERNAME + CLIENT_ID` で HMAC-SHA256、Base64 エンコード。
- **初回サインインで NEW_PASSWORD_REQUIRED**
  → `/auth/new-password` に `session` と `new_password` を渡して完了。
- **MFA の種類**
  → SMS なら `SMS_MFA`、Authenticator アプリなら `SOFTWARE_TOKEN_MFA` を指定して `/auth/mfa` で応答。
- **リフレッシュ**
  → `REFRESH_TOKEN_AUTH` を使う。Client secret ありの構成は面倒になりがちなので、**サーバー側なら client secret なし**の App client を用意して分離するのが運用しやすいです（漏洩リスク/実装簡素化の両面）。

---

## 5) 追加（保護用のトークン検証）

保護エンドポイントでは、`Authorization: Bearer <id/access token>` を受け取り、
`https://cognito-idp.{region}.amazonaws.com/{userPoolId}/.well-known/jwks.json` を使って署名検証（`python-jose`）してください。
必要ならその検証ミドルウェア（依存関数）も用意します。

---

必要なら、**Cookie（HttpOnly/SameSite）にトークンを載せる実装**や、**Hosted UI/OAuth2 フロー**版、**Next.js 側との連携コード**もこの流れで用意します。どこまで組み込みますか？
