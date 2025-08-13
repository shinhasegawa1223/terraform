了解です。**MFA（SMS/SOFTWARE TOKEN）関連は削除**し、**環境変数は `settings.py`**、**ログイン/ログアウト等は `user/api.py`** にまとめた最小構成を用意しました。
（前提：Cognito App client で「**Enable username password auth for admin APIs**」を有効化）

---

# settings.py（環境変数の読み込み）

```python
# settings.py
import os

# ... 既存設定 ...

# ===== Cognito settings =====
AWS_REGION = os.getenv("AWS_REGION", "ap-northeast-1")

COGNITO_USER_POOL_ID = os.getenv("COGNITO_USER_POOL_ID")  # 例: ap-northeast-1_XXXXXXX
COGNITO_APP_CLIENT_ID = os.getenv("COGNITO_APP_CLIENT_ID")
# ※ サーバー側実装では client secret なしの App client を推奨（Refresh が楽）
COGNITO_APP_CLIENT_SECRET = os.getenv("COGNITO_APP_CLIENT_SECRET", "")

# 起動時に最低限のチェック（本番は assert を外してもOK）
assert COGNITO_USER_POOL_ID, "COGNITO_USER_POOL_ID is required"
assert COGNITO_APP_CLIENT_ID, "COGNITO_APP_CLIENT_ID is required"
```

.env 例：

```
AWS_REGION=ap-northeast-1
COGNITO_USER_POOL_ID=ap-northeast-1_XXXXXXX
COGNITO_APP_CLIENT_ID=xxxxxxxxxxxxxxxxxxxxxx
# COGNITO_APP_CLIENT_SECRET=yyyyyyyyyyyyyyyyy   # 使うなら定義
```

---

# user/api.py（ログイン/新 PW/リフレッシュ/ログアウト）

```python
# user/api.py
import base64
import hmac
import hashlib
from typing import Optional, Literal

import boto3
from ninja import Router, Schema
from django.conf import settings
from django.http import HttpRequest

router = Router(tags=["user"])

cognito = boto3.client("cognito-idp", region_name=settings.AWS_REGION)

# ===== Schemas =====
class LoginIn(Schema):
    email: str
    password: str

class LoginOut(Schema):
    access_token: Optional[str] = None
    id_token: Optional[str] = None
    refresh_token: Optional[str] = None
    expires_in: Optional[int] = None
    token_type: Optional[str] = None
    # 初回PW変更チャレンジのみ残す（MFAは削除）
    challenge: Optional[Literal["NEW_PASSWORD_REQUIRED"]] = None
    session: Optional[str] = None

class NewPasswordIn(Schema):
    email: str
    new_password: str
    session: str  # /login で返した session

class RefreshIn(Schema):
    refresh_token: str
    # Client secret を使っている場合のみ必須（SECRET_HASH の計算に使用）
    username: Optional[str] = None

class SimpleOK(Schema):
    ok: bool


# ===== Helpers =====
def _secret_hash(username: str) -> Optional[str]:
    """Client secret を使っている場合のみ必要"""
    secret = settings.COGNITO_APP_CLIENT_SECRET
    if not secret:
        return None
    msg = (username + settings.COGNITO_APP_CLIENT_ID).encode("utf-8")
    digest = hmac.new(secret.encode("utf-8"), msg, hashlib.sha256).digest()
    return base64.b64encode(digest).decode()


def _tokens_from_result(result: dict) -> LoginOut:
    ar = result.get("AuthenticationResult", {})
    return LoginOut(
        access_token=ar.get("AccessToken"),
        id_token=ar.get("IdToken"),
        refresh_token=ar.get("RefreshToken"),
        expires_in=ar.get("ExpiresIn"),
        token_type=ar.get("TokenType"),
    )


# ===== Endpoints =====
@router.post("/login", response={200: LoginOut, 400: dict})
def login(request: HttpRequest, payload: LoginIn):
    """
    メール + パスワードで Cognito ログイン（ADMIN_NO_SRP_AUTH）
    App client 設定で「Enable username password auth for admin APIs」を有効化しておくこと。
    """
    params = {
        "AuthFlow": "ADMIN_NO_SRP_AUTH",
        "UserPoolId": settings.COGNITO_USER_POOL_ID,
        "ClientId": settings.COGNITO_APP_CLIENT_ID,
        "AuthParameters": {
            "USERNAME": payload.email,
            "PASSWORD": payload.password,
        },
    }
    sh = _secret_hash(payload.email)
    if sh:
        params["AuthParameters"]["SECRET_HASH"] = sh

    try:
        res = cognito.admin_initiate_auth(**params)

        # 成功（トークン発行）
        if "AuthenticationResult" in res:
            return 200, _tokens_from_result(res)

        # 初回パスワード変更のみ許容
        if res.get("ChallengeName") == "NEW_PASSWORD_REQUIRED":
            return 200, LoginOut(challenge="NEW_PASSWORD_REQUIRED", session=res["Session"])

        return 400, {"message": f"Unsupported challenge: {res.get('ChallengeName')}"}

    except cognito.exceptions.NotAuthorizedException:
        return 400, {"message": "Invalid email or password"}
    except cognito.exceptions.UserNotFoundException:
        return 400, {"message": "User not found"}
    except Exception as e:
        return 400, {"message": f"Login failed: {e}"}


@router.post("/new-password", response={200: LoginOut, 400: dict})
def new_password(request: HttpRequest, payload: NewPasswordIn):
    """
    NEW_PASSWORD_REQUIRED 応答
    """
    args = {
        "UserPoolId": settings.COGNITO_USER_POOL_ID,
        "ClientId": settings.COGNITO_APP_CLIENT_ID,
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


@router.post("/refresh", response={200: LoginOut, 400: dict})
def refresh(request: HttpRequest, payload: RefreshIn):
    """
    Refresh Token で再発行（REFRESH_TOKEN_AUTH）
    - client secret なし: InitiateAuth で OK（USERNAME 不要）
    - client secret あり: SECRET_HASH が必要 → username を受け取り必須化
    """
    using_secret = bool(settings.COGNITO_APP_CLIENT_SECRET)
    auth_params = {"REFRESH_TOKEN": payload.refresh_token}

    if using_secret:
        if not payload.username:
            return 400, {"message": "username is required when client secret is enabled"}
        sh = _secret_hash(payload.username)
        auth_params["SECRET_HASH"] = sh

        # server-side は admin API でも良い
        try:
            res = cognito.admin_initiate_auth(
                UserPoolId=settings.COGNITO_USER_POOL_ID,
                ClientId=settings.COGNITO_APP_CLIENT_ID,
                AuthFlow="REFRESH_TOKEN_AUTH",
                AuthParameters=auth_params,
            )
        except Exception as e:
            return 400, {"message": f"Refresh error: {e}"}
    else:
        try:
            res = cognito.initiate_auth(
                ClientId=settings.COGNITO_APP_CLIENT_ID,
                AuthFlow="REFRESH_TOKEN_AUTH",
                AuthParameters=auth_params,
            )
        except Exception as e:
            return 400, {"message": f"Refresh error: {e}"}

    if "AuthenticationResult" in res:
        return 200, _tokens_from_result(res)
    return 400, {"message": "Could not refresh token"}


@router.post("/logout", response={200: SimpleOK, 400: dict})
def logout(request: HttpRequest):
    """
    ログアウト（グローバルサインアウト）
    - Authorization: Bearer <AccessToken> を推奨
    """
    auth = request.headers.get("Authorization") or request.headers.get("authorization")
    if not auth or not auth.lower().startswith("bearer "):
        return 400, {"message": "Missing Authorization Bearer token"}

    access_token = auth.split(" ", 1)[1].strip()
    try:
        cognito.global_sign_out(AccessToken=access_token)
        return 200, SimpleOK(ok=True)
    except Exception as e:
        return 400, {"message": f"Logout error: {e}"}
```

---

# ルーティング（例）

```python
# project/api.py（任意の場所）
from ninja import NinjaAPI
from user.api import router as user_router

api = NinjaAPI()
api.add_router("/user", user_router)
```

```python
# project/urls.py
from django.urls import path
from .api import api

urlpatterns = [
    path("api/", api.urls),
]
```

---

## 使い方（例）

- **ログイン**

  ```
  POST /api/user/login
  {"email":"foo@example.com","password":"YourPassw0rd!"}
  → 200 { access_token, id_token, refresh_token, ... }
  → 200 { challenge:"NEW_PASSWORD_REQUIRED", session:"..." }
  ```

- **初回 PW 変更**

  ```
  POST /api/user/new-password
  {"email":"foo@example.com","new_password":"NewPassw0rd!","session":"<from login>"}
  → 200 { access_token, id_token, ... }
  ```

- **リフレッシュ**

  ```
  # client secret なし
  POST /api/user/refresh
  {"refresh_token":"<refresh>"} → 200 { access_token, ... }

  # client secret あり（username 必須）
  POST /api/user/refresh
  {"refresh_token":"<refresh>","username":"foo@example.com"}
  ```

- **ログアウト**

  ```
  POST /api/user/logout
  Authorization: Bearer <AccessToken>
  → 200 {"ok": true}
  ```

---

### 補足（ハマりがちポイント）

- **AdminInitiateAuth が失敗** → App client で「Enable username password auth for admin APIs」有効化。
- **ECS で Null になる** → **タスクロール**に `cognito-idp:*Auth*`, `GlobalSignOut`, `GetUser` など付与。
- **client secret 利用時の Refresh** → `SECRET_HASH` に **username** が必要。面倒なら**secret なしの App client を別途用意**するのが運用ラク。

必要なら、**ID/Access トークンの検証（JWKS）依存関数**や、**Cookie への格納**もすぐ足せます。
