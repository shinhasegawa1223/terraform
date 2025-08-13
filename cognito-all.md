# Django Ninja × Amazon Cognito（email/password ログイン & API 認証）

> MFA（SMS/ソフトウェアトークン）は **未対応/削除**。初回サインインの `NEW_PASSWORD_REQUIRED` のみ対応。以降の API 認証は **JWT（Access/Id Token）検証**で行います。

---

## ディレクトリ構成

```
django-cognito-sample/
├─ manage.py
├─ requirements.txt
├─ .env.example
├─ config/
│  ├─ __init__.py
│  ├─ settings.py
│  ├─ urls.py
│  ├─ api.py
│  ├─ asgi.py
│  └─ wsgi.py
├─ user/
│  ├─ __init__.py
│  ├─ api.py         # ログイン/新PW/リフレッシュ/ログアウト
│  └─ auth.py        # JWT 検証（JWKS キャッシュ）＋ Ninja 認証クラス
└─ item/
   ├─ __init__.py
   └─ api.py         # 認証が必要な保護APIの例
```

---

## セットアップ

### `requirements.txt`

```
Django>=4.2,<5.1
django-ninja>=1.3.0
boto3>=1.34
python-jose[cryptography]>=3.3.0
httpx>=0.27
# 必要に応じて CORS
django-cors-headers>=4.4
```

### `.env.example`

```
# Django
SECRET_KEY=change-me
DEBUG=1
ALLOWED_HOSTS=*

# Cognito
AWS_REGION=ap-northeast-1
COGNITO_USER_POOL_ID=ap-northeast-1_XXXXXXXXX
COGNITO_APP_CLIENT_ID=yyyyyyyyyyyyyyyyyyyyyy
# クライアントシークレットを使う場合のみ（推奨は未設定＝空）
# COGNITO_APP_CLIENT_SECRET=zzzzzzzzzzzzzzzzzzzzzz

# 検証でどちらのトークンを優先するか（"access" or "id"）
COGNITO_PREFERRED_TOKEN_USE=access
```

---

## `manage.py`

```python
#!/usr/bin/env python
import os
import sys

def main():
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")
    from django.core.management import execute_from_command_line
    execute_from_command_line(sys.argv)

if __name__ == "__main__":
    main()
```

---

## `config/__init__.py`

```python
# empty
```

---

## `config/settings.py`

```python
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

SECRET_KEY = os.getenv("SECRET_KEY", "change-me")
DEBUG = os.getenv("DEBUG", "0") == "1"
ALLOWED_HOSTS = os.getenv("ALLOWED_HOSTS", "*").split(",")

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "ninja",
    # 任意: CORS を使う場合
    "corsheaders",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    # 任意: CORS
    "corsheaders.middleware.CorsMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "config.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "config.wsgi.application"
ASGI_APPLICATION = "config.asgi.application"

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": BASE_DIR / "db.sqlite3",
    }
}

LANGUAGE_CODE = "ja"
TIME_ZONE = "Asia/Tokyo"
USE_I18N = True
USE_TZ = True

STATIC_URL = "static/"
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# ===== Cognito =====
AWS_REGION = os.getenv("AWS_REGION", "ap-northeast-1")
COGNITO_USER_POOL_ID = os.getenv("COGNITO_USER_POOL_ID")
COGNITO_APP_CLIENT_ID = os.getenv("COGNITO_APP_CLIENT_ID")
COGNITO_APP_CLIENT_SECRET = os.getenv("COGNITO_APP_CLIENT_SECRET", "")

assert COGNITO_USER_POOL_ID, "COGNITO_USER_POOL_ID is required"
assert COGNITO_APP_CLIENT_ID, "COGNITO_APP_CLIENT_ID is required"

COGNITO_ISSUER = f"https://cognito-idp.{AWS_REGION}.amazonaws.com/{COGNITO_USER_POOL_ID}"
COGNITO_JWKS_URL = f"{COGNITO_ISSUER}/.well-known/jwks.json"
COGNITO_PREFERRED_TOKEN_USE = os.getenv("COGNITO_PREFERRED_TOKEN_USE", "access")  # "access" or "id"

# ===== CORS (任意) =====
CORS_ALLOW_ALL_ORIGINS = True if os.getenv("DEBUG", "0") == "1" else False
CORS_ALLOWED_ORIGINS = os.getenv("CORS_ALLOWED_ORIGINS", "").split(",") if not CORS_ALLOW_ALL_ORIGINS else []
```

---

## `config/api.py`

```python
from ninja import NinjaAPI
from user.api import router as user_router
from item.api import router as item_router

api = NinjaAPI(title="Django Ninja × Cognito")
api.add_router("/user", user_router)
api.add_router("/items", item_router)
```

---

## `config/urls.py`

```python
from django.urls import path
from .api import api

urlpatterns = [
    path("api/", api.urls),
]
```

---

## `config/asgi.py`

```python
import os
from django.core.asgi import get_asgi_application

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")
application = get_asgi_application()
```

---

## `config/wsgi.py`

```python
import os
from django.core.wsgi import get_wsgi_application

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")
application = get_wsgi_application()
```

---

## `user/api.py`（ログイン/新 PW/リフレッシュ/ログアウト）

```python
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
    # 初回PW変更のみ
    challenge: Optional[Literal["NEW_PASSWORD_REQUIRED"]] = None
    session: Optional[str] = None

class NewPasswordIn(Schema):
    email: str
    new_password: str
    session: str

class RefreshIn(Schema):
    refresh_token: str
    username: Optional[str] = None  # client secret 利用時のみ必須

class SimpleOK(Schema):
    ok: bool

# ===== Helpers =====

def _secret_hash(username: str) -> Optional[str]:
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
    """メール+パスワードで Cognito ログイン（ADMIN_NO_SRP_AUTH）。
    App client で「Enable username password auth for admin APIs」を有効化しておくこと。
    返却される session は **NEW_PASSWORD_REQUIRED** 用の一時トークンであり、以後のAPI認証には使用しません。
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
        if "AuthenticationResult" in res:
            return 200, _tokens_from_result(res)
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
    """NEW_PASSWORD_REQUIRED 応答"""
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
    """Refresh Token で再発行（REFRESH_TOKEN_AUTH）"""
    using_secret = bool(settings.COGNITO_APP_CLIENT_SECRET)
    auth_params = {"REFRESH_TOKEN": payload.refresh_token}

    if using_secret:
        if not payload.username:
            return 400, {"message": "username is required when client secret is enabled"}
        sh = _secret_hash(payload.username)
        auth_params["SECRET_HASH"] = sh
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
    """グローバルサインアウト。Authorization: Bearer <AccessToken> 必須。"""
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

## `user/auth.py`（JWT 検証 + Ninja 認証クラス）

```python
import time
import httpx
from typing import Dict, Any, Optional

from django.conf import settings
from ninja.errors import HttpError
from ninja.security import HttpBearer

from jose import jwt
from jose.utils import base64url_decode
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# ------- JWKS キャッシュ -------
_JWKS_CACHE: Dict[str, Any] = {"keys": None, "exp": 0}  # exp: epoch sec


def _fetch_jwks() -> list[dict]:
    r = httpx.get(settings.COGNITO_JWKS_URL, timeout=5)
    r.raise_for_status()
    return r.json()["keys"]


def _get_jwks() -> list[dict]:
    now = time.time()
    if not _JWKS_CACHE["keys"] or now >= _JWKS_CACHE["exp"]:
        _JWKS_CACHE["keys"] = _fetch_jwks()
        _JWKS_CACHE["exp"] = now + 60 * 60  # 1h キャッシュ
    return _JWKS_CACHE["keys"]


def _rsa_pem_from_jwk(jwk: dict) -> bytes:
    n = int.from_bytes(base64url_decode(jwk["n"].encode()), "big")
    e = int.from_bytes(base64url_decode(jwk["e"].encode()), "big")
    pub_numbers = rsa.RSAPublicNumbers(e, n)
    pub_key = pub_numbers.public_key()
    return pub_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def verify_cognito_jwt(token: str, token_use: str = "access") -> dict:
    """Cognito の JWT を検証してクレームを返す。token_use: "access" or "id"""
    unverified_header = jwt.get_unverified_header(token)
    kid = unverified_header.get("kid")
    if not kid:
        raise HttpError(401, "Invalid token header")

    jwks = _get_jwks()
    jwk = next((k for k in jwks if k["kid"] == kid), None)
    if jwk is None:
        _JWKS_CACHE["exp"] = 0
        jwks = _get_jwks()
        jwk = next((k for k in jwks if k["kid"] == kid), None)
        if jwk is None:
            raise HttpError(401, "Unknown signing key")

    pem = _rsa_pem_from_jwk(jwk)

    claims = jwt.decode(
        token,
        pem,
        algorithms=["RS256"],
        issuer=settings.COGNITO_ISSUER,
        options={"verify_aud": False},  # aud は後で手動チェック
    )

    tu = claims.get("token_use")
    if tu != token_use:
        raise HttpError(401, f"Wrong token use: expected {token_use}, got {tu}")

    client_id = settings.COGNITO_APP_CLIENT_ID
    if token_use == "id":
        aud = claims.get("aud")
        if aud != client_id:
            raise HttpError(401, "Invalid audience")
    else:  # access
        cid = claims.get("client_id")
        if cid != client_id:
            raise HttpError(401, "Invalid client_id")

    return claims


class CognitoAuth(HttpBearer):
    """Ninja 用 Bearer 認証。
    使い方:  @router.get("/...", auth=CognitoAuth())  # Access Token を検証
             @router.get("/...", auth=CognitoAuth("id"))  # Id Token を検証
    """
    def __init__(self, token_use: Optional[str] = None):
        self.token_use = token_use or settings.COGNITO_PREFERRED_TOKEN_USE

    def authenticate(self, request, token: str) -> dict:
        try:
            claims = verify_cognito_jwt(token, token_use=self.token_use)
            return {
                "sub": claims.get("sub"),
                "username": claims.get("cognito:username") or claims.get("username"),
                "email": claims.get("email"),
                "scope": claims.get("scope"),
                "claims": claims,
            }
        except HttpError:
            raise
        except Exception:
            raise HttpError(401, "Unauthorized")
```

---

## `item/api.py`（保護 API の例）

```python
from ninja import Router, Schema
from django.http import HttpRequest
from user.auth import CognitoAuth

router = Router(tags=["items"])

class ItemOut(Schema):
    id: int
    name: str
    owner_sub: str

@router.get("/", response=list[ItemOut], auth=CognitoAuth())
def list_items(request: HttpRequest):
    user = request.auth  # {sub, username, email, scope, claims}
    # 実際は DB フィルタなどに user["sub"] を利用
    return [
        ItemOut(id=1, name="sample-1", owner_sub=user["sub"]),
        ItemOut(id=2, name="sample-2", owner_sub=user["sub"]),
    ]

@router.get("/me", auth=CognitoAuth())
def me(request: HttpRequest):
    return {
        "sub": request.auth["sub"],
        "username": request.auth["username"],
        "email": request.auth["email"],
        "token_use": request.auth["claims"].get("token_use"),
    }
```

---

## 実行方法

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env  # 値を埋める
python manage.py migrate
python manage.py runserver 0.0.0.0:8000
```

### API ドキュメント（Swagger UI）

- `http://localhost:8000/api/docs`

---

## 動作確認（例）

### 1) ログイン

```bash
curl -s http://localhost:8000/api/user/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"foo@example.com","password":"YourPassw0rd!"}'
```

- 成功: `{ access_token, id_token, refresh_token, ... }`
- 初回 PW 変更: `{ challenge:"NEW_PASSWORD_REQUIRED", session:"..." }`

### 2) 初回 PW 変更

```bash
curl -s http://localhost:8000/api/user/new-password \
  -H 'Content-Type: application/json' \
  -d '{"email":"foo@example.com","new_password":"NewPassw0rd!","session":"<from login>"}'
```

### 3) 認証付き API 呼び出し

```bash
ACCESS="<AccessToken>"
curl -s http://localhost:8000/api/items/ -H "Authorization: Bearer $ACCESS"
```

### 4) リフレッシュ

```bash
curl -s http://localhost:8000/api/user/refresh \
  -H 'Content-Type: application/json' \
  -d '{"refresh_token":"<RefreshToken>"}'
```

> クライアントシークレット有効時は `{"refresh_token":"...","username":"foo@example.com"}`

### 5) ログアウト

```bash
curl -s -X POST http://localhost:8000/api/user/logout \
  -H "Authorization: Bearer $ACCESS"
```

---

## 補足メモ

- **session** は `NEW_PASSWORD_REQUIRED` 継続用です。以降の API 認証には **Access/Id Token** を使ってください。
- API の保護には **Access Token** 利用が一般的。Id Token を検証したい場合は `CognitoAuth("id")` を利用。
- ECS 等で実行する場合は **タスクロール**に `cognito-idp:AdminInitiateAuth`, `AdminRespondToAuthChallenge`, `InitiateAuth`, `RespondToAuthChallenge`, `GlobalSignOut`, `GetUser` 等を付与。
- App client 設定で **Enable username password auth for admin APIs** をオンにするのを忘れずに。

```diff
- MFA (SMS / SOFTWARE_TOKEN) 関連は本構成から削除済み
```
