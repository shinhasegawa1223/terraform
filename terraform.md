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
├─ item/
│  ├─ __init__.py
│  └─ api.py         # 認証＋テナント整合性チェック
└─ alert/
   ├─ __init__.py
   └─ api.py         # 認証＋テナント整合性チェック
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

````python
from ninja import NinjaAPI
from user.api import router as user_router
from item.api import router as item_router
from alert.api import router as alert_router

api = NinjaAPI(title="Django Ninja × Cognito")
api.add_router("/user", user_router)
api.add_router("/items", item_router)
api.add_router("/alerts", alert_router)
```python
from ninja import NinjaAPI
from user.api import router as user_router
from item.api import router as item_router

api = NinjaAPI(title="Django Ninja × Cognito")
api.add_router("/user", user_router)
api.add_router("/items", item_router)
````

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

テナントを追加したい場合は？

---

# マルチテナント対応（追加）

**目的**: 1 つの Cognito User Pool を使いながら、\*\*テナント（tenant）\*\*単位でアクセスを分離します。

- 既定では **HTTP ヘッダ **\`\` でテナントを受け取り、Cognito のトークンに含まれるテナント情報（任意）と**一致検証**します。
- 代替として **サブドメイン** や **JWT のカスタムクレーム（例: **\`\`**）** から解決することも可能です。

> 注: Cognito の **custom attributes** は通常 **ID トークン**に入ります。**Access Token だけ**でテナントをクレームから取りたい場合は外部照会（`GetUser`）か、API を **Id Token 基準**で保護する設計をご検討ください（本構成はヘッダ運用がデフォルト）。

---

## 1) 追加の環境変数

`.env.example` に追記:

```
# --- Multi-tenant ---
MULTI_TENANT_ENABLED=1
TENANT_MODE=header        # header | subdomain | claim
TENANT_HEADER=X-Tenant-Id # header モード時のヘッダ名
TENANT_STRICT=1           # ヘッダ/サブドメインとトークン側の不一致を 403 にする
TENANT_MAIN_DOMAIN=       # 例: app.example.com の場合 example.com を指定（subdomain モード用）
COGNITO_TENANT_CLAIM=custom:tenant_id  # claim モードで参照するクレーム名
```

---

## 2) `config/settings.py` 追記

```python
# 既存の末尾あたりに追記
MULTI_TENANT_ENABLED = os.getenv("MULTI_TENANT_ENABLED", "1") == "1"
TENANT_MODE = os.getenv("TENANT_MODE", "header")  # header | subdomain | claim
TENANT_HEADER = os.getenv("TENANT_HEADER", "X-Tenant-Id")
TENANT_STRICT = os.getenv("TENANT_STRICT", "1") == "1"
TENANT_MAIN_DOMAIN = os.getenv("TENANT_MAIN_DOMAIN", "")
COGNITO_TENANT_CLAIM = os.getenv("COGNITO_TENANT_CLAIM", "custom:tenant_id")
```

---

## 3) `user/auth.py`（テナント解決を追加した改訂版）

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
        options={"verify_aud": False},
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


# ---- テナント解決 ----

def _host_without_port(host: str) -> str:
    return host.split(":", 1)[0]


def _tenant_from_subdomain(host: str, main_domain: str) -> Optional[str]:
    h = _host_without_port(host or "")
    if not h:
        return None
    parts = h.split(".")
    if main_domain:
        # 末尾が main_domain の場合のみ先頭ラベルを tenant とする
        if h.endswith(main_domain) and len(parts) > len(main_domain.split(".")):
            return parts[0]
        return None
    # main_domain 指定なし: 3 ラベル以上なら先頭を tenant とみなす（例: tenant.api.local）
    return parts[0] if len(parts) >= 3 else None


def _resolve_tenant_id(request, claims) -> Optional[str]:
    if not settings.MULTI_TENANT_ENABLED:
        return None

    mode = settings.TENANT_MODE
    claim_name = settings.COGNITO_TENANT_CLAIM
    claim_tid = claims.get(claim_name)

    if mode == "header":
        tid = request.headers.get(settings.TENANT_HEADER)
        if settings.TENANT_STRICT and tid and claim_tid and tid != claim_tid:
            raise HttpError(403, "Tenant mismatch (header vs token)")
        return tid or claim_tid

    if mode == "subdomain":
        tid = _tenant_from_subdomain(request.get_host(), settings.TENANT_MAIN_DOMAIN)
        if settings.TENANT_STRICT and tid and claim_tid and tid != claim_tid:
            raise HttpError(403, "Tenant mismatch (subdomain vs token)")
        return tid or claim_tid

    if mode == "claim":
        return claim_tid

    raise HttpError(500, "Invalid TENANT_MODE")


class CognitoAuth(HttpBearer):
    """Ninja 用 Bearer 認証 + テナント解決。
    使い方:  @router.get("/...", auth=CognitoAuth())      # Access (既定)
             @router.get("/...", auth=CognitoAuth("id"))  # Id Token
    """
    def __init__(self, token_use: Optional[str] = None):
        self.token_use = token_use or settings.COGNITO_PREFERRED_TOKEN_USE

    def authenticate(self, request, token: str) -> dict:
        try:
            claims = verify_cognito_jwt(token, token_use=self.token_use)
            tenant_id = _resolve_tenant_id(request, claims)
            if settings.MULTI_TENANT_ENABLED and not tenant_id:
                # テナント必須運用のときは 400/403 を返す運用を推奨
                raise HttpError(400, "Tenant not provided")

            return {
                "sub": claims.get("sub"),
                "username": claims.get("cognito:username") or claims.get("username"),
                "email": claims.get("email"),
                "scope": claims.get("scope"),
                "tenant_id": tenant_id,
                "claims": claims,
            }
        except HttpError:
            raise
        except Exception:
            raise HttpError(401, "Unauthorized")
```

---

## 4) `item/api.py`（テナント対応の例）

```python
from ninja import Router, Schema
from django.http import HttpRequest
from user.auth import CognitoAuth

router = Router(tags=["items"])

class ItemOut(Schema):
    id: int
    name: str
    tenant_id: str

@router.get("/", response=list[ItemOut], auth=CognitoAuth())
def list_items(request: HttpRequest):
    user = request.auth
    tid = user.get("tenant_id") or "public"
    # 実際は DB 側で tenant_id=tid をフィルタしてください。
    return [
        ItemOut(id=1, name="sample-1", tenant_id=tid),
        ItemOut(id=2, name="sample-2", tenant_id=tid),
    ]

@router.get("/tenant", auth=CognitoAuth())
def current_tenant(request: HttpRequest):
    return {
        "tenant_id": request.auth.get("tenant_id"),
        "token_use": request.auth["claims"].get("token_use"),
        "mode": getattr(__import__("django.conf").conf.settings, "TENANT_MODE", None),
    }
```

---

## 5) フロントエンドの送信例（header モード）

```
GET /api/items/
Authorization: Bearer <AccessToken>
X-Tenant-Id: tenant_a
```

> **strict モード** (`TENANT_STRICT=1`) では、トークン側のクレーム（ある場合）と `X-Tenant-Id` の不一致は **403** になります。

---

## 6) 運用 Tips

- テナントを **JWT クレームで保証**したい場合は、`TENANT_MODE=claim` とし、ID トークンで API を保護（`COGNITO_PREFERRED_TOKEN_USE=id`）。
- **サブドメイン運用**（`TENANT_MODE=subdomain`）では `TENANT_MAIN_DOMAIN` を指定し、`{tenant}.api.example.com` → `tenant` を抽出します。
- DB を使う場合は、各モデルに `tenant_id` を持たせ、**必ずクエリで絞り込み**ましょう（ModelManager でデフォルトフィルタにするのが安全）。

---

## `alert/api.py`（JWT ＋テナント整合性チェック）

```python
from ninja import Router, Schema
from django.http import HttpRequest
from user.auth import CognitoAuth

router = Router(tags=["alerts"])

class AlertOut(Schema):
    id: int
    title: str
    tenant_id: str
    owner_sub: str

@router.get("/", response=list[AlertOut], auth=CognitoAuth())
def list_alerts(request: HttpRequest):
    user = request.auth  # {sub, username, email, scope, tenant_id, claims}
    tid = user.get("tenant_id") or "public"  # 必要なら strict モードで必須化
    sub = user["sub"]
    # 実際は DB を tenant_id=tid ＆ owner_sub=sub 等で絞り込む
    return [
        AlertOut(id=101, title="disk usage high", tenant_id=tid, owner_sub=sub),
        AlertOut(id=102, title="new login detected", tenant_id=tid, owner_sub=sub),
    ]

@router.get("/{alert_id}", response=AlertOut, auth=CognitoAuth())
def get_alert(request: HttpRequest, alert_id: int):
    user = request.auth
    tid = user.get("tenant_id") or "public"
    return AlertOut(id=alert_id, title=f"alert-{alert_id}", tenant_id=tid, owner_sub=user["sub"])
```

---

# Terraform（Cognito 構築）

**目的**: 本プロジェクト（Django Ninja × Cognito）のための **User Pool / App Clients / Hosted UI ドメイン** を Terraform で構築します。

- **サーバ用クライアント**（Admin API で email+password ログイン／SECRET なし推奨）
- **フロントエンド用クライアント**（Hosted UI + OAuth2 Code with PKCE、`callback_urls`/`logout_urls` 設定あり）
- **カスタム属性 `custom:tenant_id`** を user pool に定義（ID トークンに含められる）
- **MFA 無効**、**メール検証**、**パスワードポリシー** 設定

## ディレクトリ追加

```
django-cognito-sample/
└─ infra/
   └─ tf/
      ├─ provider.tf
      ├─ variables.tf
      ├─ locals.tf
      ├─ main.tf
      ├─ outputs.tf
      └─ terraform.tfvars.example
```

---

## `infra/tf/provider.tf`

```hcl
terraform {
  required_version = ">= 1.6.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.45"
    }
  }
}

provider "aws" {
  region = var.aws_region
}
```

---

## `infra/tf/variables.tf`

```hcl
variable "project_name" {
  type        = string
  description = "Prefix for Cognito resources"
}

variable "aws_region" {
  type        = string
  description = "AWS region"
  default     = "ap-northeast-1"
}

variable "domain_prefix" {
  type        = string
  description = "Cognito hosted UI domain prefix (unique in region). e.g. myapp-tenant"
}

variable "callback_urls" {
  type        = list(string)
  description = "Allowed OAuth2 callback URLs for the frontend client"
}

variable "logout_urls" {
  type        = list(string)
  description = "Allowed sign-out URLs for the frontend client"
}

variable "refresh_token_validity_days" {
  type        = number
  default     = 30
  description = "Refresh token validity (days)"
}

variable "access_token_validity_minutes" {
  type        = number
  default     = 60
  description = "Access token validity (minutes)"
}

variable "id_token_validity_minutes" {
  type        = number
  default     = 60
  description = "ID token validity (minutes)"
}

variable "generate_server_client_secret" {
  type        = bool
  default     = false
  description = "Whether to generate client secret for server app client (false recommended)"
}
```

---

## `infra/tf/locals.tf`

```hcl
locals {
  tags = {
    Project = var.project_name
    Stack   = "cognito"
  }
}
```

---

## `infra/tf/main.tf`

```hcl
# -----------------------------
# Cognito User Pool
# -----------------------------
resource "aws_cognito_user_pool" "this" {
  name = "${var.project_name}-user-pool"

  mfa_configuration          = "OFF"
  auto_verified_attributes   = ["email"]
  username_attributes        = ["email"]   # ログインIDに email を使用
  verification_message_template {
    default_email_option = "CONFIRM_WITH_CODE"
  }

  password_policy {
    minimum_length                   = 8
    require_lowercase                = true
    require_numbers                  = true
    require_symbols                  = true
    require_uppercase                = true
    temporary_password_validity_days = 7
  }

  # custom attribute for tenant
  schema {
    name                = "tenant_id"
    attribute_data_type = "String"
    mutable             = true
    required            = false
    string_attribute_constraints {
      min_length = "1"
      max_length = "64"
    }
  }

  # token 有効期限（単位を明示）
  token_validity_units {
    access_token  = "minutes"
    id_token      = "minutes"
    refresh_token = "days"
  }
  access_token_validity  = var.access_token_validity_minutes
  id_token_validity      = var.id_token_validity_minutes
  refresh_token_validity = var.refresh_token_validity_days

  admin_create_user_config {
    allow_admin_create_user_only = true
  }

  # ユーザ存在隠蔽
  prevent_user_existence_errors = "ENABLED"

  tags = local.tags
}

# -----------------------------
# Hosted UI Domain
# -----------------------------
resource "aws_cognito_user_pool_domain" "this" {
  domain       = var.domain_prefix # 例: myapp-tenant
  user_pool_id = aws_cognito_user_pool.this.id
}

# -----------------------------
# Server App Client (no OAuth)
# - Admin API で email/password ログイン（ADMIN_NO_SRP_AUTH）
# -----------------------------
resource "aws_cognito_user_pool_client" "server" {
  name                                 = "${var.project_name}-server"
  user_pool_id                          = aws_cognito_user_pool.this.id
  generate_secret                       = var.generate_server_client_secret
  enable_token_revocation               = true
  prevent_user_existence_errors         = "ENABLED"

  explicit_auth_flows = [
    "ALLOW_ADMIN_USER_PASSWORD_AUTH",
    "ALLOW_REFRESH_TOKEN_AUTH",
  ]

  # OAuth は使わない（Hosted UI想定なし）
  allowed_oauth_flows_user_pool_client = false

  # token 有効期限（client 単位の上書きは不要）
  depends_on = [aws_cognito_user_pool.this]
}

# -----------------------------
# Frontend App Client (Hosted UI + OAuth2 Code with PKCE)
# -----------------------------
resource "aws_cognito_user_pool_client" "web" {
  name                                 = "${var.project_name}-web"
  user_pool_id                          = aws_cognito_user_pool.this.id
  generate_secret                       = false             # SPA/PKCE は secret なし
  enable_token_revocation               = true
  prevent_user_existence_errors         = "ENABLED"

  allowed_oauth_flows_user_pool_client = true
  allowed_oauth_flows                  = ["code"]          # PKCE（implicit は非推奨）
  supported_identity_providers         = ["COGNITO"]
  allowed_oauth_scopes                 = ["openid", "email", "profile"]

  callback_urls = var.callback_urls     # 例: ["https://app.example.com/auth/callback"]
  logout_urls   = var.logout_urls       # 例: ["https://app.example.com/"]

  explicit_auth_flows = [
    "ALLOW_REFRESH_TOKEN_AUTH",
    # Hosted UI 経由では USER_SRP_AUTH や USER_PASSWORD_AUTH は不要
  ]

  depends_on = [aws_cognito_user_pool_domain.this]
}
```

---

## `infra/tf/outputs.tf`

```hcl
output "user_pool_id" {
  value       = aws_cognito_user_pool.this.id
  description = "Cognito User Pool ID"
}

output "user_pool_arn" {
  value       = aws_cognito_user_pool.this.arn
  description = "Cognito User Pool ARN"
}

output "server_app_client_id" {
  value       = aws_cognito_user_pool_client.server.id
  description = "Server app client ID (use in Django .env)"
}

output "server_app_client_secret" {
  value       = aws_cognito_user_pool_client.server.client_secret
  description = "Server app client secret (if generated)"
  sensitive   = true
}

output "web_app_client_id" {
  value       = aws_cognito_user_pool_client.web.id
  description = "Frontend (Hosted UI) app client ID"
}

output "hosted_ui_base_url" {
  value       = "https://${aws_cognito_user_pool_domain.this.domain}.auth.${var.aws_region}.amazoncognito.com"
  description = "Hosted UI base URL"
}

output "authorization_endpoint" {
  value = "https://${aws_cognito_user_pool_domain.this.domain}.auth.${var.aws_region}.amazoncognito.com/oauth2/authorize"
}

output "token_endpoint" {
  value = "https://${aws_cognito_user_pool_domain.this.domain}.auth.${var.aws_region}.amazoncognito.com/oauth2/token"
}

output "logout_endpoint" {
  value = "https://${aws_cognito_user_pool_domain.this.domain}.auth.${var.aws_region}.amazoncognito.com/logout"
}
```

---

## `infra/tf/terraform.tfvars.example`

```hcl
project_name   = "django-cognito-sample"
aws_region     = "ap-northeast-1"

# リージョン内で一意なプレフィックス（英小文字・数字・ハイフン）
domain_prefix  = "django-cog-tenant"

# フロントエンドのコールバック／サインアウト先
callback_urls  = [
  "https://app.example.com/auth/callback",  # SPA
  # "http://localhost:5173/auth/callback",  # 開発用
]
logout_urls = [
  "https://app.example.com/",
  # "http://localhost:5173/",
]

# 任意調整
refresh_token_validity_days   = 30
access_token_validity_minutes = 60
id_token_validity_minutes     = 60

generate_server_client_secret = false
```

---

## 適用手順

```bash
cd infra/tf
terraform init
terraform plan -var-file="terraform.tfvars" -out plan.out
terraform apply plan.out
```

**適用後**、Django 側の `.env` を以下のように設定:

```
AWS_REGION=ap-northeast-1
COGNITO_USER_POOL_ID=<terraform output user_pool_id>
# サーバ側の Admin API 用は server_app_client_id を使用
COGNITO_APP_CLIENT_ID=<terraform output server_app_client_id>
# もし server client で secret を ON にした場合のみ
# COGNITO_APP_CLIENT_SECRET=<terraform output server_app_client_secret>
```

フロントエンド（Hosted UI 経由で OAuth2）には `web_app_client_id` と `hosted_ui_base_url` を利用します。

---

## テナント属性（`custom:tenant_id`）について

- 本 Terraform で **User Pool に `tenant_id`** を定義しました。ユーザーにこの値を設定すれば **ID トークン**に `custom:tenant_id` として入ります。
- 付与は**ユーザー作成時**または**後から更新**で可能です（例：管理ツールやサインアップ Lambda で設定）。
- 参考コード（Django 管理バッチ例、AWS SDK）で `AdminUpdateUserAttributes` を呼べば設定できます。

> サンプルユーザーの Terraform 作成も可能ですが、秘密情報（初期パスワード等）を IaC に置くのは推奨しません。必要であれば `aws_cognito_user` リソースでの例も追記します。

---

## 要件への適合ポイント（チェックリスト）

- [x] **email / password ログイン**: Server app client の `explicit_auth_flows` に `ALLOW_ADMIN_USER_PASSWORD_AUTH` 指定 → Django から `AdminInitiateAuth` でログイン可能
- [x] **MFA 無効**: `mfa_configuration = "OFF"`
- [x] **Hosted UI コールバック／サインアウト URL**: Frontend app client に `callback_urls` / `logout_urls` を明示
- [x] **PKCE(Code Flow)**: `allowed_oauth_flows = ["code"]` と `allowed_oauth_flows_user_pool_client = true`
- [x] **custom\:tenant_id**: User Pool に `schema` 追加 → ID トークンに載せてサーバで照合可
- [x] **トークン有効期限**: 変数で調整（Access/ID: 分、Refresh: 日）
- [x] **ユーザ存在隠蔽**: `prevent_user_existence_errors = "ENABLED"`
- [x] **ドメイン構成**: `aws_cognito_user_pool_domain` で Hosted UI を有効化

---

---

結論から 👇

- **いまの構成（Django は AdminInitiateAuth でサーバ側ログイン、フロントは Hosted UI を使う想定）なら**
  **`callback_urls` は“フロントエンド”のリダイレクト先**を入れます。
  **バックエンド `http://localhost:8000/...` は不要**です。

- 開発環境（Next.js/NextAuth 想定）の例

  ```hcl
  # terraform.tfvars
  callback_urls = [
    "http://localhost:3000/api/auth/callback/cognito"  # NextAuthのデフォルト
  ]
  logout_urls = [
    "http://localhost:3000/"
  ]
  ```

  > NextAuth（Auth.js）を使う場合、デフォルトのコールバックは
  > `http://<frontend-origin>/api/auth/callback/<provider>`
  > （ここでは `<provider>=cognito` としてます）

---

# なぜフロント URL なの？

- **Hosted UI（OAuth2 / PKCE）を使うとき**は、Cognito がユーザー認証後に**ブラウザをどこへ戻すか**を指定します。
  返す先＝**認可コードを受け取ってトークン交換するエンドポイント**で、通常は**フロントのルート**（NextAuth のコールバック）です。
- 逆に、**Django が AdminInitiateAuth（email/password）で直接ログイン**するフローは**OAuth2 リダイレクトを使いません**。
  この“サーバ用クライアント”には `callback_urls` 設定自体が不要です（Terraform でも分けてあります）。

---

# もし「バックエンドでコード受け取りたい」なら

- その場合は**Django 側に `/auth/cognito/callback` のようなコールバック API**を実装し、
  そこで `authorization_code` を受け取って**サーバからトークン交換**します。
- そのときは `callback_urls = ["http://localhost:8000/auth/cognito/callback"]` のように**バックエンド URL**を登録します。
  （← 今のサンプルにはこのエンドポイント実装は入れていません）

---

# よくあるハマり

- **URL は完全一致**（スキーム・ホスト・ポート・パス・末尾スラッシュまで）。`/callback` と `/callback/` は別物。
- **`http` が許されるのは localhost のみ**。本番は `https://`。
- **ワイルドカード不可**。環境ごとに URL を列挙します（例：開発/ステージ/本番）。

---

# まとめ（あなたの環境用のそのままコピペ）

- フロント：`http://localhost:3000`（Next.js/NextAuth）
- バックエンド：`http://localhost:8000`（Django/Ninja）

**Terraform (`infra/tf/terraform.tfvars`)**

```hcl
callback_urls = [
  "http://localhost:3000/api/auth/callback/cognito"
]
logout_urls = [
  "http://localhost:3000/"
]
```

この設定で、Hosted UI → 認可コード → **Next.js 側で受け取り** → 以降は取得した JWT を `Authorization: Bearer` で Django に投げる、という流れになります。
