いいね、その後段の「認証チェック」を**Django Ninja でキレイに再利用できる形**で用意します。ポイントは：

- フロントエンドからは\*\*`Authorization: Bearer <AccessToken or IdToken>`\*\*を送ってもらう
  ※`login` のときに返した \*\*`session` は「初回 PW 変更チャレンジ用の一時値」\*\*で、以降の認証には使いません。
- サーバ側は **Cognito の JWKS で JWT 署名を検証**し、`request.auth` にクレームを載せる
- `item/api.py` の各エンドポイントを `auth=CognitoAuth()` で保護

以下コピペで OK です。

---

# 1) settings.py に検証用の定数を追加

```python
# settings.py（前回の環境変数に加えて）
AWS_REGION = os.getenv("AWS_REGION", "ap-northeast-1")
COGNITO_USER_POOL_ID = os.getenv("COGNITO_USER_POOL_ID")
COGNITO_APP_CLIENT_ID = os.getenv("COGNITO_APP_CLIENT_ID")
COGNITO_APP_CLIENT_SECRET = os.getenv("COGNITO_APP_CLIENT_SECRET", "")

# JWT検証用（発行者とJWKS）
COGNITO_ISSUER = f"https://cognito-idp.{AWS_REGION}.amazonaws.com/{COGNITO_USER_POOL_ID}"
COGNITO_JWKS_URL = f"{COGNITO_ISSUER}/.well-known/jwks.json"

# APIでは基本 Access Token を推奨（Id Tokenでも検証可）
COGNITO_PREFERRED_TOKEN_USE = os.getenv("COGNITO_PREFERRED_TOKEN_USE", "access")  # "access" or "id"
```

---

# 2) 認証ユーティリティ（JWT 検証 & Ninja の HttpBearer）

`user/auth.py` を作成：

```python
# user/auth.py
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
    """JWK (n, e) -> RSA PublicKey(PEM)"""
    n = int.from_bytes(base64url_decode(jwk["n"].encode()), "big")
    e = int.from_bytes(base64url_decode(jwk["e"].encode()), "big")
    pub_numbers = rsa.RSAPublicNumbers(e, n)
    pub_key = pub_numbers.public_key()
    return pub_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def verify_cognito_jwt(token: str, token_use: str = "access") -> dict:
    """
    Cognito の JWT を検証してクレームを返す。
    token_use: "access" or "id"
    """
    # kid に合う鍵を取得
    unverified_header = jwt.get_unverified_header(token)
    kid = unverified_header.get("kid")
    if not kid:
        raise HttpError(401, "Invalid token header")

    jwks = _get_jwks()
    jwk = next((k for k in jwks if k["kid"] == kid), None)
    if jwk is None:
        # 失敗時はキー回転を疑い、再取得して再試行
        _JWKS_CACHE["exp"] = 0
        jwks = _get_jwks()
        jwk = next((k for k in jwks if k["kid"] == kid), None)
        if jwk is None:
            raise HttpError(401, "Unknown signing key")

    pem = _rsa_pem_from_jwk(jwk)

    # まず issuer/exp等を検証
    # Access Token は "aud" を持たないため audience 検証はオフにして後で手動チェック
    claims = jwt.decode(
        token,
        pem,
        algorithms=["RS256"],
        issuer=settings.COGNITO_ISSUER,
        options={"verify_aud": False},  # aud は後段で手動チェック
    )

    # token_use / aud / client_id を確認
    tu = claims.get("token_use")
    if tu != token_use:
        # もし許容したい場合は settings.COGNITO_PREFERRED_TOKEN_USE を "id" か "access" に合わせる
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


# ------- Ninja 用 Bearer 認証クラス -------
class CognitoAuth(HttpBearer):
    """
    使い方:
      @router.get("/...", auth=CognitoAuth())  # Access Token を検証
      @router.get("/...", auth=CognitoAuth("id"))  # Id Token を検証
    """
    def __init__(self, token_use: Optional[str] = None):
        self.token_use = token_use or settings.COGNITO_PREFERRED_TOKEN_USE

    def authenticate(self, request, token: str) -> dict:
        try:
            claims = verify_cognito_jwt(token, token_use=self.token_use)
            # request.auth に返る値（必要なら整形）
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
            # 署名・exp・iss 等のいずれかが不正
            raise HttpError(401, "Unauthorized")
```

> 補足：ネットワークコール無しで**ローカル検証**できるので高速です（鍵は 1 時間キャッシュ）。
> サーバ側で毎回 API に当てたい場合は `boto3.client('cognito-idp').get_user(AccessToken=...)` でも検証できますが、毎回 AWS に行くためレイテンシ増＋権限が必要です。

---

# 3) 認証が必要なエンドポイント（例：item/api.py）

```python
# item/api.py
from ninja import Router, Schema
from django.http import HttpRequest
from user.auth import CognitoAuth  # さきほどの認証クラス

router = Router(tags=["items"])

class ItemOut(Schema):
    id: int
    name: str
    owner_sub: str

@router.get("/", response=list[ItemOut], auth=CognitoAuth())  # Access Token を検証
def list_items(request: HttpRequest):
    user = request.auth  # {"sub", "username", "email", "scope", "claims"}
    # ここで user["sub"] 等を使ってDBを絞り込むなど
    return [
        ItemOut(id=1, name="sample-1", owner_sub=user["sub"]),
        ItemOut(id=2, name="sample-2", owner_sub=user["sub"]),
    ]

@router.get("/me", auth=CognitoAuth())  # 自分のクレーム確認用
def me(request: HttpRequest):
    return {
        "sub": request.auth["sub"],
        "username": request.auth["username"],
        "email": request.auth["email"],
        "token_use": request.auth["claims"].get("token_use"),
    }
```

> ルータ登録はこれまで通り：`api.add_router("/items", item.router)` のように追加。

---

## フロントエンド側の送信例

- **ヘッダに載せる**（推奨）

```
GET /api/items
Authorization: Bearer <AccessToken>
```

- Cookie 派なら、サーバ側で `Authorization` が無いとき `request.COOKIES.get("access_token")` を拾う処理を `CognitoAuth.authenticate` に少し追加すれば OK です。

---

## よくある質問（超要点）

- **「`session` を使って認証して良い？」**
  → いいえ。`login` で返る `session` は **初回パスワード変更（NEW_PASSWORD_REQUIRED）** の**継続用トークン**だけです。
  **以降の API 認証は Access Token（or Id Token）** を必ず使ってください。

- **Access と Id どっちを API で使う？**
  → API の保護は **Access Token** が一般的（`scope`/`client_id` で判定）。
  画面でユーザー情報を読むだけなら Id Token でも OK。両方サポートしたい場合は `CognitoAuth("id")` を別エンドポイントで使い分けてください。

- **トークンが無効・期限切れのとき**
  → この実装では 401 を返します。フロントは `/user/refresh` で再発行 → リトライ、の流れに。

---

必要なら、この認証を**全ルーターで共通適用**するミドルウェア化や、**権限（scope/role）チェック**のデコレータもすぐ足します。
