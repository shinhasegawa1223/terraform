了解です。シンプルに動く構成として必要なファイルを全部まとめた実装を以下に示します。前提は：

- Next.js（App Router）を使っている
- サーバー側（API ルート等）で `process.env.API_URL` 等を使う
- 本番では IAM ロール経由で SSM から取る（アクセスキー不要）、開発時は `.env.local` を使う
- クライアントに出す値は `NEXT_PUBLIC_` プレフィックスを使う

---

## 1. `lib/loadSsmParams.ts`（SSM を一度だけ取って `process.env` に入れる）

```ts
// lib/loadSsmParams.ts
import { SSMClient, GetParameterCommand } from "@aws-sdk/client-ssm";

const REGION =
  process.env.AWS_REGION || process.env.AWS_DEFAULT_REGION || "ap-northeast-1";
const ssm = new SSMClient({ region: REGION });

let initialized = false;

const PARAMETER_MAP: Record<string, string> = {
  API_URL: "/test/api_url",
  MANUALS_TOKEN: "/myapp/prod/manuals_token",
  // 必要なら他もここに追加。例: S3_BUCKET: "/test/s3_bukket"
};

/**
 * 一度だけ SSM から取って process.env にセットする（冪等）。
 */
export async function loadSsmParametersOnce(): Promise<void> {
  if (initialized) return;
  initialized = true;

  if (process.env.USE_SSM && process.env.USE_SSM.toLowerCase() === "false") {
    return;
  }

  try {
    for (const [envKey, paramName] of Object.entries(PARAMETER_MAP)) {
      const cmd = new GetParameterCommand({
        Name: paramName,
        WithDecryption: true,
      });
      const res = await ssm.send(cmd);
      if (res.Parameter?.Value) {
        process.env[envKey] = res.Parameter.Value;
      }
    }
  } catch (err) {
    console.error("loadSsmParametersOnce error:", err);
    // 必要ならここで例外を投げるかフォールバック処理を書く
  }
}
```

---

## 2. `lib/init.ts`（アプリ起動側で先に読み込ませる用。各ルートで import すれば一度だけ実行される）

```ts
// lib/init.ts
import { loadSsmParametersOnce } from "./loadSsmParams";

loadSsmParametersOnce().catch((e) => {
  console.warn("SSM 初期化失敗:", e);
});
```

---

## 3. `.env.local`（ローカル開発用フォールバック）

```env
# .env.local
USE_SSM=false

# 本来は SSM から取るもの（ローカル開発用代替）
API_URL=http://api:8000
MANUALS_TOKEN=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9....
MINIO_ENDPOINT=http://localhost:9000
MINIO_BUCKET=sample

# クライアントに出すなら NEXT_PUBLIC_ を使う
NEXT_PUBLIC_MINIO_ENDPOINT=http://localhost:9000
NEXT_PUBLIC_MINIO_BUCKET=sample
```

---

## 4. `next.config.js`（クライアントで使うホスト／公開 env の設定）

```js
// next.config.js
const { parsed: localEnv } = require("dotenv").config();

module.exports = {
  experimental: {
    appDir: true,
  },
  env: {
    // サーバー側で直接 process.env.API_URL 等を使うのでここは不要だが、
    // クライアント側で出したいなら NEXT_PUBLIC_ を明示的に渡す
    NEXT_PUBLIC_MINIO_ENDPOINT: process.env.NEXT_PUBLIC_MINIO_ENDPOINT,
    NEXT_PUBLIC_MINIO_BUCKET: process.env.NEXT_PUBLIC_MINIO_BUCKET,
  },
  images: {
    // もし next/image で MinIO を使うならホストを追加
    remotePatterns: [
      {
        protocol: "http",
        hostname: "localhost", // dev の場合
        port: "9000",
        pathname: "/**",
      },
      // 本番のホストがあるならここに追加
    ],
  },
};
```

---

## 5. API ルート例：`/app/api/s3/route.ts`

```ts
// app/api/s3/route.ts
import { NextRequest, NextResponse } from "next/server";
// 先に init を読んでおく（loadSsmParametersOnce を実行）
import "@/lib/init";

export async function GET(req: NextRequest) {
  const apiUrl = process.env.API_URL;
  const manualsToken = process.env.MANUALS_TOKEN;

  if (!apiUrl || !manualsToken) {
    return NextResponse.json(
      { error: "Missing required environment variables" },
      { status: 500 }
    );
  }

  try {
    const downstream = await fetch(`${apiUrl}/some/path`, {
      headers: {
        Authorization: `Bearer ${manualsToken}`,
      },
    });

    if (!downstream.ok) {
      const text = await downstream.text();
      return NextResponse.json(
        { error: "Downstream fetch failed", detail: text },
        { status: downstream.status }
      );
    }

    const data = await downstream.json();
    return NextResponse.json({ data });
  } catch (err) {
    console.error("GET /api/s3 error:", err);
    return NextResponse.json(
      { error: "Internal error", detail: (err as Error).message },
      { status: 500 }
    );
  }
}
```

---

## 6. サーバーサイドでの使用例（他のモジュール内で）

```ts
// 例: サーバー内の別処理で process.env.API_URL を使う
import "@/lib/init"; // 必要な場所で先に読み込む（loadSsmParametersOnce が走る）

export async function callSomeService() {
  const base = process.env.API_URL;
  if (!base) throw new Error("API_URL not set");
  const res = await fetch(`${base}/health`);
  return res.json();
}
```

---

## 7. IAM / 実行環境に関する補足（本番向け）

- ECS タスク定義や EC2 / Lambda には SSM 読み取り権限を持つ IAM ロールをアタッチ
  例ポリシー（必要なパラメータだけ）:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["ssm:GetParameter"],
      "Resource": [
        "arn:aws:ssm:ap-northeast-1:YOUR_ACCOUNT_ID:parameter/test/api_url",
        "arn:aws:ssm:ap-northeast-1:YOUR_ACCOUNT_ID:parameter/myapp/prod/manuals_token"
      ]
    }
  ]
}
```

- 環境変数 `AWS_REGION` か `AWS_DEFAULT_REGION` を設定しておく（多くの環境では自動設定される）

---

これで「起動時に一度だけ SSM から取って `process.env` に入れ、`process.env.API_URL` などを普通に使う」構成が動きます。必要なら `MANUALS_TOKEN` を使った認証付きフェッチや、クライアントに出す値のラッピングも補助します。これで全部のコードとして足りますか？
