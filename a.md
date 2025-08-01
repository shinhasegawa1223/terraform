// lib/aws-ssm.ts
import { SSMClient, GetParameterCommand } from "@aws-sdk/client-ssm";
import dotenv from "dotenv";

dotenv.config(); // ローカルの .env.local を読み込む

const REGION = process.env.AWS_REGION || process.env.AWS_DEFAULT_REGION || "ap-northeast-1";
const ssm = new SSMClient({ region: REGION });

// キャッシュ（起動中に一度だけ取得）
let cached: { API_URL: string; MANUALS_TOKEN: string } | null = null;

// Parameter Store に保存している名前（実際の名前に合わせて書き換える）
const PARAM_NAMES = {
API_URL: "/test/api_url",
MANUALS_TOKEN: "/myapp/prod/manuals_token", // ここは実際に登録した名前にする
};

async function fetchParam(name: string): Promise<string> {
const cmd = new GetParameterCommand({ Name: name, WithDecryption: true });
const res = await ssm.send(cmd);
if (!res.Parameter?.Value) throw new Error(`SSM parameter ${name} empty`);
return res.Parameter.Value;
}

/\*\*

- 起動時に一度だけ呼ぶ。環境変数があればそれを優先し、なければ SSM から取る。
  \*/
  export async function loadAwsParamsOnce() {
  if (cached) return cached;

const apiUrl = process.env.API_URL || (await fetchParam(PARAM_NAMES.API_URL));
const manualsToken = process.env.MANUALS_TOKEN || (await fetchParam(PARAM_NAMES.MANUALS_TOKEN));

cached = {
API_URL: apiUrl,
MANUALS_TOKEN: manualsToken,
};
return cached;
}
