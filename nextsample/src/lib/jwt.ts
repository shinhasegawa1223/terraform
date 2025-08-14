export function decodeJwtPayload<T = any>(jwt: string): T {
  const parts = jwt.split(".");
  if (parts.length < 2) throw new Error("Invalid JWT");
  const payload = parts[1];
  const json = Buffer.from(payload.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8");
  return JSON.parse(json);
}
