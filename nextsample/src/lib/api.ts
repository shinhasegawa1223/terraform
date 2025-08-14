"use client";
import { useAuth } from "@/contexts/AuthContext";

export async function callApi(
  path: string,
  init: RequestInit = {},
  getAuth: () => { accessToken?: string; tenantId?: string | null }
) {
  const base = process.env.NEXT_PUBLIC_API_BASE!;
  const { accessToken, tenantId } = getAuth();
  if (!accessToken) throw new Error("No access token");

  const tenantHeader = process.env.NEXT_PUBLIC_TENANT_HEADER || "X-Tenant-Id";

  const res = await fetch(`${base}${path}`, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      ...(init.headers || {}),
      Authorization: `Bearer ${accessToken}`,
      [tenantHeader]: tenantId ?? "public",
    } as any,
    cache: "no-store",
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`API ${res.status}: ${text}`);
  }
  return res;
}

// Convenience hooks for React components
export function useApi() {
  const { auth } = useAuth();
  return {
    get: (path: string) => callApi(path, { method: "GET" }, () => auth),
    post: (path: string, body: any) =>
      callApi(path, { method: "POST", body: JSON.stringify(body) }, () => auth),
  };
}
