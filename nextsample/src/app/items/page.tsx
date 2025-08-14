"use client";
import { useEffect, useState } from "react";
import { useApi } from "@/lib/api";
import { useAuth } from "@/contexts/AuthContext";
import { useRouter } from "next/navigation";

export default function ItemsPage() {
  const { auth } = useAuth();
  const api = useApi();
  const router = useRouter();
  const [data, setData] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!auth.accessToken) { router.push("/login"); return; }
    api.get("/api/items/")
      .then(res => res.json())
      .then(setData)
      .catch((e) => setError(e.message));
  }, [auth.accessToken]);

  return (
    <main style={{ padding: 24 }}>
      <h1>Items</h1>
      {error && <p style={{ color: "crimson" }}>{error}</p>}
      <pre>{JSON.stringify(data, null, 2)}</pre>
    </main>
  );
}
