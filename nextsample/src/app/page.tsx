"use client";
import Link from "next/link";
import { useAuth } from "@/contexts/AuthContext";

export default function Home() {
  const { auth, logout } = useAuth();
  const authed = Boolean(auth.accessToken);
  return (
    <main style={{ padding: 24 }}>
      <h1>Frontend (email/password direct login)</h1>
      {authed ? (
        <>
          <p>Signed in. tenant_id: <b>{auth.tenantId ?? "(none)"}</b></p>
          <ul>
            <li><Link href="/items">Items</Link></li>
            <li><Link href="/alerts">Alerts</Link></li>
          </ul>
          <button onClick={logout}>Sign out</button>
        </>
      ) : (
        <>
          <p>Not signed in.</p>
          <Link href="/login">Go to Login</Link>
        </>
      )}
    </main>
  );
}
