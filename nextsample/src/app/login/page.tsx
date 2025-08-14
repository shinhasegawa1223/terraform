"use client";
import { FormEvent, useState } from "react";
import { useAuth } from "@/contexts/AuthContext";

export default function LoginPage() {
  const { login, completeFirstLogin, needsNewPassword } = useAuth();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [error, setError] = useState<string | null>(null);

  const onSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    try {
      await login(email, password);
      window.location.href = "/";
    } catch (err: any) {
      if (err?.message === "NEW_PASSWORD_REQUIRED") {
        // show new password form
      } else {
        setError(err?.message || "Login failed");
      }
    }
  };

  const onCompleteNewPw = async (e: FormEvent) => {
    e.preventDefault();
    try {
      await completeFirstLogin(newPassword);
      window.location.href = "/";
    } catch (err: any) {
      setError(err?.message || "Failed to set new password");
    }
  };

  return (
    <main style={{ padding: 24, maxWidth: 480 }}>
      <h1>Sign in</h1>
      {error && <p style={{ color: "crimson" }}>{error}</p>}

      {!needsNewPassword ? (
        <form onSubmit={onSubmit}>
          <label>Email<br />
            <input value={email} onChange={(e) => setEmail(e.target.value)} type="email" required />
          </label>
          <br />
          <label>Password<br />
            <input value={password} onChange={(e) => setPassword(e.target.value)} type="password" required />
          </label>
          <br />
          <button type="submit">Sign in</button>
        </form>
      ) : (
        <form onSubmit={onCompleteNewPw}>
          <p>初回サインインのため新しいパスワードを設定してください。</p>
          <label>New Password<br />
            <input value={newPassword} onChange={(e) => setNewPassword(e.target.value)} type="password" required />
          </label>
          <br />
          <button type="submit">Complete</button>
        </form>
      )}
    </main>
  );
}
