"use client";
import React, { createContext, useContext, useEffect, useMemo, useState } from "react";
import { signInWithEmailPassword, completeNewPassword, SignInResult } from "@/lib/cognito";

export type AuthState = {
  accessToken?: string;
  idToken?: string;
  refreshToken?: string;
  tenantId?: string | null;
  idClaims?: any;
};

const AuthContext = createContext<{
  auth: AuthState;
  needsNewPassword: boolean;
  login: (email: string, password: string) => Promise<void>;
  completeFirstLogin: (newPassword: string) => Promise<void>;
  logout: () => void;
}>({} as any);

function load(): AuthState {
  if (typeof window === "undefined") return {};
  try {
    return JSON.parse(localStorage.getItem("auth") || "{}");
  } catch {
    return {};
  }
}

function save(state: AuthState) {
  if (typeof window === "undefined") return;
  localStorage.setItem("auth", JSON.stringify(state));
}

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [auth, setAuth] = useState<AuthState>({});
  const [pendingUser, setPendingUser] = useState<any>(null);

  useEffect(() => {
    setAuth(load());
  }, []);
  useEffect(() => {
    save(auth);
  }, [auth]);

  const value = useMemo(() => ({
    auth,
    needsNewPassword: !!pendingUser,
    login: async (email: string, password: string) => {
      try {
        const res = await signInWithEmailPassword(email, password);
        setPendingUser(null);
        setAuth({
          accessToken: res.accessToken,
          idToken: res.idToken,
          refreshToken: res.refreshToken,
          tenantId: res.tenantId,
          idClaims: res.idClaims,
        });
      } catch (e: any) {
        if (e?.challenge === "NEW_PASSWORD_REQUIRED" && e?.user) {
          setPendingUser(e.user);
          throw new Error("NEW_PASSWORD_REQUIRED");
        }
        throw e;
      }
    },
    completeFirstLogin: async (newPassword: string) => {
      if (!pendingUser) throw new Error("No pending user session");
      const res: SignInResult = await completeNewPassword(pendingUser, newPassword);
      setPendingUser(null);
      setAuth({
        accessToken: res.accessToken,
        idToken: res.idToken,
        refreshToken: res.refreshToken,
        tenantId: res.tenantId,
        idClaims: res.idClaims,
      });
    },
    logout: () => {
      setAuth({});
      localStorage.removeItem("auth");
      setPendingUser(null);
    },
  }), [auth, pendingUser]);

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() { return useContext(AuthContext); }
