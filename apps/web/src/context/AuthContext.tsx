import { createContext, useContext, useEffect, useState, type ReactNode } from "react";
import { api, setAccessToken } from "../api/client";

export type Role = "STANDARD_USER" | "DOCUMENT_OWNER" | "AUDITOR" | "ADMINISTRATOR";
export type User = { id: string; email: string; displayName: string; role: Role; status: string; createdAt: string; lastLoginAt: string | null };
type AuthValue = { user: User | null; loading: boolean; login: (email: string, password: string) => Promise<void>; register: (email: string, displayName: string, password: string) => Promise<User>; logout: () => Promise<void> };
const AuthContext = createContext<AuthValue | undefined>(undefined);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);
  useEffect(() => {
    api.post<{ accessToken: string }>("/auth/refresh").then(({ data }) => {
      setAccessToken(data.accessToken);
      return api.get<{ user: User }>("/auth/me");
    }).then(({ data }) => setUser(data.user)).catch(() => setAccessToken(null)).finally(() => setLoading(false));
  }, []);
  async function login(email: string, password: string) {
    const { data } = await api.post<{ accessToken: string; user: User }>("/auth/login", { email, password });
    setAccessToken(data.accessToken); setUser(data.user);
  }
  async function register(email: string, displayName: string, password: string) {
    const { data } = await api.post<{ user: User }>("/auth/register", { email, displayName, password });
    return data.user;
  }
  async function logout() { await api.post("/auth/logout").catch(() => undefined); setAccessToken(null); setUser(null); }
  return <AuthContext.Provider value={{ user, loading, login, register, logout }}>{children}</AuthContext.Provider>;
}
export function useAuth(): AuthValue { const value = useContext(AuthContext); if (!value) throw new Error("useAuth must be used within AuthProvider"); return value; }
