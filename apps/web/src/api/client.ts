import axios, { AxiosError, type InternalAxiosRequestConfig } from "axios";

export const api = axios.create({
  baseURL: "http://127.0.0.1:3000/api",
  withCredentials: true,
});

// Keep the short-lived access token in memory only; localStorage is readable by injected scripts.
let accessToken: string | null = null;
let refreshing: Promise<string | null> | null = null;

export function setAccessToken(token: string | null): void {
  accessToken = token;
}

function csrfToken(): string | null {
  const cookie = document.cookie.split("; ").find((item) => item.startsWith("sd_csrf="));
  return cookie ? decodeURIComponent(cookie.slice("sd_csrf=".length)) : null;
}

api.interceptors.request.use((config: InternalAxiosRequestConfig) => {
  if (accessToken) config.headers.Authorization = `Bearer ${accessToken}`;
  const csrf = csrfToken();
  if (csrf) config.headers["X-CSRF-Token"] = csrf;
  return config;
});

async function refreshAccessToken(): Promise<string | null> {
  try {
    const response = await api.post<{ accessToken: string }>("/auth/refresh");
    accessToken = response.data.accessToken;
    return accessToken;
  } catch {
    accessToken = null;
    return null;
  }
}

api.interceptors.response.use(undefined, async (error: AxiosError) => {
  const original = error.config as (InternalAxiosRequestConfig & { _retry?: boolean }) | undefined;
  if (error.response?.status !== 401 || !original || original._retry || original.url?.includes("/auth/refresh")) {
    return Promise.reject(error);
  }
  original._retry = true;
  refreshing ??= refreshAccessToken().finally(() => { refreshing = null; });
  const token = await refreshing;
  if (!token) {
    window.location.assign("/login");
    return Promise.reject(error);
  }
  original.headers.Authorization = `Bearer ${token}`;
  return api(original);
});
