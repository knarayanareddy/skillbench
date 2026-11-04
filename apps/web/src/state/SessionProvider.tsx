import { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";
import type { ReactNode } from "react";
import { ApiError, request, setCsrfToken } from "../api/client";
import type { SessionBody } from "../api/types";

interface SessionState {
  session: SessionBody | null;
  loading: boolean;
  error: string | null;
  refresh: () => Promise<void>;
  logout: () => Promise<void>;
}

const SessionContext = createContext<SessionState | null>(null);

export function SessionProvider({ children }: { children: ReactNode }): JSX.Element {
  const [session, setSession] = useState<SessionBody | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      const body = await request<SessionBody>("/api/v1/auth/session");
      setCsrfToken(body.csrf_token);
      setSession(body);
      setError(null);
    } catch (caught) {
      setCsrfToken(null);
      setSession(null);
      setError(caught instanceof ApiError ? caught.problem.detail : "Session unavailable.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const logout = useCallback(async () => {
    try {
      await request<undefined>("/api/v1/auth/logout", { method: "POST", mutation: true });
    } finally {
      setCsrfToken(null);
      setSession(null);
      window.location.assign("/");
    }
  }, []);

  const value = useMemo(
    () => ({ session, loading, error, refresh, logout }),
    [session, loading, error, refresh, logout],
  );
  return <SessionContext.Provider value={value}>{children}</SessionContext.Provider>;
}

export function useSession(): SessionState {
  const value = useContext(SessionContext);
  if (!value) throw new Error("useSession must be used inside SessionProvider");
  return value;
}
