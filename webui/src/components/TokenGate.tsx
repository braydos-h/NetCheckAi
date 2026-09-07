import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { Activity, KeyRound, Loader2, ShieldAlert } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { AUTH_EXPIRED_EVENT, expireSession, getStoredToken, setStoredToken } from "@/api/client";
import { useCapabilities } from "@/api/hooks";
import { ApiError } from "@/api/client";
import { queryClient } from "@/api/queryClient";

interface TokenGateProps {
  children: React.ReactNode;
}

export function TokenGate({ children }: TokenGateProps) {
  const [tokenInput, setTokenInput] = useState("");
  const [connectError, setConnectError] = useState("");
  const [verifying, setVerifying] = useState(false);
  // Tick bumped when an AUTH_EXPIRED_EVENT arrives. hasToken reads sessionStorage
  // at render time, which nothing observes — without this a mid-session 401
  // would clear the token while the gate (already mounted) never re-renders.
  const [authExpiredAt, setAuthExpiredAt] = useState(0);
  const navigate = useNavigate();

  useEffect(() => {
    const onExpired = () => setAuthExpiredAt(Date.now());
    window.addEventListener(AUTH_EXPIRED_EVENT, onExpired);
    return () => window.removeEventListener(AUTH_EXPIRED_EVENT, onExpired);
  }, []);

  const hasToken = authExpiredAt === 0 && !!getStoredToken();
  const capabilities = useCapabilities(hasToken);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setConnectError("");
    setVerifying(true);
    const trimmed = tokenInput.trim();
    if (!trimmed) {
      setConnectError("Enter the bearer token from .webui_secret_key or BREACHPILOT_API_TOKEN.");
      setVerifying(false);
      return;
    }
    setStoredToken(trimmed);
    try {
      await capabilities.refetch();
      setTokenInput("");
      setAuthExpiredAt(0);
    } catch (err) {
      if (err instanceof ApiError && err.isAuth) {
        setConnectError("Token rejected by the API.");
        setStoredToken("");
      } else if (err instanceof ApiError && err.status === 0) {
        setConnectError("Could not reach the API daemon. Start it with: python main.py --demon");
        setStoredToken("");
      } else {
        setConnectError(err instanceof Error ? err.message : "Verification failed.");
        setStoredToken("");
      }
    } finally {
      setVerifying(false);
    }
  };

  const signOut = () => {
    // Same teardown as a 401: expireSession clears the token + toasts, and
    // removeQueries drops cached data so the next auth in this tab replays
    // fresh instead of resuming stale run events.
    expireSession("Signed out. Enter a token to reconnect.");
    queryClient.removeQueries();
    setTokenInput("");
    navigate("/");
  };

  if (!hasToken) {
    return (
      <div className="flex min-h-dvh items-center justify-center bg-background px-4 py-10">
        <Card className="w-full max-w-md">
          <CardHeader className="space-y-2">
            <div className="flex items-center gap-2 text-muted-foreground">
              <ShieldAlert className="h-4 w-4" />
              <span className="text-xs uppercase tracking-wide">Local console</span>
            </div>
            <CardTitle className="text-xl">BreachPilot console</CardTitle>
            <CardDescription>
              Enter the API bearer token to continue. The token is generated into{" "}
              <code className="rounded bg-muted px-1 py-0.5 text-xs">.webui_secret_key</code> or set via{" "}
              <code className="rounded bg-muted px-1 py-0.5 text-xs">BREACHPILOT_API_TOKEN</code>.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <form className="space-y-4" onSubmit={submit}>
              <div className="space-y-2">
                <Label htmlFor="token">Bearer token</Label>
                <Input
                  id="token"
                  type="password"
                  autoComplete="off"
                  spellCheck={false}
                  value={tokenInput}
                  onChange={(e) => setTokenInput(e.target.value)}
                  placeholder="Paste the token from .webui_secret_key"
                  aria-describedby="token-error"
                  aria-invalid={!!connectError}
                />
                <p id="token-error" className="min-h-[1lh] text-xs text-destructive" aria-live="polite">
                  {connectError}
                </p>
              </div>
              <Button type="submit" className="w-full" disabled={verifying}>
                {verifying ? <Loader2 className="h-4 w-4 animate-spin" /> : <KeyRound className="h-4 w-4" />}
                {verifying ? "Verifying" : "Connect"}
              </Button>
            </form>
            <p className="mt-4 text-xs text-muted-foreground">
              The token is held in memory only (never stored in the browser) and is sent to{" "}
              <code className="rounded bg-muted px-1 py-0.5">127.0.0.1</code> only. Refreshing
              this page signs you out.
            </p>
          </CardContent>
        </Card>
      </div>
    );
  }

  const isLoading = capabilities.isLoading && capabilities.fetchStatus !== "idle";
  const isError = capabilities.isError;
  const apiErrorMessage =
    capabilities.error instanceof ApiError ? capabilities.error.message : "Could not verify token.";

  if (isLoading) {
    return (
      <div className="flex min-h-dvh items-center justify-center bg-background">
        <div className="flex items-center gap-2 text-muted-foreground">
          <Activity className="h-4 w-4 animate-pulse" />
          <span>Connecting to the API...</span>
        </div>
      </div>
    );
  }

  if (isError) {
    const err = capabilities.error;
    const isAuth = err instanceof ApiError && err.isAuth;
    const isNetwork = err instanceof ApiError && err.status === 0;
    return (
      <div className="flex min-h-dvh items-center justify-center bg-background px-4 py-10">
        <Card className="w-full max-w-md">
          <CardHeader>
            <CardTitle className="text-lg">{isAuth ? "Token rejected" : "API unreachable"}</CardTitle>
            <CardDescription>{apiErrorMessage}</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3 text-sm text-muted-foreground">
            {isAuth && <p>The token was rejected. Re-enter it to continue.</p>}
            {isNetwork && (
              <p>Start the daemon first: <code className="rounded bg-muted px-1 py-0.5">python main.py --demon</code></p>
            )}
            <Button variant="outline" onClick={signOut}>Change token</Button>
          </CardContent>
        </Card>
      </div>
    );
  }

  return <>{children}</>;
}
