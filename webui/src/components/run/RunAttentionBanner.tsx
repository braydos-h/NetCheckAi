import { memo } from "react";
import { AlertTriangle, ArrowDown, WifiOff } from "lucide-react";
import { Button } from "@/components/ui/button";
import type { WsStatus } from "@/api/ws";

interface RunAttentionBannerProps {
  authError?: string;
  pendingCount: number;
  active: boolean;
  eventsStatus: WsStatus;
  /** True when the stream is open but silent past the watchdog threshold —
   *  the socket says "connected" yet nothing has arrived for a while. */
  stale?: boolean;
  /** Count of error events this run (from deriveRun). A burst while active
   *  means the agent is stuck erroring — surface it above the fold. */
  errorCount?: number;
}

function scrollToPending() {
  document.getElementById("pending-decisions")?.scrollIntoView({ behavior: "smooth", block: "center" });
}

/**
 * One full-width attention strip below the header. Priority: auth failure →
 * run waiting on operator input → live connection lost. Renders nothing when
 * the run is healthy, so a quiet run keeps a quiet header.
 */
export const RunAttentionBanner = memo(function RunAttentionBanner({
  authError,
  pendingCount,
  active,
  eventsStatus,
  stale = false,
  errorCount = 0,
}: RunAttentionBannerProps) {
  if (authError) {
    return (
      <div
        role="alert"
        className="flex items-start gap-2 rounded-md border border-destructive/40 bg-destructive/10 p-3 text-sm text-red-200"
      >
        <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" aria-hidden />
        <div className="min-w-0 break-words">{authError}</div>
      </div>
    );
  }

  if (pendingCount > 0) {
    return (
      <div
        role="alert"
        className="flex flex-wrap items-center gap-2 rounded-md border border-yellow-500/40 bg-yellow-500/10 px-3 py-2.5 text-sm text-yellow-200"
      >
        <AlertTriangle className="h-4 w-4 shrink-0 animate-pulse" aria-hidden />
        <span className="min-w-0">
          The run is waiting on operator input —{" "}
          <span className="font-semibold">
            {pendingCount} pending decision{pendingCount === 1 ? "" : "s"}
          </span>
          .
        </span>
        <Button
          type="button"
          size="sm"
          variant="outline"
          className="ml-auto h-8 gap-1.5 border-yellow-500/40 text-xs"
          onClick={scrollToPending}
        >
          <ArrowDown className="h-3.5 w-3.5" aria-hidden />
          Review now
        </Button>
      </div>
    );
  }

  // Deep Run Logs: an active run accumulating error events (stuck_loop /
  // tool_error / circuit_open) is erroring, not just quiet — say so above
  // the fold. The detail lives in the Errors filter + errors.jsonl artifact.
  if (active && errorCount > 0) {
    return (
      <div
        role="alert"
        className="flex items-center gap-2 rounded-md border border-destructive/40 bg-destructive/10 px-3 py-2 text-sm text-red-200"
      >
        <AlertTriangle className="h-4 w-4 shrink-0 animate-pulse" aria-hidden />
        <span>
          Run is logging errors —{" "}
          <span className="font-semibold">
            {errorCount} error event{errorCount === 1 ? "" : "s"}
          </span>
          . Check the Errors filter or errors.jsonl for kind/phase/traceback.
        </span>
      </div>
    );
  }

  if (active && (eventsStatus === "reconnecting" || eventsStatus === "closed" || stale)) {
    return (
      <div
        role="status"
        className="flex items-center gap-2 rounded-md border border-muted-foreground/30 bg-muted/30 px-3 py-2 text-sm text-muted-foreground"
      >
        <WifiOff className="h-4 w-4 shrink-0" aria-hidden />
        <span>
          {eventsStatus === "reconnecting"
            ? "Live connection lost — reconnecting…"
            : eventsStatus === "closed"
              ? "Live connection offline. Data shown is the last received snapshot."
              : "No live data for a while — connection may be stale."}
        </span>
      </div>
    );
  }

  return null;
});
