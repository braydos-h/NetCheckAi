// BreachPilot by @braydos-h — https://github.com/braydos-h/BreachPilot
// Structured mission-event timeline for a benchmark run.
import { useMemo } from "react";
import { AlertCircle, CheckCircle2, Clock, Flag, PackageOpen, PlayCircle, Save, ShieldAlert, Wrench, XCircle } from "lucide-react";
import { cn } from "@/lib/utils";
import { formatDuration } from "@/features/benchmarks/MetricCards";
import type { BenchmarkEvent } from "@/features/benchmarks/types";

const EVENT_ICON: Record<string, React.ComponentType<{ className?: string }>> = {
  run_start: PlayCircle,
  run_end: CheckCircle2,
  run_cancelled: XCircle,
  run_error: AlertCircle,
  target_ready: CheckCircle2,
  target_provision_failed: AlertCircle,
  sandbox_unavailable: ShieldAlert,
  mission_start: PlayCircle,
  agent_phase: Clock,
  agent_boot: PackageOpen,
  agent_tool_start: Wrench,
  agent_tool_result: Wrench,
  oracle_result: Flag,
  verify_session_unavailable: ShieldAlert,
  baseline_saved: Save,
  regression_check: ShieldAlert,
  mission_error: AlertCircle,
  mission_timeout: AlertCircle,
};

function eventLabel(event: BenchmarkEvent): string {
  switch (event.type) {
    case "run_start":
      return `Benchmark started — ${String(event.payload.scenarios ?? "").slice(0, 120)}`;
    case "run_end":
      return `Run ${String(event.payload.status ?? "ended")} — solved ${String(event.payload.solved ?? 0)}/${String(event.payload.trials_total ?? 0)}`;
    case "run_cancelled":
      return "Run cancelled by operator";
    case "run_error":
      return `Run failed: ${String(event.payload.error ?? "").slice(0, 160)}`;
    case "target_ready":
      return `Target ready: ${event.target || String(event.payload.host ?? "")} (ports ${JSON.stringify(event.payload.ports ?? [])})`;
    case "target_provision_failed":
      return `Target provisioning failed: ${String(event.payload.detail ?? "").slice(0, 160)}`;
    case "sandbox_unavailable":
      return "Sandbox unavailable — no host-execution fallback";
    case "mission_start":
      return `Mission started (goal: ${String(event.payload.goal ?? "?")})`;
    case "agent_phase":
      return `Phase: ${String(event.payload.phase ?? "")}`;
    case "agent_boot":
      return `Agent: ${String(event.payload.label ?? event.payload.step ?? "boot")}${event.payload.ok === false ? " (failed)" : ""}`;
    case "agent_tool_request":
      return `Tool requested: ${event.tool}`;
    case "agent_tool_start":
      return `Tool started: ${event.tool}`;
    case "agent_tool_result":
      return `Tool result: ${event.tool} — ${String(event.payload.status ?? "")}`;
    case "model_usage":
      return `Model usage: ${String(event.payload.model_calls ?? 0)} calls, ${String(event.payload.total_tokens ?? 0)} tokens`;
    case "oracle_result":
      return `Oracle: ${event.payload.verified ? "VERIFIED" : "NOT verified"} (${String(event.payload.flags_captured ?? 0)}/${String(event.payload.flags_total ?? 0)} flags)`;
    case "verify_session_unavailable":
      return "Verifier session degraded — shell checks fail closed";
    case "baseline_saved":
      return `Baseline saved: ${String(event.payload.path ?? "")}`;
    case "regression_check":
      return `Regression check: ${event.payload.passed ? "passed" : "FAILED"}`;
    case "mission_timeout":
      return "Mission timed out";
    case "mission_error":
      return `Error: ${String(event.payload.error ?? "").slice(0, 160)}`;
    default:
      return event.type;
  }
}

export interface BenchmarkTimelineProps {
  events: BenchmarkEvent[];
  trialId?: string;
  isLoading?: boolean;
  maxEvents?: number;
}

export function BenchmarkTimeline({ events, trialId, isLoading, maxEvents = 200 }: BenchmarkTimelineProps) {
  const filtered = useMemo(() => {
    const rows = trialId ? events.filter((e) => e.trial_id === trialId) : events;
    // Show most recent events when capped — slice from tail if overflow
    if (rows.length > maxEvents) return rows.slice(rows.length - maxEvents);
    return rows;
  }, [events, trialId, maxEvents]);

  if (isLoading) {
    return (
      <div className="space-y-2 py-2" aria-live="polite" aria-label="Loading timeline">
        {Array.from({ length: 4 }).map((_, i) => (
          <div key={i} className="flex gap-3">
            <div className="h-6 w-6 shrink-0 animate-pulse rounded-full bg-muted" />
            <div className="flex-1 space-y-1.5 pt-1">
              <div className="h-3 w-2/3 animate-pulse rounded bg-muted" />
              <div className="h-2 w-1/3 animate-pulse rounded bg-muted" />
            </div>
          </div>
        ))}
      </div>
    );
  }
  if (filtered.length === 0) {
    return (
      <div className="py-8 text-center" role="status">
        <div className="text-sm text-muted-foreground">No events recorded.</div>
        <div className="mt-1 text-xs text-muted-foreground">Events appear as the benchmark provisions targets, runs exploits, and verifies flags.</div>
      </div>
    );
  }

  const showCapped = events.length > maxEvents && !trialId;
  return (
    <div className="space-y-2">
      {showCapped && (
        <div className="rounded-md bg-muted/40 px-2 py-1.5 text-center text-[11px] text-muted-foreground">
          Showing last {maxEvents} of {events.length} events — full timeline streams live
        </div>
      )}
      <ol className="relative space-y-0" data-testid="benchmark-timeline">
        {filtered.map((event, idx) => {
          const Icon = EVENT_ICON[event.type] ?? Clock;
          const isError = event.level === "error" || event.type.includes("error") || event.type.includes("timeout");
          // run_end carries no `verified` field on failed runs — only the
          // oracle verdict or a completed status counts as verified.
          const isVerified =
            event.type === "oracle_result"
              ? event.payload.verified === true
              : event.type === "run_end"
                ? event.payload.status === "completed"
                : false;
          return (
            <li key={event.sequence} className="relative flex gap-3 pb-4">
              {idx < filtered.length - 1 && (
                <span className="absolute left-[11px] top-6 h-[calc(100%-1rem)] w-px bg-border" aria-hidden />
              )}
              <span
                className={cn(
                  "relative z-10 flex h-6 w-6 shrink-0 items-center justify-center rounded-full border bg-background",
                  isError
                    ? "border-red-500/40 text-red-500"
                    : isVerified
                      ? "border-emerald-500/40 text-emerald-500"
                      : "border-border text-muted-foreground",
                )}
              >
                <Icon className="h-3.5 w-3.5" />
              </span>
              <div className="min-w-0 flex-1 pt-0.5">
                <div className="flex flex-wrap items-baseline gap-x-2">
                  <span className="text-[10px] font-medium tabular-nums text-muted-foreground">
                    {formatDuration(event.elapsed_seconds)}
                  </span>
                  <span className="flex items-center gap-1.5 text-sm">
                    {isError && <AlertCircle className="h-3.5 w-3.5 text-destructive" aria-label="Error" />}
                    {eventLabel(event)}
                  </span>
                </div>
                <div className="mt-0.5 flex flex-wrap gap-2 text-[10px] text-muted-foreground">
                  {event.scenario_id && <span className="font-mono">{event.scenario_id}</span>}
                  {event.tool && (
                    <span className="font-mono">
                      tool: {event.tool}
                      {event.agent ? ` · agent: ${event.agent}` : ""}
                    </span>
                  )}
                  <span className="font-mono">#{event.sequence}</span>
                </div>
              </div>
            </li>
          );
        })}
      </ol>
    </div>
  );
}
