import { memo } from "react";
import {
  Activity,
  AlertTriangle,
  Clock,
  FileCheck,
  Layers,
  MessageSquare,
  ShieldCheck,
  Terminal,
} from "lucide-react";
import { cn, truncate } from "@/lib/utils";
import { fmtElapsed } from "@/lib/format";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { phaseInfo, type DerivedRun } from "@/lib/deriveRun";
import type { RunState } from "@/api/types";
import { isTerminalState } from "@/api/types";

interface LiveRunSummaryProps {
  derived: DerivedRun;
  runState?: RunState;
  className?: string;
}

/**
 * Rail summary — the "health → progress → errors → activity" reading order.
 * Pure presentation over {@link DerivedRun}; telemetry values live in
 * RunTelemetryCard so nothing is shown twice.
 */
export const LiveRunSummary = memo(function LiveRunSummary({
  derived,
  runState,
  className,
}: LiveRunSummaryProps) {
  const terminal = isTerminalState(runState as RunState);
  const hasAny =
    derived.phase ||
    derived.round != null ||
    derived.actions != null ||
    derived.lastTool?.name ||
    derived.lastAssistant ||
    derived.bootTotal > 0;

  if (!hasAny) {
    return (
      <Card className={cn(className)}>
        <CardHeader className="px-2.5 py-2 pb-1">
          <CardTitle className="flex items-center gap-1.5 text-xs">
            <Activity className="h-3.5 w-3.5" aria-hidden /> Live activity
          </CardTitle>
        </CardHeader>
        <CardContent className="px-2.5 pb-2 pt-0 text-xs text-muted-foreground">
          Waiting…
        </CardContent>
      </Card>
    );
  }

  const bootComplete = derived.bootTotal > 0 && derived.bootDone >= derived.bootTotal;
  const errorCount = derived.toolErrors + derived.errorEvents;
  const info = phaseInfo(derived.phase);

  const health = terminal
    ? { tone: "neutral", text: "Finished" }
    : derived.bootTotal > 0 && !bootComplete
      ? { tone: "warn", text: `Booting ${derived.bootDone}/${derived.bootTotal}` }
      : errorCount > 0
        ? { tone: "danger", text: `${errorCount} error${errorCount === 1 ? "" : "s"}` }
        : { tone: "ok", text: "Running" };

  return (
    <Card className={cn("overflow-hidden", className)}>
      <CardHeader className="px-2.5 py-2 pb-1">
        <CardTitle className="flex items-center gap-1.5 text-xs">
          <Activity className="h-3.5 w-3.5 text-primary" aria-hidden /> Run activity
          {derived.phase && (
            <Badge variant="info" className="ml-auto font-mono text-[9px] uppercase leading-none">
              {info.short}
            </Badge>
          )}
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-1.5 px-2.5 pb-2 pt-0 text-xs">
        <div className="flex items-center gap-1.5 leading-none">
          {health.tone === "ok" ? (
            <span className="relative flex h-2 w-2">
              <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-400/60" />
              <span className="relative inline-flex h-2 w-2 rounded-full bg-emerald-400" />
            </span>
          ) : (
            <ShieldCheck className={cn("h-3 w-3", health.tone === "danger" ? "text-red-400" : health.tone === "warn" ? "text-yellow-300" : "text-muted-foreground")} aria-hidden />
          )}
          <span
            className={cn(
              "text-[11px] font-medium leading-none",
              health.tone === "danger"
                ? "text-red-300"
                : health.tone === "warn"
                  ? "text-yellow-300"
                  : health.tone === "ok"
                    ? "text-emerald-300"
                    : "text-muted-foreground",
            )}
          >
            {health.text}
          </span>
        </div>

        <div className="grid grid-cols-3 gap-1 font-mono text-[11px]">
          <Stat icon={<Layers className="h-3 w-3" />} label="rnd" value={derived.round != null ? String(derived.round) : "—"} />
          <Stat icon={<Terminal className="h-3 w-3" />} label="act" value={derived.actions != null ? String(derived.actions) : "—"} />
          <Stat icon={<Clock className="h-3 w-3" />} label="elap" value={derived.elapsedSeconds != null ? fmtElapsed(derived.elapsedSeconds) : "—"} />
        </div>

        <div className="grid grid-cols-4 gap-1 font-mono text-[11px]">
          <Stat icon={<Terminal className="h-3 w-3" />} label="tools" value={String(derived.toolCount)} />
          <Stat icon={<MessageSquare className="h-3 w-3" />} label="msgs" value={String(derived.assistantCount)} />
          <Stat icon={<FileCheck className="h-3 w-3" />} label="arts" value={String(derived.artifacts)} />
          <Stat icon={<Activity className="h-3 w-3" />} label="/min" value={derived.eventsPerMin != null ? String(derived.eventsPerMin) : "—"} />
        </div>

        {errorCount > 0 && (
          <div className="flex items-center gap-1.5 rounded border border-destructive/40 bg-destructive/10 px-1.5 py-1 text-[11px] leading-none text-red-300">
            <AlertTriangle className="h-3 w-3 shrink-0" aria-hidden />
            <span className="truncate">
              {derived.toolErrors > 0 && `${derived.toolErrors} fail`}
              {derived.toolErrors > 0 && derived.errorEvents > 0 && " · "}
              {derived.errorEvents > 0 && `${derived.errorEvents} err`}
            </span>
          </div>
        )}

        {derived.lastTool?.name && (
          <div className="flex items-center gap-1.5 rounded border bg-muted/30 px-2 py-1">
            <Terminal className="h-3 w-3 shrink-0 text-muted-foreground" aria-hidden />
            <span className="truncate font-mono text-[11px] text-foreground">{derived.lastTool.name}</span>
            <Badge
              variant={
                derived.lastTool.completed
                  ? derived.lastTool.success === true
                    ? "success"
                    : "danger"
                  : derived.lastTool.started
                    ? "warn"
                    : "info"
              }
              className="ml-auto shrink-0 text-[9px] leading-none"
            >
              {derived.lastTool.completed
                ? derived.lastTool.success === true
                  ? "done"
                  : "fail"
                : derived.lastTool.started
                  ? "run"
                  : "wait"}
            </Badge>
          </div>
        )}

        {derived.lastAssistant && (
          <div className="rounded border border-primary/20 bg-primary/5 px-2 py-1 text-[11px] leading-snug">
            <p className="truncate whitespace-nowrap break-words text-foreground" title={derived.lastAssistant}>
              {truncate(derived.lastAssistant, 120)}
            </p>
          </div>
        )}
      </CardContent>
    </Card>
  );
});

function Stat({
  icon,
  label,
  value,
}: {
  icon: React.ReactNode;
  label: string;
  value: string;
}) {
  return (
    <div className="space-y-0 rounded border bg-card/40 px-1.5 py-1">
      <div className="flex items-center gap-1 text-muted-foreground">
        {icon}
        <span className="text-[9px] uppercase tracking-wide">{label}</span>
      </div>
      <div className="tabular-nums text-foreground">{value}</div>
    </div>
  );
}
