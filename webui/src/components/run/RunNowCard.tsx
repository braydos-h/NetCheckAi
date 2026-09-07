import { memo } from "react";
import { Clock, Cpu, Layers, MessageSquare, Sparkles, Terminal } from "lucide-react";
import { cn, formatRelative, truncate } from "@/lib/utils";
import { fmtElapsed } from "@/lib/format";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { phaseInfo, type DerivedRun } from "@/lib/deriveRun";
import type { RunState } from "@/api/types";

interface RunNowCardProps {
  derived: DerivedRun;
  active: boolean;
  state: RunState;
}

/**
 * "What is BreachPilot doing right now?" — the single operator-facing answer
 * derived from the existing event stream. Never shows chain-of-thought: only
 * the phase, the latest assistant message, the tool currently executing (or
 * waiting on a decision), and run counters the backend already emits.
 */
export const RunNowCard = memo(function RunNowCard({
  derived,
  active,
  state,
}: RunNowCardProps) {
  const info = phaseInfo(derived.phase);
  const waiting = state === "awaiting_input" || state === "awaiting_confirmation";

  return (
    <Card className="border-primary/20 bg-card/60">
      <CardHeader className="px-2.5 py-2 pb-1.5">
        <CardTitle className="flex items-center gap-1.5 text-xs">
          <span className="relative flex h-2 w-2">
            {active && !waiting ? (
              <>
                <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-400/60" />
                <span className="relative inline-flex h-2 w-2 rounded-full bg-emerald-400" />
              </>
            ) : (
              <span className="relative inline-flex h-2 w-2 rounded-full bg-yellow-400" />
            )}
          </span>
          <span className="text-[11px] font-semibold uppercase tracking-wide">Agent</span>
          <span className="font-mono text-[11px] font-normal normal-case tracking-normal text-muted-foreground">{info.label}</span>
          {derived.source && (
            <Badge variant="secondary" className="ml-1 text-[9px] uppercase leading-none">
              {derived.source}
            </Badge>
          )}
          {waiting && (
            <Badge variant="warn" className="ml-auto text-[9px] leading-none">
              waiting
            </Badge>
          )}
        </CardTitle>
      </CardHeader>

      <CardContent className="space-y-1.5 px-2.5 pb-2 pt-0 text-xs">
        <div aria-live="polite">
          <ActivityBlock derived={derived} />
        </div>

        {derived.lastAssistant && (
          <div className="flex gap-1.5 rounded border border-primary/20 bg-primary/5 px-2 py-1.5 text-[11px] leading-snug">
            <Sparkles className="mt-0.5 h-3 w-3 shrink-0 text-primary" aria-hidden />
            <div className="min-w-0 flex-1">
              <p className="truncate whitespace-nowrap break-words text-foreground" title={derived.lastAssistant}>
                {truncate(derived.lastAssistant, 180)}
              </p>
            </div>
          </div>
        )}

        <div className="flex flex-wrap items-center gap-1">
          <Chip icon={<Layers className="h-3 w-3" />} label="rnd" value={derived.round != null ? String(derived.round) : "—"} />
          <Chip icon={<Terminal className="h-3 w-3" />} label="act" value={derived.actions != null ? String(derived.actions) : "—"} />
          <Chip icon={<Clock className="h-3 w-3" />} label="elapsed" value={derived.elapsedSeconds != null ? fmtElapsed(derived.elapsedSeconds) : "—"} />
          <Chip icon={<Cpu className="h-3 w-3" />} label="/min" value={derived.eventsPerMin != null ? String(derived.eventsPerMin) : "—"} />
          {derived.lastMeaningfulAt && (
            <span className="ml-auto inline-flex items-center gap-1 text-[10px] leading-none text-muted-foreground">
              <MessageSquare className="h-3 w-3" aria-hidden />
              {formatRelative(derived.lastMeaningfulAt)}
            </span>
          )}
        </div>
      </CardContent>
    </Card>
  );
});

function ActivityBlock({ derived }: { derived: DerivedRun }) {
  const t = derived.currentTool;
  if (t) {
    const running = t.started;
    return (
      <div className="flex items-center gap-1.5 rounded border bg-card/40 px-2 py-1.5">
        <Terminal className={cn("h-3 w-3 shrink-0", running ? "animate-pulse text-primary" : "text-yellow-300")} aria-hidden />
        <span className="truncate font-mono text-[11px] text-foreground">{t.name}</span>
        {t.args && <span className="hidden min-w-0 flex-1 truncate font-mono text-[10px] text-muted-foreground sm:block">{t.args}</span>}
        <Badge
          variant={running ? "warn" : "info"}
          className="ml-auto shrink-0 text-[9px] leading-none"
          title={running ? "Tool is executing" : "Awaiting operator approval"}
        >
          {running ? "run" : "wait"}
        </Badge>
      </div>
    );
  }
  if (derived.lastTool && derived.lastTool.completed) {
    const ok = derived.lastTool.success === true;
    return (
      <div className="flex items-center gap-1.5 rounded border bg-card/40 px-2 py-1.5">
        <Terminal className={cn("h-3 w-3 shrink-0", ok ? "text-emerald-400" : "text-red-400")} aria-hidden />
        <span className="truncate font-mono text-[11px] text-foreground">{derived.lastTool.name}</span>
        {derived.lastTool.exitCode != null && (
          <span className="font-mono text-[10px] text-muted-foreground">exit {derived.lastTool.exitCode}</span>
        )}
        <Badge variant={ok ? "success" : "danger"} className="ml-auto shrink-0 text-[9px] leading-none">
          {ok ? "done" : "fail"}
        </Badge>
      </div>
    );
  }
  return (
    <p className="rounded border border-dashed px-2 py-1.5 text-[11px] leading-none text-muted-foreground">
      No tool yet — {derived.phase === "starting" ? "booting…" : "working…"}
    </p>
  );
}

function Chip({
  icon,
  label,
  value,
}: {
  icon: React.ReactNode;
  label: string;
  value: string;
}) {
  return (
    <span className="inline-flex items-center gap-1 rounded border bg-card/40 px-1.5 py-0.5 text-[10px] leading-none text-muted-foreground">
      {icon}
      <span className="hidden sm:inline">{label}</span>
      <span className="font-mono tabular-nums text-foreground">{value}</span>
    </span>
  );
}
