import { memo } from "react";
import { AlertTriangle, CheckCircle2, Cpu, OctagonAlert } from "lucide-react";
import { cn } from "@/lib/utils";
import { formatTokens } from "@/lib/format";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Sparkline } from "@/components/run/Sparkline";
import type { DerivedRun } from "@/lib/deriveRun";
import type { RunResultTelemetry } from "@/api/types";

interface RunTelemetryCardProps {
  telemetry: RunResultTelemetry | null;
  derived: DerivedRun;
  className?: string;
}

type Level = "normal" | "high" | "critical";

function ctxLevel(pct: number): Level {
  if (pct < 70) return "normal";
  if (pct < 90) return "high";
  return "critical";
}

const LEVEL_META: Record<Level, { bar: string; label: string; badge: "success" | "warn" | "danger"; icon: typeof CheckCircle2 }> = {
  normal: { bar: "bg-primary", label: "Normal", badge: "success", icon: CheckCircle2 },
  high: { bar: "bg-primary", label: "Getting high", badge: "warn", icon: AlertTriangle },
  critical: { bar: "bg-primary", label: "Critical", badge: "danger", icon: OctagonAlert },
};

/**
 * LLM usage telemetry: context fill is the headline (normal → getting high →
 * critical), token/call counts are secondary. Context % is emphasized over
 * raw token counts per the redesign spec.
 */
export const RunTelemetryCard = memo(function RunTelemetryCard({
  telemetry,
  derived,
  className,
}: RunTelemetryCardProps) {
  const rawCtxPct = telemetry?.last_ctx_pct;
  const rawCtxWindow = telemetry?.context_window_tokens;
  const rawCtxUsed = telemetry?.last_estimated_context_tokens;
  const rawCalls = telemetry?.calls;
  const rawTokens = telemetry?.total_tokens ?? derived.tokens ?? null;
  const ctxPct = typeof rawCtxPct === "number" && Number.isFinite(rawCtxPct) ? rawCtxPct : null;
  const ctxWindow = typeof rawCtxWindow === "number" && Number.isFinite(rawCtxWindow) ? rawCtxWindow : null;
  const ctxUsed = typeof rawCtxUsed === "number" && Number.isFinite(rawCtxUsed) ? rawCtxUsed : null;
  const remaining =
    ctxUsed != null && ctxWindow != null && Number.isFinite(ctxWindow - ctxUsed)
      ? Math.max(0, ctxWindow - ctxUsed)
      : null;
  const calls = typeof rawCalls === "number" && Number.isFinite(rawCalls) ? rawCalls : null;
  const tokens = typeof rawTokens === "number" && Number.isFinite(rawTokens) ? rawTokens : null;
  const ctxSeries = derived.telemetrySeries
    .map((s) => s.ctxPct)
    .filter((v): v is number => typeof v === "number" && Number.isFinite(v));
  const tokenSeries = derived.telemetrySeries.map((s) => s.tokens).filter((v) => typeof v === "number" && Number.isFinite(v));
  const hasSpark = tokenSeries.length >= 2 || ctxSeries.length >= 2;

  const level = ctxPct != null ? ctxLevel(ctxPct) : null;
  const meta = level ? LEVEL_META[level] : null;
  const barPct = ctxPct != null ? Math.max(0, Math.min(100, Math.round(ctxPct))) : null;

  return (
    <Card className={cn("overflow-hidden", className)}>
      <CardHeader className="px-2.5 py-2 pb-1">
        <CardTitle className="flex items-center gap-1.5 text-xs">
          <Cpu className="h-3.5 w-3.5 text-primary" aria-hidden />
          Telemetry
          {meta && (
            <Badge variant={meta.badge} className="ml-auto gap-1 text-[9px] leading-none">
              <meta.icon className="h-3 w-3" aria-hidden />
              {meta.label}
            </Badge>
          )}
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-2 px-2.5 pb-2 pt-0 text-xs">
        {ctxPct == null ? (
          <p className="text-[11px] leading-snug text-muted-foreground">
            No telemetry yet.
          </p>
        ) : (
          <div className="space-y-1">
            <div className="flex items-center justify-between text-[11px] leading-none text-muted-foreground">
              <span>Context</span>
              <span className="font-mono tabular-nums text-foreground">{ctxPct.toFixed(1)}%</span>
            </div>
            <div
              className="h-1.5 w-full overflow-hidden rounded-full bg-muted"
              role="progressbar"
              aria-valuenow={barPct ?? 0}
              aria-valuemin={0}
              aria-valuemax={100}
              aria-label="Context window usage"
            >
              <div
                className={cn("h-full rounded-full transition-all", meta?.bar)}
                style={{ width: `${barPct ?? 0}%` }}
              />
            </div>
            {ctxUsed != null && ctxWindow != null && (
              <p className="truncate text-[11px] leading-none text-muted-foreground">
                <span className="font-mono tabular-nums text-foreground">
                  {formatTokens(ctxUsed)}
                </span>{" "}
                / <span className="font-mono tabular-nums">{formatTokens(ctxWindow)}</span>{" "}
                {remaining != null && (
                  <>
                    · <span className="font-mono tabular-nums text-foreground">{formatTokens(remaining)}</span> left
                  </>
                )}
              </p>
            )}
          </div>
        )}

        {(tokens != null || calls != null) && (
          <div className="grid grid-cols-2 gap-1.5 font-mono text-[11px]">
            {tokens != null && (
              <StatCell label="tokens" value={tokens.toLocaleString()} />
            )}
            {calls != null && <StatCell label="calls" value={String(calls)} />}
          </div>
        )}

        {hasSpark && (
          <div className={cn("grid gap-1.5", ctxSeries.length >= 2 ? "grid-cols-2" : "grid-cols-1")}>
            <Sparkline
              label="tokens"
              values={tokenSeries}
              className="rounded border bg-card/40 p-1"
            />
            {ctxSeries.length >= 2 && (
              <Sparkline
                label="ctx %"
                values={ctxSeries}
                format={(v) => `${v.toFixed(1)}%`}
                className="rounded border bg-card/40 p-1"
              />
            )}
          </div>
        )}
      </CardContent>
    </Card>
  );
});

function StatCell({ label, value }: { label: string; value: string }) {
  return (
    <div className="space-y-0 rounded border bg-card/40 px-1.5 py-1">
      <div className="text-[9px] uppercase tracking-wide text-muted-foreground">{label}</div>
      <div className="tabular-nums text-foreground">{value}</div>
    </div>
  );
}
