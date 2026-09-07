import { useMemo, type ReactNode } from "react";
import { Link } from "react-router-dom";
import {
  Activity,
  AlertTriangle,
  ArrowUpRight,
  BarChart3,
  CheckCircle2,
  Clock3,
  Coins,
  Cpu,
  Gauge,
  HeartPulse,
  History,
  Info,
  OctagonAlert,
  Layers3,
  ListChecks,
  RefreshCw,
  Timer,
  XCircle,
} from "lucide-react";
import { ApiError } from "@/api/client";
import { useRuns, useTelemetry } from "@/api/hooks";
import { isActiveState, isTerminalState, type RunListRow, type RunState, type TelemetryRecord, type TelemetrySummary } from "@/api/types";
import { ErrorState, Skeleton } from "@/components/Loading";
import { StatusBadge } from "@/components/StatusBadge";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import { formatTokens } from "@/lib/format";
import { cn, formatRelative } from "@/lib/utils";

const RUN_LIMIT = 200;
const TELEMETRY_LIMIT = 50;
const DAYS = 14;
const RECENT_RUN_COUNT = 8;
const AXIS_RATIOS = [1, 0.75, 0.5, 0.25, 0];

type Tone = "neutral" | "success" | "danger" | "warning";

interface RunDay {
  date: string;
  total: number;
  completed: number;
  failed: number;
  other: number;
}

interface TokenDay {
  date: string;
  total: number;
  prompt: number;
  completion: number;
  unattributed: number;
  calls: number;
}

interface DailyChartPoint {
  date: string;
  total: number;
  values: Record<string, number>;
}

interface DailyChartSegment {
  key: string;
  label: string;
  className: string;
}

interface StateMeta {
  label: string;
  barClass: string;
}

// Active states share one hue deliberately — they collapse to a single
// "Active" identity; distinct hues are reserved for distinct outcomes.
const STATE_META: Record<RunState, StateMeta> = {
  draft: { label: "Draft", barClass: "bg-muted-foreground/45" },
  preparing: { label: "Preparing", barClass: "bg-muted-foreground/50" },
  awaiting_confirmation: { label: "Active", barClass: "bg-amber-500/80" },
  queued: { label: "Queued", barClass: "bg-muted-foreground/50" },
  running: { label: "Active", barClass: "bg-amber-500/80" },
  awaiting_input: { label: "Active", barClass: "bg-amber-500/80" },
  completed: { label: "Completed", barClass: "bg-emerald-500/85" },
  failed: { label: "Failed", barClass: "bg-destructive/85" },
  cancelled: { label: "Cancelled", barClass: "bg-slate-500/75" },
  interrupted: { label: "Interrupted", barClass: "bg-orange-500/80" },
  cancelling: { label: "Active", barClass: "bg-amber-500/80" },
};

const STATE_ORDER: RunState[] = [
  "running",
  "queued",
  "awaiting_confirmation",
  "awaiting_input",
  "cancelling",
  "completed",
  "failed",
  "cancelled",
  "interrupted",
  "draft",
];

const chartDateFormatter = new Intl.DateTimeFormat(undefined, { month: "numeric", day: "numeric" });
const fullDateFormatter = new Intl.DateTimeFormat(undefined, {
  weekday: "short",
  month: "short",
  day: "numeric",
  year: "numeric",
});

function dayKey(date: Date): string {
  return `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, "0")}-${String(date.getDate()).padStart(2, "0")}`;
}

function dayKeyFromValue(value?: string): string | null {
  if (!value) return null;
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? null : dayKey(date);
}

function dateFromKey(value: string): Date {
  const [year, month, day] = value.split("-").map(Number);
  return new Date(year ?? 0, (month ?? 1) - 1, day ?? 1);
}

function formatChartDay(value: string): string {
  return chartDateFormatter.format(dateFromKey(value));
}

function formatFullDay(value: string): string {
  return fullDateFormatter.format(dateFromKey(value));
}

function lastNDays(n: number): string[] {
  const now = new Date();
  const out: string[] = [];
  for (let i = n - 1; i >= 0; i -= 1) {
    out.push(dayKey(new Date(now.getFullYear(), now.getMonth(), now.getDate() - i)));
  }
  return out;
}

function safeNonNegative(value: number | null | undefined): number {
  return typeof value === "number" && Number.isFinite(value) ? Math.max(0, value) : 0;
}

function timestampMs(value?: string): number {
  if (!value) return Number.NEGATIVE_INFINITY;
  const time = Date.parse(value);
  return Number.isNaN(time) ? Number.NEGATIVE_INFINITY : time;
}

function formatCount(value: number): string {
  return Math.round(value).toLocaleString();
}

function formatPercent(value: number | null | undefined): string {
  if (value == null || !Number.isFinite(value)) return "—";
  return `${Math.round(value)}%`;
}

function ratioPercent(numerator: number, denominator: number): number | null {
  return denominator > 0 ? (numerator / denominator) * 100 : null;
}

function formatRate(value: number | null | undefined): string {
  return value != null && Number.isFinite(value) ? `${value.toFixed(1)} tok/s` : "—";
}

function formatTelemetryError(error: unknown, fallback: string): string {
  return error instanceof ApiError && error.message ? error.message : fallback;
}

export function aggregateRunsByDay(days: string[], rows: RunListRow[]): RunDay[] {
  const points = days.map<RunDay>((date) => ({ date, total: 0, completed: 0, failed: 0, other: 0 }));
  const byDate = new Map(points.map((point) => [point.date, point]));
  for (const row of rows) {
    const point = byDate.get(dayKeyFromValue(row.created_at) ?? "");
    if (!point) continue;
    point.total += 1;
    if (row.state === "completed") point.completed += 1;
    else if (row.state === "failed") point.failed += 1;
    else point.other += 1;
  }
  return points;
}

export function aggregateTokensByDay(days: string[], records: TelemetryRecord[]): TokenDay[] {
  const points = days.map<TokenDay>((date) => ({
    date,
    total: 0,
    prompt: 0,
    completion: 0,
    unattributed: 0,
    calls: 0,
  }));
  const byDate = new Map(points.map((point) => [point.date, point]));
  for (const record of records) {
    const point = byDate.get(dayKeyFromValue(record.started_at ?? record.ended_at) ?? "");
    if (!point) continue;
    const prompt = safeNonNegative(record.prompt_tokens);
    const completion = safeNonNegative(record.completion_tokens);
    const reportedTotal = safeNonNegative(record.total_tokens);
    point.prompt += prompt;
    point.completion += completion;
    point.total += Math.max(reportedTotal, prompt + completion);
    point.calls += 1;
  }
  for (const point of points) {
    point.unattributed = Math.max(0, point.total - point.prompt - point.completion);
  }
  return points;
}

export function StatsPage() {
  const runs = useRuns(RUN_LIMIT, 0);
  const telemetry = useTelemetry();
  const rows = runs.data?.runs ?? [];
  const summary = telemetry.data?.summary;
  const recentTelemetry = telemetry.data?.recent ?? [];
  const days = useMemo(() => lastNDays(DAYS), []);
  const runDays = useMemo(() => aggregateRunsByDay(days, rows), [days, rows]);
  const tokenDays = useMemo(() => aggregateTokensByDay(days, recentTelemetry), [days, recentTelemetry]);
  const stateCounts = useMemo(() => {
    const counts = new Map<RunState, number>();
    for (const row of rows) counts.set(row.state, (counts.get(row.state) ?? 0) + 1);
    return counts;
  }, [rows]);
  const recentRuns = useMemo(
    () => [...rows].sort((a, b) => timestampMs(b.created_at) - timestampMs(a.created_at)).slice(0, RECENT_RUN_COUNT),
    [rows],
  );

  const active = rows.filter((row) => isActiveState(row.state)).length;
  const completed = stateCounts.get("completed") ?? 0;
  const failed = stateCounts.get("failed") ?? 0;
  const cancelled = stateCounts.get("cancelled") ?? 0;
  const interrupted = stateCounts.get("interrupted") ?? 0;
  const terminal = rows.filter((row) => isTerminalState(row.state)).length;
  const successRate = ratioPercent(completed, terminal);
  const llmCalls = summary?.calls ?? 0;
  const llmSuccessRate = summary ? ratioPercent(summary.successful_calls, llmCalls) : null;
  const refreshing = runs.isFetching || telemetry.isFetching;
  const runsAvailable = Boolean(runs.data);
  const telemetryAvailable = Boolean(telemetry.data);
  const telemetryEmpty = Boolean(summary && summary.calls === 0 && recentTelemetry.length === 0);

  return (
    <TooltipProvider delayDuration={120}>
      <div className="mx-auto max-w-[1600px] space-y-5 p-4 md:p-6">
        <header className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
          <div className="flex min-w-0 items-start gap-2.5">
            <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg border bg-card">
              <BarChart3 className="h-5 w-5 text-primary" />
            </div>
            <div className="min-w-0">
              <h1 className="text-lg font-semibold leading-tight">Stats</h1>
              <p className="mt-0.5 text-sm text-muted-foreground">Operational activity and LLM efficiency at a glance.</p>
              <div className="mt-2 flex flex-wrap items-center gap-x-2 gap-y-1 text-[11px] text-muted-foreground">
                <span className="font-mono">Last {RUN_LIMIT} runs</span>
                <span aria-hidden="true">·</span>
                <span className="font-mono">Last {TELEMETRY_LIMIT} LLM calls</span>
                {telemetry.dataUpdatedAt > 0 && (
                  <>
                    <span aria-hidden="true">·</span>
                    <span>telemetry updated {formatRelative(new Date(telemetry.dataUpdatedAt).toISOString())}</span>
                  </>
                )}
              </div>
            </div>
          </div>
          <Button
            size="sm"
            variant="outline"
            className="self-start sm:mt-0"
            onClick={() => void Promise.allSettled([runs.refetch(), telemetry.refetch()])}
            disabled={refreshing}
            aria-label="Refresh runs and telemetry"
          >
            <RefreshCw className={cn("h-3.5 w-3.5", refreshing && "animate-spin")} />
            <span>Refresh</span>
          </Button>
        </header>

        {(runs.error || telemetry.error) && (
          <div className="space-y-2" aria-live="polite">
            {runs.error && (
              <div className="rounded-md border border-destructive/40 bg-destructive/5 p-3">
                <ErrorState
                  message={runs.data ? "Could not refresh runs; showing the last loaded window." : formatTelemetryError(runs.error, "Failed to load runs.")}
                  onRetry={() => void runs.refetch()}
                />
              </div>
            )}
            {telemetry.error && (
              <div className="rounded-md border border-destructive/40 bg-destructive/5 p-3">
                <ErrorState
                  message={telemetry.data ? "Could not refresh telemetry; showing the last loaded summary." : formatTelemetryError(telemetry.error, "Failed to load telemetry.")}
                  onRetry={() => void telemetry.refetch()}
                />
              </div>
            )}
          </div>
        )}

        <section aria-labelledby="stats-overview-heading" className="space-y-3">
          <div className="flex flex-wrap items-end justify-between gap-2">
            <div>
              <h2 id="stats-overview-heading" className="text-sm font-semibold">Overview</h2>
              <p className="text-xs text-muted-foreground">Loaded run outcomes and model usage.</p>
            </div>
            {runs.data?.total != null && runs.data.total > rows.length && (
              <span className="text-[11px] text-muted-foreground">{formatCount(runs.data.total)} stored runs total</span>
            )}
          </div>
          <KpiOverview
            runsAvailable={runsAvailable}
            telemetryAvailable={telemetryAvailable}
            runsLoading={runs.isLoading && !runs.data}
            telemetryLoading={telemetry.isLoading && !telemetry.data}
            loadedRuns={rows.length}
            activeRuns={active}
            completed={completed}
            terminal={terminal}
            successRate={successRate}
            failed={failed}
            cancelled={cancelled}
            interrupted={interrupted}
            summary={summary}
            llmCalls={llmCalls}
            llmSuccessRate={llmSuccessRate}
          />
        </section>

        {runs.isLoading && !runs.data && <RunAnalyticsSkeleton />}
        {runs.data && rows.length === 0 && <EmptyRunsState />}
        {!runs.data && !runs.isLoading && runs.error && (
          <UnavailableCard title="Run analytics unavailable" message="The run window could not be loaded. Retry when the API is available." />
        )}

        {runs.data && rows.length > 0 && (
          <>
            <section aria-labelledby="run-activity-heading" className="space-y-3">
              <div>
                <h2 id="run-activity-heading" className="text-sm font-semibold">Run activity</h2>
                <p className="text-xs text-muted-foreground">Daily activity across the loaded run window.</p>
              </div>
              <div className="grid gap-4 xl:grid-cols-[minmax(0,1.25fr)_minmax(22rem,0.75fr)]">
                <RunsChart data={runDays} />
                <StateDistribution counts={stateCounts} total={rows.length} />
              </div>
            </section>
            <RecentRuns rows={recentRuns} />
          </>
        )}

        <section aria-labelledby="llm-telemetry-heading" className="space-y-3">
          <div className="flex flex-wrap items-end justify-between gap-2">
            <div>
              <h2 id="llm-telemetry-heading" className="text-sm font-semibold">LLM telemetry</h2>
              <p className="text-xs text-muted-foreground">Generation throughput, context pressure, and recent token flow.</p>
            </div>
            {summary?.aliases.length ? <Badge variant="muted">{summary.aliases.join(", ")}</Badge> : null}
          </div>

          {telemetry.isLoading && !telemetry.data && <TelemetrySkeleton />}
          {telemetry.data && summary && telemetryEmpty && <EmptyTelemetryState />}
          {telemetry.data && summary && !telemetryEmpty && (
            <div className="grid gap-4 xl:grid-cols-[minmax(0,1.25fr)_minmax(22rem,0.75fr)]">
              <TokenUsageChart data={tokenDays} />
              <TelemetryOverview summary={summary} recentCount={recentTelemetry.length} />
            </div>
          )}
          {!telemetry.data && !telemetry.isLoading && telemetry.error && (
            <UnavailableCard title="LLM telemetry unavailable" message="Recent model usage could not be loaded. Retry to restore this section." />
          )}
        </section>
      </div>
    </TooltipProvider>
  );
}

function KpiOverview({
  runsAvailable,
  telemetryAvailable,
  runsLoading,
  telemetryLoading,
  loadedRuns,
  activeRuns,
  completed,
  terminal,
  successRate,
  failed,
  cancelled,
  interrupted,
  summary,
  llmCalls,
  llmSuccessRate,
}: {
  runsAvailable: boolean;
  telemetryAvailable: boolean;
  runsLoading: boolean;
  telemetryLoading: boolean;
  loadedRuns: number;
  activeRuns: number;
  completed: number;
  terminal: number;
  successRate: number | null;
  failed: number;
  cancelled: number;
  interrupted: number;
  summary?: TelemetrySummary;
  llmCalls: number;
  llmSuccessRate: number | null;
}) {
  const failureDetails = [
    cancelled > 0 ? `${cancelled} cancelled` : null,
    interrupted > 0 ? `${interrupted} interrupted` : null,
  ].filter(Boolean).join(" · ") || "No cancellations or interruptions";
  const llmFailureCount = summary?.failed_calls ?? 0;
  const llmSuccessCount = summary?.successful_calls ?? 0;

  return (
    <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3 2xl:grid-cols-6">
      <StatCard
        icon={Activity}
        label="Runs loaded"
        value={String(loadedRuns)}
        sub={`${activeRuns} active`}
        tone="neutral"
        loading={runsLoading}
        available={runsAvailable}
      />
      <StatCard
        icon={CheckCircle2}
        label="Success rate"
        value={formatPercent(successRate)}
        sub={terminal > 0 ? `${completed} completed · ${terminal} terminal` : "No terminal runs yet"}
        tone="success"
        loading={runsLoading}
        available={runsAvailable}
      />
      <StatCard
        icon={XCircle}
        label="Failed runs"
        value={String(failed)}
        sub={failureDetails}
        tone="danger"
        loading={runsLoading}
        available={runsAvailable}
      />
      <StatCard
        icon={Coins}
        label="LLM volume"
        value={summary ? formatTokens(safeNonNegative(summary.total_tokens)) : "—"}
        sub={telemetryAvailable ? `${formatCount(llmCalls)} calls · ${formatTokens(safeNonNegative(summary?.prompt_tokens))} prompt` : "Telemetry unavailable"}
        tone="neutral"
        loading={telemetryLoading}
        available={telemetryAvailable}
      />
      <StatCard
        icon={HeartPulse}
        label="LLM reliability"
        value={formatPercent(llmSuccessRate)}
        sub={telemetryAvailable ? `${formatCount(llmSuccessCount)} successful · ${formatCount(llmFailureCount)} failed` : "Telemetry unavailable"}
        tone={llmFailureCount > 0 ? "warning" : "success"}
        loading={telemetryLoading}
        available={telemetryAvailable}
      />
      <StatCard
        icon={Gauge}
        label="Throughput"
        value={summary ? formatRate(summary.average_tokens_per_second) : "—"}
        sub={summary ? `completion ${formatRate(summary.average_completion_tokens_per_second)}` : "Telemetry unavailable"}
        tone="neutral"
        loading={telemetryLoading}
        available={telemetryAvailable}
      />
    </div>
  );
}

function StatCard({
  icon: Icon,
  label,
  value,
  sub,
  tone,
  loading,
  available,
}: {
  icon: typeof Activity;
  label: string;
  value: string;
  sub: string;
  tone: Tone;
  loading: boolean;
  available: boolean;
}) {
  // Values wear text tokens — tone lives on the icon chip only.
  const toneClasses: Record<Tone, { icon: string; value: string; border: string }> = {
    neutral: { icon: "bg-primary/10 text-primary", value: "text-foreground", border: "border-primary/15" },
    success: { icon: "bg-emerald-500/10 text-emerald-700 dark:text-emerald-300", value: "text-foreground", border: "border-emerald-500/20" },
    danger: { icon: "bg-destructive/10 text-red-600 dark:text-red-300", value: "text-foreground", border: "border-destructive/20" },
    warning: { icon: "bg-amber-500/10 text-amber-700 dark:text-amber-300", value: "text-foreground", border: "border-amber-500/20" },
  };
  const classes = toneClasses[tone];

  return (
    <Card className={cn("h-full", classes.border)}>
      <CardContent className="flex min-h-[7.5rem] flex-col justify-between gap-3 p-4">
        <div className="flex items-center justify-between gap-2">
          <span className="text-[10px] font-medium uppercase tracking-wide text-muted-foreground">{label}</span>
          <span className={cn("flex h-7 w-7 items-center justify-center rounded-md", classes.icon)}>
            <Icon className="h-3.5 w-3.5" aria-hidden="true" />
          </span>
        </div>
        <div className="min-w-0">
          {loading ? (
            <Skeleton className="h-7 w-20" />
          ) : (
            <div className={cn("truncate font-mono text-2xl font-semibold tabular-nums", classes.value)}>{available ? value : "—"}</div>
          )}
          <div className="mt-1 truncate text-xs text-muted-foreground">{loading ? <Skeleton className="h-3 w-28" /> : available ? sub : "Data unavailable"}</div>
        </div>
      </CardContent>
    </Card>
  );
}

function RunsChart({ data }: { data: RunDay[] }) {
  const chartData: DailyChartPoint[] = data.map((point) => ({
    date: point.date,
    total: point.total,
    values: { completed: point.completed, failed: point.failed, other: point.other },
  }));
  return (
    <Card className="h-full">
      <CardHeader className="pb-3">
        <div className="flex items-start justify-between gap-3">
          <div>
            <CardTitle className="text-sm">Runs over time</CardTitle>
            <CardDescription className="mt-1">Created runs by day across the latest {RUN_LIMIT}-run window.</CardDescription>
          </div>
          <Badge variant="muted" className="shrink-0">{DAYS} days</Badge>
        </div>
      </CardHeader>
      <CardContent>
        <DailyStackedBarChart
          data={chartData}
          segments={[
            { key: "completed", label: "Completed", className: "bg-emerald-500/85" },
            { key: "failed", label: "Failed", className: "bg-destructive/85" },
            { key: "other", label: "Other", className: "bg-muted-foreground/45" },
          ]}
          formatValue={formatCount}
          emptyLabel="No run activity in this window"
          ariaLabel="Runs over time chart"
          tooltip={(point) => (
            <ChartTooltip
              date={point.date}
              rows={[
                { label: "Total runs", value: formatCount(point.total) },
                { label: "Completed", value: formatCount(point.values.completed ?? 0), colorClass: "bg-emerald-500" },
                { label: "Failed", value: formatCount(point.values.failed ?? 0), colorClass: "bg-destructive" },
                { label: "Other", value: formatCount(point.values.other ?? 0), colorClass: "bg-muted-foreground/60" },
              ]}
            />
          )}
        />
        <ChartLegend
          items={[
            { label: "Completed", className: "bg-emerald-500" },
            { label: "Failed", className: "bg-destructive" },
            { label: "Other states", className: "bg-muted-foreground/60" },
          ]}
        />
      </CardContent>
    </Card>
  );
}

function TokenUsageChart({ data }: { data: TokenDay[] }) {
  const chartData: DailyChartPoint[] = data.map((point) => ({
    date: point.date,
    total: point.total,
    values: { prompt: point.prompt, completion: point.completion, unattributed: point.unattributed },
  }));
  const hasUnattributed = data.some((point) => point.unattributed > 0);
  // Completion is a categorical identity (prompt vs completion), not a status —
  // emerald stays reserved for success states.
  const segments: DailyChartSegment[] = [
    { key: "prompt", label: "Prompt", className: "bg-primary/75" },
    { key: "completion", label: "Completion", className: "bg-sky-500/80" },
  ];
  if (hasUnattributed) segments.push({ key: "unattributed", label: "Unattributed", className: "bg-muted-foreground/45" });

  return (
    <Card className="h-full">
      <CardHeader className="pb-3">
        <div className="flex items-start justify-between gap-3">
          <div>
            <CardTitle className="text-sm">LLM usage over time</CardTitle>
            <CardDescription className="mt-1">Prompt and completion tokens from the latest {TELEMETRY_LIMIT} recorded calls.</CardDescription>
          </div>
          <Badge variant="muted" className="shrink-0">Recent window</Badge>
        </div>
      </CardHeader>
      <CardContent>
        <DailyStackedBarChart
          data={chartData}
          segments={segments}
          formatValue={formatTokens}
          emptyLabel="No recent token activity"
          ariaLabel="LLM token usage over time chart"
          tooltip={(point) => (
            <ChartTooltip
              date={point.date}
              rows={[
                { label: "Total tokens", value: formatTokens(point.total) },
                { label: "Prompt tokens", value: formatTokens(point.values.prompt ?? 0), colorClass: "bg-primary" },
                { label: "Completion tokens", value: formatTokens(point.values.completion ?? 0), colorClass: "bg-sky-500" },
                ...(hasUnattributed
                  ? [{ label: "Unattributed", value: formatTokens(point.values.unattributed ?? 0), colorClass: "bg-muted-foreground/60" }]
                  : []),
                { label: "Recorded calls", value: formatCount(data.find((item) => item.date === point.date)?.calls ?? 0) },
              ]}
            />
          )}
        />
        <ChartLegend
          items={[
            { label: "Prompt", className: "bg-primary" },
            { label: "Completion", className: "bg-sky-500" },
            ...(hasUnattributed ? [{ label: "Unattributed", className: "bg-muted-foreground/60" }] : []),
          ]}
        />
        <p className="mt-3 text-[11px] text-muted-foreground">This chart is limited to recent telemetry; summary KPIs may include older recorded calls.</p>
      </CardContent>
    </Card>
  );
}

function DailyStackedBarChart({
  data,
  segments,
  formatValue,
  emptyLabel,
  ariaLabel,
  tooltip,
}: {
  data: DailyChartPoint[];
  segments: DailyChartSegment[];
  formatValue: (value: number) => string;
  emptyLabel: string;
  ariaLabel: string;
  tooltip: (point: DailyChartPoint) => ReactNode;
}) {
  const max = Math.max(1, ...data.map((point) => point.total));
  const hasData = data.some((point) => point.total > 0);

  return (
    <div className="space-y-2">
      <div className="relative h-64" role="group" aria-label={ariaLabel}>
        <div className="absolute bottom-6 left-8 right-0 top-0" aria-hidden="true">
          {AXIS_RATIOS.map((ratio) => (
            <div key={ratio} className="absolute inset-x-0 border-t border-border/70" style={{ top: `${(1 - ratio) * 100}%` }}>
              <span className="absolute -left-8 -top-2 w-7 text-right text-[9px] tabular-nums text-muted-foreground">
                {formatValue(max * ratio)}
              </span>
            </div>
          ))}
        </div>
        <div className="absolute bottom-6 left-8 right-0 top-0 flex gap-1.5">
          {data.map((point) => {
            const stackTotal = segments.reduce((total, segment) => total + safeNonNegative(point.values[segment.key]), 0);
            const breakdown = segments
              .map((segment) => `${segment.label} ${formatValue(safeNonNegative(point.values[segment.key]))}`)
              .join(", ");
            const ariaLabelForPoint = `${formatFullDay(point.date)}: ${formatValue(point.total)} total, ${breakdown}`;
            return (
              <Tooltip key={point.date}>
                <TooltipTrigger asChild>
                  <button
                    type="button"
                    className="group flex h-full min-w-0 flex-1 flex-col justify-end rounded-sm p-0.5 text-left outline-none transition-colors hover:bg-primary/5 focus-visible:bg-primary/10"
                    aria-label={ariaLabelForPoint}
                  >
                    {point.total > 0 && stackTotal > 0 ? (
                      <div
                        className="flex w-full flex-col-reverse gap-px overflow-hidden rounded-t-sm border border-foreground/10 bg-background p-px shadow-sm transition-[filter] group-hover:brightness-110 group-focus-visible:brightness-110"
                        style={{ height: `${Math.max(6, (point.total / max) * 100)}%` }}
                      >
                        {segments.map((segment) => {
                          const value = safeNonNegative(point.values[segment.key]);
                          if (value === 0) return null;
                          return <div key={segment.key} className={segment.className} style={{ height: `${(value / stackTotal) * 100}%` }} />;
                        })}
                      </div>
                    ) : (
                      <div className="h-px w-full bg-border" aria-hidden="true" />
                    )}
                  </button>
                </TooltipTrigger>
                <TooltipContent side="top" align="center" className="min-w-[12rem] border border-border bg-popover text-popover-foreground shadow-lg">
                  {tooltip(point)}
                </TooltipContent>
              </Tooltip>
            );
          })}
        </div>
        <div className="absolute bottom-0 left-8 right-0 flex h-6 gap-1.5" aria-hidden="true">
          {data.map((point) => (
            <span key={point.date} className="min-w-0 flex-1 truncate text-center text-[9px] tabular-nums text-muted-foreground">
              {formatChartDay(point.date)}
            </span>
          ))}
        </div>
        {!hasData && (
          <div className="pointer-events-none absolute bottom-8 left-8 right-0 top-0 flex items-center justify-center">
            <span className="rounded-md border border-dashed bg-background/80 px-3 py-2 text-xs text-muted-foreground">{emptyLabel}</span>
          </div>
        )}
      </div>
    </div>
  );
}

function ChartTooltip({ date, rows }: { date: string; rows: Array<{ label: string; value: string; colorClass?: string }> }) {
  return (
    <div className="space-y-1.5">
      <div className="font-medium">{formatFullDay(date)}</div>
      <div className="space-y-1">
        {rows.map((row) => (
          <div key={row.label} className="flex items-center justify-between gap-4">
            <span className="flex items-center gap-1.5 text-muted-foreground">
              <span className={cn("h-1.5 w-1.5 rounded-sm", row.colorClass ?? "bg-muted-foreground")} aria-hidden="true" />
              {row.label}
            </span>
            <span className="font-mono tabular-nums">{row.value}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

function ChartLegend({ items }: { items: Array<{ label: string; className: string }> }) {
  return (
    <div className="mt-3 flex flex-wrap gap-x-4 gap-y-1.5 text-[11px] text-muted-foreground" aria-label="Chart legend">
      {items.map((item) => (
        <span key={item.label} className="inline-flex items-center gap-1.5">
          <span className={cn("h-2 w-2 rounded-sm", item.className)} aria-hidden="true" />
          {item.label}
        </span>
      ))}
    </div>
  );
}

function StateDistribution({ counts, total }: { counts: Map<RunState, number>; total: number }) {
  const entries = [...counts.entries()].sort(
    ([stateA, countA], [stateB, countB]) => countB - countA || STATE_ORDER.indexOf(stateA) - STATE_ORDER.indexOf(stateB),
  );

  return (
    <Card className="h-full">
      <CardHeader className="pb-3">
        <div className="flex items-start justify-between gap-3">
          <div>
            <CardTitle className="text-sm">Run state distribution</CardTitle>
            <CardDescription className="mt-1">How the loaded run window is currently resolving.</CardDescription>
          </div>
          <ListChecks className="h-4 w-4 text-muted-foreground" aria-hidden="true" />
        </div>
      </CardHeader>
      <CardContent className="space-y-3">
        {entries.map(([state, count]) => {
          const percentage = ratioPercent(count, total) ?? 0;
          const meta = STATE_META[state];
          return (
            <div key={state} className="space-y-1.5">
              <div className="flex items-center gap-2 text-xs">
                <span className={cn("h-2 w-2 shrink-0 rounded-sm", meta.barClass)} aria-hidden="true" />
                <span className="min-w-0 flex-1 truncate">{meta.label}</span>
                <span className="font-mono tabular-nums text-muted-foreground">{formatCount(count)}</span>
                <span className="w-10 text-right font-mono tabular-nums text-muted-foreground">{formatPercent(percentage)}</span>
              </div>
              <div
                className="h-1.5 overflow-hidden rounded-full bg-muted"
                role="progressbar"
                aria-label={`${meta.label}: ${formatCount(count)} of ${formatCount(total)} runs`}
                aria-valuemin={0}
                aria-valuemax={total}
                aria-valuenow={count}
              >
                <div className={cn("h-full rounded-full transition-[width]", meta.barClass)} style={{ width: `${Math.min(100, percentage)}%` }} />
              </div>
            </div>
          );
        })}
      </CardContent>
    </Card>
  );
}

function TelemetryOverview({ summary, recentCount }: { summary: TelemetrySummary; recentCount: number }) {
  const callSuccessRate = ratioPercent(summary.successful_calls, summary.calls);
  return (
    <Card className="h-full">
      <CardHeader className="pb-3">
        <CardTitle className="text-sm">LLM performance</CardTitle>
        <CardDescription className="mt-1">Summary across recorded telemetry; the chart uses the recent window.</CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="grid gap-3 sm:grid-cols-2">
          <TelemetryMetric
            icon={CheckCircle2}
            label="Call success rate"
            value={formatPercent(callSuccessRate)}
            sub={`${formatCount(summary.successful_calls)} successful · ${formatCount(summary.failed_calls)} failed`}
          />
          <TelemetryMetric
            icon={Gauge}
            label="Average tokens/sec"
            help="Average generated throughput for calls with a measured token rate."
            value={formatRate(summary.average_tokens_per_second)}
            sub={`${formatCount(summary.calls)} total calls`}
          />
          <TelemetryMetric
            icon={Timer}
            label="Completion tokens/sec"
            help="Average completion-only throughput, separate from prompt processing."
            value={formatRate(summary.average_completion_tokens_per_second)}
            sub="Completion generation"
          />
          <TelemetryMetric
            icon={Layers3}
            label="Prompt tokens"
            value={formatTokens(safeNonNegative(summary.prompt_tokens))}
            sub="Recorded input volume"
          />
          <TelemetryMetric
            icon={Coins}
            label="Completion tokens"
            value={formatTokens(safeNonNegative(summary.completion_tokens))}
            sub="Recorded output volume"
          />
          <TelemetryMetric
            icon={Clock3}
            label="Last LLM call"
            value={formatRelative(summary.last_call_at)}
            sub={recentCount > 0 ? `${recentCount} recent records available` : "No recent records"}
            valueTitle={summary.last_call_at || undefined}
          />
        </div>
        <div className="grid gap-4 border-t pt-4 sm:grid-cols-2">
          <ContextMeter label="Average context usage" value={summary.average_context_usage_pct} />
          <ContextMeter label="Maximum context usage" value={summary.max_context_usage_pct} />
        </div>
      </CardContent>
    </Card>
  );
}

function TelemetryMetric({
  icon: Icon,
  label,
  value,
  sub,
  help,
  valueTitle,
}: {
  icon: typeof Activity;
  label: string;
  value: string;
  sub: string;
  help?: string;
  valueTitle?: string;
}) {
  return (
    <div className="min-w-0 rounded-md border bg-card/40 p-3">
      <div className="flex items-center gap-1.5 text-[10px] uppercase tracking-wide text-muted-foreground">
        <Icon className="h-3 w-3" aria-hidden="true" />
        <span className="truncate">{label}</span>
        {help && <MetricHelp label={label} help={help} />}
      </div>
      <div className="mt-1 truncate font-mono text-base font-semibold tabular-nums" title={valueTitle}>{value}</div>
      <div className="mt-0.5 truncate text-[11px] text-muted-foreground">{sub}</div>
    </div>
  );
}

function MetricHelp({ label, help }: { label: string; help: string }) {
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <button type="button" className="inline-flex h-4 w-4 items-center justify-center rounded-sm text-muted-foreground hover:text-foreground" aria-label={`${label} information`}>
          <Info className="h-3 w-3" aria-hidden="true" />
        </button>
      </TooltipTrigger>
      <TooltipContent className="max-w-[16rem] border border-border bg-popover text-popover-foreground shadow-lg">{help}</TooltipContent>
    </Tooltip>
  );
}

function ContextMeter({ label, value }: { label: string; value: number | null }) {
  const percentage = value != null && Number.isFinite(value) ? value : null;
  const clamped = percentage == null ? 0 : Math.min(100, Math.max(0, percentage));
  // One magnitude, one hue — High/Critical ride on the badge + icon, not the fill.
  const level = percentage != null && percentage >= 90 ? "critical" : percentage != null && percentage >= 75 ? "high" : null;
  const LevelIcon = level === "critical" ? OctagonAlert : level === "high" ? AlertTriangle : null;

  return (
    <div>
      <div className="flex items-center justify-between gap-2 text-xs">
        <span className="flex items-center gap-1.5">
          <span className="font-medium">{label}</span>
          <MetricHelp label={label} help="Estimated context tokens as a percentage of the configured model context window. Higher values mean less remaining context, not an automatic error." />
        </span>
        <span className="flex items-center gap-1.5 font-mono font-semibold tabular-nums">
          {formatPercent(percentage)}
          {level && LevelIcon && (
            <span className={cn("inline-flex items-center gap-0.5 text-[10px] uppercase tracking-wide", level === "critical" ? "text-destructive" : "text-amber-700 dark:text-amber-300")}>
              <LevelIcon className="h-3 w-3" aria-hidden />
              {level}
            </span>
          )}
        </span>
      </div>
      <div
        className="mt-2 h-2 overflow-hidden rounded-full bg-muted"
        role="meter"
        aria-label={label}
        aria-valuemin={0}
        aria-valuemax={100}
        aria-valuenow={percentage == null ? undefined : clamped}
        aria-valuetext={percentage == null ? "No context sample" : `${percentage.toFixed(1)} percent`}
      >
        {percentage != null && <div className="h-full rounded-full bg-primary transition-[width]" style={{ width: `${clamped}%` }} />}
      </div>
      <p className="mt-1 text-[10px] text-muted-foreground">Higher means less remaining context.</p>
    </div>
  );
}

function RecentRuns({ rows }: { rows: RunListRow[] }) {
  return (
    <section aria-labelledby="recent-runs-heading" className="space-y-3">
      <div className="flex flex-wrap items-end justify-between gap-2">
        <div>
          <h2 id="recent-runs-heading" className="text-sm font-semibold">Recent runs</h2>
          <p className="text-xs text-muted-foreground">A compact snapshot of the latest loaded activity.</p>
        </div>
        <Badge variant="muted"><History className="h-3 w-3" /> Latest {rows.length}</Badge>
      </div>
      <Card>
        <CardContent className="p-0">
          <div className="divide-y">
            {rows.map((row) => {
              const title = row.title || row.target || row.target_ip || "Untitled run";
              const target = row.target || row.target_ip || "Target unavailable";
              return (
                <Link
                  key={row.id}
                  to={`/runs/${row.id}`}
                  className="flex min-w-0 items-start gap-3 p-3 transition-colors hover:bg-primary/5 focus-visible:bg-primary/10"
                  aria-label={`Open ${title}, ${row.state}`}
                >
                  <StatusBadge state={row.state} className="mt-0.5 shrink-0" />
                  <div className="min-w-0 flex-1">
                    <div className="truncate text-sm font-medium">{title}</div>
                    <div className="mt-0.5 truncate font-mono text-[11px] text-muted-foreground">{target}</div>
                    <div className="mt-2 flex flex-wrap gap-x-3 gap-y-1 text-[11px] text-muted-foreground">
                      <span><span className="text-foreground/70">mode</span> {row.mode}</span>
                      <span className="max-w-[15rem] truncate"><span className="text-foreground/70">goal</span> {row.goal_name || "—"}</span>
                      <span className="font-mono"><span className="font-sans text-foreground/70">model</span> {row.model_alias || "—"}</span>
                    </div>
                  </div>
                  <div className="flex shrink-0 items-center gap-1 text-right text-[11px] text-muted-foreground">
                    <time dateTime={row.created_at} title={row.created_at}>{formatRelative(row.created_at)}</time>
                    <ArrowUpRight className="h-3.5 w-3.5" aria-hidden="true" />
                  </div>
                </Link>
              );
            })}
          </div>
        </CardContent>
      </Card>
    </section>
  );
}

function RunAnalyticsSkeleton() {
  return (
    <div className="grid gap-4 xl:grid-cols-[minmax(0,1.25fr)_minmax(22rem,0.75fr)]" role="status" aria-label="Loading run analytics">
      <Card>
        <CardHeader><Skeleton className="h-4 w-32" /><Skeleton className="h-3 w-56" /></CardHeader>
        <CardContent><Skeleton className="h-64 w-full" /></CardContent>
      </Card>
      <Card>
        <CardHeader><Skeleton className="h-4 w-40" /><Skeleton className="h-3 w-64" /></CardHeader>
        <CardContent className="space-y-4"><Skeleton className="h-6 w-full" /><Skeleton className="h-6 w-full" /><Skeleton className="h-6 w-full" /><Skeleton className="h-6 w-full" /></CardContent>
      </Card>
    </div>
  );
}

function TelemetrySkeleton() {
  return (
    <div className="grid gap-4 xl:grid-cols-[minmax(0,1.25fr)_minmax(22rem,0.75fr)]" role="status" aria-label="Loading LLM telemetry">
      <Card><CardContent className="p-4"><Skeleton className="h-64 w-full" /></CardContent></Card>
      <Card><CardContent className="grid gap-3 p-4 sm:grid-cols-2"><Skeleton className="h-20 w-full" /><Skeleton className="h-20 w-full" /><Skeleton className="h-20 w-full" /><Skeleton className="h-20 w-full" /><Skeleton className="h-20 w-full" /><Skeleton className="h-20 w-full" /></CardContent></Card>
    </div>
  );
}

function EmptyRunsState() {
  return (
    <Card>
      <CardContent className="flex flex-col items-center justify-center gap-3 p-8 text-center">
        <span className="flex h-10 w-10 items-center justify-center rounded-full bg-primary/10 text-primary"><Activity className="h-5 w-5" /></span>
        <div>
          <h2 className="font-medium">No run data yet</h2>
          <p className="mt-1 text-sm text-muted-foreground">Start a run and activity will appear here.</p>
        </div>
        <Button asChild size="sm"><Link to="/runs/new">Start a run</Link></Button>
      </CardContent>
    </Card>
  );
}

function EmptyTelemetryState() {
  return (
    <Card>
      <CardContent className="flex flex-col items-center justify-center gap-3 p-8 text-center">
        <span className="flex h-10 w-10 items-center justify-center rounded-full bg-primary/10 text-primary"><Cpu className="h-5 w-5" /></span>
        <div>
          <h2 className="font-medium">No LLM telemetry yet</h2>
          <p className="mt-1 text-sm text-muted-foreground">Usage and performance will appear after the first model call.</p>
        </div>
      </CardContent>
    </Card>
  );
}

function UnavailableCard({ title, message }: { title: string; message: string }) {
  return (
    <Card className="border-destructive/30">
      <CardContent className="flex items-center gap-3 p-4 text-sm">
        <AlertTriangle className="h-4 w-4 shrink-0 text-destructive" aria-hidden="true" />
        <div>
          <div className="font-medium">{title}</div>
          <div className="mt-0.5 text-muted-foreground">{message}</div>
        </div>
      </CardContent>
    </Card>
  );
}
