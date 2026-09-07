// BreachPilot by @braydos-h — https://github.com/braydos-h/BreachPilot
// Benchmark run detail — tabbed like the normal run page (RunPage).
// Layout: header + live bar, main tabs (Overview/Trials/Timeline/Evidence/Config)
// + aside telemetry. Incremental event polling, progressive skeletons, live progress.
//
// Live-progress note: run.json's `trials` array is only persisted at finalize,
// so during an active run this page polls `/runs/{id}/scenarios` (the runner
// writes each trial JSON the moment it ends) and merges those into the UI.
import { useMemo, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { keepPreviousData, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  AlertTriangle,
  BarChart3,
  ClipboardList,
  Clock3,
  FileSearch,
  FlaskConical,
  GitCommitHorizontal,
  Loader2,
  ScrollText,
  Settings2,
  ShieldCheck,
  XCircle,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Skeleton } from "@/components/ui/skeleton";
import { ErrorState } from "@/components/Loading";
import { toast } from "@/hooks/use-toast";
import {
  cancelBenchmarkRun,
  fetchOverview,
  fetchRun,
  fetchRunEvents,
  fetchRunScenarios,
  saveBaseline,
} from "@/features/benchmarks/api";
import { isActiveState, isOrphanedRun, runStatusToBadge } from "@/features/benchmarks/format";
import { MetricCards, formatCost, formatDuration, formatPct } from "@/features/benchmarks/MetricCards";
import { ScenarioResultsTable, StatusBadge } from "@/features/benchmarks/ScenarioResultsTable";
import { BenchmarkTimeline } from "@/features/benchmarks/BenchmarkTimeline";
import type { BenchmarkEvent, RunDetail, Trial } from "@/features/benchmarks/types";
import { formatRelative } from "@/lib/utils";

const REFRESH_MS = 2000;

function isRunActive(status: string): boolean {
  return isActiveState(status);
}

function derivePhases(trial: Trial | undefined): Array<{ label: string; state: "done" | "running" | "pending" }> {
  if (!trial) {
    return [
      { label: "Provision", state: "pending" },
      { label: "Exploit", state: "pending" },
      { label: "Verify", state: "pending" },
    ];
  }
  const done = trial.ended_at !== "";
  return [
    { label: "Provision", state: "done" },
    { label: "Exploit", state: done ? "done" : "running" },
    { label: "Verify", state: done ? "done" : "pending" },
  ];
}

export function BenchmarkRunPage() {
  const { runId = "" } = useParams();
  const queryClient = useQueryClient();
  const [tab, setTab] = useState("overview");
  const [timelineTrial, setTimelineTrial] = useState<string>("");

  const run = useQuery({
    queryKey: ["benchmarks", "run", runId],
    queryFn: () => fetchRun(runId),
    enabled: !!runId,
    placeholderData: keepPreviousData,
    staleTime: 5_000,
    gcTime: 5 * 60_000,
    refetchInterval: (query) => {
      const data = query.state.data as RunDetail | undefined;
      if (!data) return false;
      // While the overview hasn't delivered a verdict on ownership, keep
      // polling anything that looks in-flight (or lacks a summary).
      const ov = queryClient.getQueryData<{ active?: { run_id: string | null; state: string } }>([
        "benchmarks",
        "overview",
      ]);
      if (ov?.active) {
        // Overview knows the truth: poll only while it says WE are the active run.
        return ov.active.run_id === runId && isActiveState(ov.active.state) ? REFRESH_MS : false;
      }
      return isRunActive(data.status) || !data.summary ? REFRESH_MS : false;
    },
  });

  const overview = useQuery({
    queryKey: ["benchmarks", "overview"],
    queryFn: fetchOverview,
    placeholderData: keepPreviousData,
    staleTime: 15_000,
    refetchInterval: (query) => {
      const active = query.state.data?.active;
      if (active?.run_id === runId && isActiveState(active.state)) return REFRESH_MS;
      if (run.data && isRunActive(run.data.status)) return REFRESH_MS;
      return false;
    },
  });

  // A run whose status still says "running" but that no runner owns (daemon
  // restarted mid-run) will never progress — detect it and stop treating the
  // page as live.
  const orphaned = isOrphanedRun(run.data?.status, overview.data, runId);

  const events = useQuery<{ events: BenchmarkEvent[]; latest_sequence?: number }>({
    queryKey: ["benchmarks", "run-events", runId],
    queryFn: async (): Promise<{ events: BenchmarkEvent[]; latest_sequence?: number }> => {
      const cached = queryClient.getQueryData<{ events: BenchmarkEvent[]; latest_sequence?: number }>([
        "benchmarks",
        "run-events",
        runId,
      ]);
      const hasCached = !!cached?.events?.length;
      if (hasCached) {
        const cursor = cached?.latest_sequence ?? (cached?.events[cached.events.length - 1]?.sequence ?? 0);
        const data = await fetchRunEvents(runId, { after: cursor, limit: 1000 });
        if (data.events.length === 0) return cached as { events: BenchmarkEvent[]; latest_sequence?: number };
        const merged = [...(cached?.events ?? []), ...data.events];
        const seen = new Set<number>();
        const deduped: BenchmarkEvent[] = [];
        for (const e of merged) {
          if (!seen.has(e.sequence)) {
            seen.add(e.sequence);
            deduped.push(e);
          }
        }
        return { events: deduped, latest_sequence: data.latest_sequence };
      }
      let cursor = 0;
      let all: BenchmarkEvent[] = [];
      let latest = 0;
      for (let page = 0; page < 5; page++) {
        const data = await fetchRunEvents(runId, { after: cursor, limit: 1000 });
        all = all.concat(data.events);
        latest = data.latest_sequence;
        if (data.events.length < 1000) break;
        cursor = data.latest_sequence;
      }
      return { events: all, latest_sequence: latest };
    },
    enabled: !!runId,
    placeholderData: keepPreviousData,
    staleTime: 2_000,
    refetchInterval: () => {
      if (!run.data) return REFRESH_MS;
      if (orphaned) return false;
      return isRunActive(run.data.status) ? REFRESH_MS : false;
    },
  });

  // Live per-trial results: the runner persists each trial JSON as soon as it
  // ends, while run.json's trial list only lands at finalize. Without this the
  // progress bar/active-trial strip would show nothing during a live run.
  // Orphaned runs fetch once (no polling) to recover their completed trials.
  const runScenarios = useQuery({
    queryKey: ["benchmarks", "run-scenarios", runId],
    queryFn: () => fetchRunScenarios(runId),
    enabled: !!runId && !!run.data && isRunActive(run.data.status),
    placeholderData: keepPreviousData,
    staleTime: 2_000,
    refetchInterval: () => {
      if (!run.data || orphaned) return false;
      return isRunActive(run.data.status) ? REFRESH_MS : false;
    },
  });

  const cancelMutation = useMutation({
    mutationFn: () => cancelBenchmarkRun(runId),
    onSuccess: () => {
      toast({ title: "Cancelling benchmark run", description: "The runner stops after the current trial step." });
      void run.refetch();
    },
    onError: (err) => {
      toast({
        title: "Cancel failed",
        description: err instanceof Error ? err.message : String(err),
        variant: "destructive",
      });
    },
  });

  const baselineMutation = useMutation({
    mutationFn: () => saveBaseline(runId),
    onSuccess: (res) => {
      toast({ title: "Baseline saved", description: res.path || "Regression baseline persisted." });
      void run.refetch();
    },
    onError: (err) => {
      toast({
        title: "Could not save baseline",
        description: err instanceof Error ? err.message : String(err),
        variant: "destructive",
      });
    },
  });

  const isActiveRun =
    (overview.data?.active.run_id === runId && isActiveState(overview.data.active.state)) ||
    (!overview.isSuccess && run.data ? isRunActive(run.data.status) : false);

  // Merge finalized trials with live per-trial results. run.json's trials
  // array is empty until finalize, so during a live run the scenarios
  // endpoint is the only source of completed-trial progress.
  const liveTrials = runScenarios.data?.scenarios ?? [];
  const activeTrial: Trial | undefined = useMemo(() => {
    const stored = run.data?.trials ?? [];
    const trials = stored.length > 0 ? stored : liveTrials;
    return [...trials].reverse().find((t) => !t.ended_at);
  }, [run.data?.trials, liveTrials]);

  if (run.isLoading && !run.data) {
    return (
      <div className="flex min-h-0 flex-col gap-2 p-2 xl:h-full xl:overflow-hidden" role="status" aria-live="polite">
        <div className="rounded-md border bg-card/50 px-2.5 py-2">
          <div className="flex items-center gap-2">
            <Skeleton className="h-5 w-40" />
            <Skeleton className="h-4 w-16 rounded-full" />
          </div>
          <div className="mt-1.5 flex flex-wrap gap-x-2 gap-y-1">
            <Skeleton className="h-3 w-32" />
            <Skeleton className="h-3 w-24" />
            <Skeleton className="h-3 w-28" />
          </div>
        </div>
        <div className="flex flex-1 gap-2 xl:overflow-hidden">
          <div className="flex flex-1 flex-col gap-2">
            <Skeleton className="h-20 rounded-md" />
            <Skeleton className="h-[40vh] flex-1 rounded-md xl:min-h-0" />
          </div>
          <div className="hidden w-[320px] xl:block">
            <Skeleton className="h-[60vh] rounded-md" />
          </div>
        </div>
      </div>
    );
  }
  if (run.isError || !run.data) {
    return (
      <div className="mx-auto w-full max-w-6xl p-4 md:p-6">
        <ErrorState
          message={run.error instanceof Error ? run.error.message : "Benchmark run not found"}
          onRetry={() => void run.refetch()}
        />
      </div>
    );
  }

  const data = run.data;
  const summary = data.summary;
  const env = data.environment;
  const manifest = data.replay_manifest;
  const phases = derivePhases(activeTrial);

  const displayTrials: Trial[] = data.trials.length > 0 ? data.trials : liveTrials;
  const trialsAreLive = data.trials.length === 0 && liveTrials.length > 0;

  const onCancel = () => cancelMutation.mutate();
  const onSaveBaseline = () => baselineMutation.mutate();

  const totalTrials = data.config.trials * Math.max(1, data.scenario_ids.length || displayTrials.length || 1);
  const completedTrials = displayTrials.filter((t) => t.ended_at).length;  const progressPct = totalTrials > 0 ? Math.min(100, Math.round((completedTrials / totalTrials) * 100)) : 0;
  const eventList = events.data?.events ?? [];
  const elapsedSec = eventList.length > 0 ? (eventList[eventList.length - 1]?.elapsed_seconds ?? 0) : 0;
  const eventCount = eventList.length;
  const trialIds = [...new Set(displayTrials.map((t) => t.trial_id))];
  const headerBadge = orphaned ? "INTERRUPTED" : isActiveRun ? "RUNNING" : runStatusToBadge(data.status);

  // Instant-finish diagnosis: a completed run whose trials all failed in the
  // provision/sandbox preflight never attempted exploitation — surface the
  // remediation at the top instead of burying it in the Evidence tab.
  const provisionFailed = summary?.failure_categories?.["TARGET_PROVISION_FAILED"] ?? 0;
  const sandboxFailed = summary?.failure_categories?.["SANDBOX_FAILED"] ?? 0;
  const infraDetail =
    displayTrials.find(
      (t) => t.failure_detail && (t.failure_category === "TARGET_PROVISION_FAILED" || t.failure_category === "SANDBOX_FAILED"),
    )?.failure_detail ?? "";
  const showProvisionBanner = !isActiveRun && !orphaned && data.status === "completed" && provisionFailed > 0;
  const showSandboxBanner = !isActiveRun && !orphaned && data.status === "completed" && sandboxFailed > 0;

  return (
    <div className="flex min-h-0 flex-col gap-2 p-2 xl:h-full xl:flex-1 xl:overflow-hidden">
      {/* Header — mirrors RunCommandHeader */}
      <div className="rounded-md border bg-card/50 px-2.5 py-2">
        <div className="flex flex-wrap items-center gap-2">
          <Link to="/benchmarks" className="text-xs text-muted-foreground underline-offset-4 hover:underline">
            Benchmarks
          </Link>
          <span className="text-muted-foreground">/</span>
          <h1 className="flex items-center gap-2 font-mono text-sm font-semibold">
            <FlaskConical className="h-4 w-4 text-primary" />
            {data.run_id}
          </h1>
          <StatusBadge status={headerBadge} />
          <span className="text-xs text-muted-foreground">
            {data.suite} · {displayTrials[0]?.started_at ? formatRelative(displayTrials[0].started_at) : "new run"}
          </span>
          {isActiveRun && (
            <span className="flex items-center gap-1 rounded-full bg-yellow-500/10 px-2 py-0.5 text-xs text-yellow-300">
              <span className="h-2 w-2 animate-pulse rounded-full bg-yellow-400" />
              live · {completedTrials}/{totalTrials} · {eventCount} events
            </span>
          )}
          <span className="ml-auto flex items-center gap-2">
            {isActiveRun ? (
              <Button size="sm" variant="destructive" className="h-7" onClick={onCancel} disabled={cancelMutation.isPending}>
                {cancelMutation.isPending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <XCircle className="h-3.5 w-3.5" />}
                Cancel
              </Button>
            ) : summary ? (
              <Button size="sm" variant="outline" className="h-7" onClick={onSaveBaseline} disabled={baselineMutation.isPending}>
                {baselineMutation.isPending && <Loader2 className="h-3.5 w-3.5 animate-spin" />}
                Save baseline
              </Button>
            ) : null}
          </span>
        </div>
        <div className="mt-1.5 flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-muted-foreground">
          <span className="flex items-center gap-1">
            <ClipboardList className="h-3 w-3" /> {data.config.trials} trial(s) × {data.scenario_ids.length || data.trials.length || 1} scenario(s)
          </span>
          <span className="flex items-center gap-1">
            <Clock3 className="h-3 w-3" /> timeout {formatDuration(data.config.timeout_seconds)}
          </span>
          <span className="flex items-center gap-1">
            <ShieldCheck className="h-3 w-3" /> sandbox {data.config.sandbox_required ? "required" : "optional"} · {env.sandbox_enabled ? "enabled" : "disabled"}
          </span>
          <span className="font-mono text-[11px]">{data.config.tags.length ? `tags: ${data.config.tags.join(", ")}` : "all tags"}</span>
        </div>
        {isActiveRun && (
          <div className="mt-2">
            <div className="h-1.5 w-full overflow-hidden rounded-full bg-muted">
              <div className="h-full bg-yellow-500 transition-all duration-500" style={{ width: `${progressPct}%` }} />
            </div>
            <div className="mt-1 flex items-center gap-2 text-[11px] text-muted-foreground">
              <Loader2 className="h-3 w-3 animate-spin" /> {completedTrials}/{totalTrials} trials completed
              {activeTrial ? ` · now: ${activeTrial.scenario_id}` : ""}
              <span className="ml-auto tabular-nums">
                {formatDuration(elapsedSec)} · {eventCount} events · polling 2s
              </span>
            </div>
          </div>
        )}
      </div>

      {/* Orphaned run: status frozen at "running" because the daemon restarted mid-run */}
      {orphaned && (
        <Card className="border-amber-500/30 bg-amber-500/5" data-testid="benchmark-interrupted-banner">
          <CardContent className="flex flex-wrap items-center gap-3 py-3">
            <AlertTriangle className="h-4 w-4 shrink-0 text-amber-400" />
            <span className="text-sm font-medium text-amber-400">Run interrupted</span>
            <span className="min-w-0 flex-1 text-xs text-muted-foreground">
              The run's status stayed “running”, but no benchmark runner currently owns it — the daemon was most
              likely restarted mid-run. Trials completed before the interruption are kept below; the run cannot be
              resumed or cancelled.
            </span>
          </CardContent>
        </Card>
      )}

      {/* Lab down: the run finished in seconds without attempting exploitation */}
      {showProvisionBanner && (
        <Card className="border-amber-500/30 bg-amber-500/5" data-testid="benchmark-infra-banner">
          <CardContent className="flex flex-wrap items-center gap-3 py-3">
            <AlertTriangle className="h-4 w-4 shrink-0 text-amber-400" />
            <span className="text-sm font-medium text-amber-400">Lab targets were unreachable</span>
            <span className="min-w-0 flex-1 text-xs text-muted-foreground">
              This run finished in seconds without attempting any exploitation — {provisionFailed} of {summary?.trials_total ?? displayTrials.length} trial(s)
              failed as INFRASTRUCTURE_ERROR / TARGET_PROVISION_FAILED. That says the lab was down, nothing about
              exploitation ability. Start the lab suite, then run the benchmark again:
              <span className="mt-1 block rounded bg-black/30 p-1.5 font-mono text-[11px] break-all">
                docker compose -f eval_targets/docker-compose.yml up -d
              </span>
              {infraDetail && <span className="mt-1 block font-mono text-[11px] break-all">{infraDetail}</span>}
            </span>
          </CardContent>
        </Card>
      )}

      {/* Sandbox gate: required-but-unavailable also finishes without exploitation */}
      {showSandboxBanner && (
        <Card className="border-amber-500/30 bg-amber-500/5" data-testid="benchmark-sandbox-banner">
          <CardContent className="flex flex-wrap items-center gap-3 py-3">
            <AlertTriangle className="h-4 w-4 shrink-0 text-amber-400" />
            <span className="text-sm font-medium text-amber-400">Sandbox unavailable</span>
            <span className="min-w-0 flex-1 text-xs text-muted-foreground">
              {sandboxFailed} of {summary?.trials_total ?? displayTrials.length} trial(s) failed as INFRASTRUCTURE_ERROR
              / SANDBOX_FAILED — the sandbox was required but unreachable, so no exploitation was attempted (there is
              no host-execution fallback). Check <span className="font-mono">sandbox.enabled</span> and the worker
              image, then run again.
              {infraDetail && <span className="mt-1 block font-mono text-[11px] break-all">{infraDetail}</span>}
            </span>
          </CardContent>
        </Card>
      )}

      <div className="flex min-h-0 flex-1 flex-col gap-2 xl:flex-row xl:overflow-hidden">
        <div className="flex min-w-0 flex-1 flex-col gap-2 xl:min-h-0 xl:overflow-hidden">
          {/* Live strip — same as RunPage's PhaseTracker */}
          {isActiveRun && activeTrial && (
            <div className="flex flex-wrap items-center gap-3 rounded-md border bg-card/40 px-2.5 py-1.5 text-sm">
              <span className="font-mono text-xs font-medium">{activeTrial.scenario_id}</span>
              <span className="text-xs text-muted-foreground">trial {activeTrial.trial_index + 1}</span>
              <div className="flex gap-1.5" aria-label="Phases">
                {phases.map((p) => (
                  <span
                    key={p.label}
                    className={
                      p.state === "done"
                        ? "rounded bg-emerald-500/15 px-1.5 py-0.5 text-xs text-emerald-500"
                        : p.state === "running"
                          ? "rounded bg-yellow-500/15 px-1.5 py-0.5 text-xs text-yellow-300"
                          : "rounded bg-muted px-1.5 py-0.5 text-xs text-muted-foreground"
                    }
                  >
                    {p.label} {p.state === "done" ? "✓" : p.state === "running" ? "●" : "○"}
                  </span>
                ))}
              </div>
              <span className="ml-auto text-xs tabular-nums text-muted-foreground">
                actions: {activeTrial.tool_calls} · {activeTrial.sandbox.enabled ? "sandbox healthy" : "sandbox disabled"}
              </span>
            </div>
          )}

          <Tabs
            value={tab}
            onValueChange={setTab}
            className="flex min-h-[280px] flex-col overflow-hidden rounded-md border bg-card/30 xl:min-h-0 xl:flex-1"
          >
            <div className="shrink-0 border-b bg-muted/30">
              <ScrollArea type="scroll" className="w-full">
                <TabsList className="h-7 bg-transparent p-0.5">
                  <TabsTrigger value="overview" className="h-6 px-2 py-0 text-xs">
                    <BarChart3 className="mr-1 h-3 w-3" /> Overview
                  </TabsTrigger>
                  <TabsTrigger value="trials" className="h-6 px-2 py-0 text-xs">
                    <FlaskConical className="mr-1 h-3 w-3" /> Trials
                  </TabsTrigger>
                  <TabsTrigger value="timeline" className="h-6 px-2 py-0 text-xs">
                    <ScrollText className="mr-1 h-3 w-3" /> Timeline
                  </TabsTrigger>
                  <TabsTrigger value="evidence" className="h-6 px-2 py-0 text-xs">
                    <FileSearch className="mr-1 h-3 w-3" /> Evidence
                  </TabsTrigger>
                  <TabsTrigger value="config" className="h-6 px-2 py-0 text-xs">
                    <Settings2 className="mr-1 h-3 w-3" /> Config
                  </TabsTrigger>
                </TabsList>
              </ScrollArea>
            </div>

            <div className="min-h-0 flex-1 overflow-y-auto overflow-x-hidden p-2 scrollbar-thin">
              <TabsContent value="overview" className="mt-0 space-y-3">
                {summary ? (
                  <>
                    <MetricCards summary={summary} />
                    <Card>
                      <CardHeader className="pb-2">
                        <CardTitle className="text-sm">Failure categories</CardTitle>
                        <CardDescription>Why unverified trials failed — drives what to build next.</CardDescription>
                      </CardHeader>
                      <CardContent>
                        {Object.keys(summary.failure_categories).length === 0 ? (
                          <div className="text-sm text-muted-foreground">No categorized failures.</div>
                        ) : (
                          <div className="flex flex-wrap gap-2">
                            {Object.entries(summary.failure_categories).map(([cat, count]) => (
                              <Badge
                                key={cat}
                                variant={cat === "FALSE_POSITIVE" ? "destructive" : "secondary"}
                                className="font-mono text-[11px]"
                              >
                                {cat}: {count}
                              </Badge>
                            ))}
                          </div>
                        )}
                      </CardContent>
                    </Card>
                    <Card>
                      <CardHeader className="pb-2">
                        <CardTitle className="text-sm">Summary</CardTitle>
                        <CardDescription>
                          {summary.solved}/{summary.trials_total} verified · {formatPct(summary.verified_success_rate)} success ·{" "}
                          {formatPct(summary.false_positive_rate)} false positives
                        </CardDescription>
                      </CardHeader>
                      <CardContent className="grid grid-cols-2 gap-3 text-sm md:grid-cols-4">
                        <div>
                          <div className="text-xs text-muted-foreground">Median solve</div>
                          <div className="font-medium tabular-nums">{formatDuration(summary.median_solve_time)}</div>
                        </div>
                        <div>
                          <div className="text-xs text-muted-foreground">Mean solve</div>
                          <div className="font-medium tabular-nums">{formatDuration(summary.mean_solve_time)}</div>
                        </div>
                        <div>
                          <div className="text-xs text-muted-foreground">Tokens</div>
                          <div className="font-medium tabular-nums">{summary.total_tokens.toLocaleString()}</div>
                        </div>
                        <div>
                          <div className="text-xs text-muted-foreground">Cost</div>
                          <div className="font-medium tabular-nums">{formatCost(summary.estimated_cost)}</div>
                        </div>
                      </CardContent>
                    </Card>
                  </>
                ) : isActiveRun ? (
                  <Card>
                    <CardHeader className="pb-2">
                      <CardTitle className="text-sm">Run summary</CardTitle>
                      <CardDescription>
                        Summary computed after trials complete · {completedTrials}/{totalTrials} done
                      </CardDescription>
                    </CardHeader>
                    <CardContent className="space-y-3">
                      <div className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6">
                        <Skeleton className="h-20 w-full" />
                        <Skeleton className="h-20 w-full" />
                        <Skeleton className="h-20 w-full" />
                        <Skeleton className="h-20 w-full" />
                        <Skeleton className="h-20 w-full" />
                        <Skeleton className="h-20 w-full" />
                      </div>
                      <div className="flex items-center gap-2 text-xs text-muted-foreground">
                        <Loader2 className="h-3 w-3 animate-spin" /> waiting for trials to finish…
                      </div>
                    </CardContent>
                  </Card>
                ) : (
                  <Card>
                    <CardContent className="py-8 text-center text-sm text-muted-foreground">
                      No summary yet — run hasn't completed.
                    </CardContent>
                  </Card>
                )}
              </TabsContent>

              <TabsContent value="trials" className="mt-0">
                <Card>
                  <CardHeader className="pb-2">
                    <CardTitle className="text-sm">Scenario results</CardTitle>
                    <CardDescription>
                      Verified outcomes from the independent oracle. “Agent claimed” is recorded separately for false-positive detection.
                      {trialsAreLive ? " Showing live results — the final trial list is written when the run completes." : ""}
                    </CardDescription>
                  </CardHeader>
                  <CardContent>
                    <ScenarioResultsTable trials={displayTrials} />
                  </CardContent>
                </Card>
              </TabsContent>

              <TabsContent value="timeline" className="mt-0 space-y-2">
                <Card>
                  <CardHeader className="pb-2">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <CardTitle className="text-sm">Mission timeline</CardTitle>
                      <div className="flex items-center gap-2">
                        <select
                          value={timelineTrial}
                          onChange={(e) => setTimelineTrial(e.target.value)}
                          className="h-7 rounded-md border bg-background px-2 text-xs"
                          aria-label="Filter by trial"
                        >
                          <option value="">All trials</option>
                          {trialIds.map((tid) => (
                            <option key={tid} value={tid}>
                              {tid}
                            </option>
                          ))}
                        </select>
                        <span className="text-xs tabular-nums text-muted-foreground">
                          {eventCount} events {events.isFetching ? "· updating…" : ""}
                        </span>
                      </div>
                    </div>
                    <CardDescription>Structured events — increments live while the run is active.</CardDescription>
                  </CardHeader>
                  <CardContent className="space-y-2">
                    <BenchmarkTimeline
                      events={eventList}
                      trialId={timelineTrial || undefined}
                      isLoading={events.isLoading && eventList.length === 0}
                      maxEvents={400}
                    />
                    {events.isFetching && eventList.length > 0 ? (
                      <div className="flex items-center gap-1 text-[11px] text-muted-foreground">
                        <Loader2 className="h-3 w-3 animate-spin" /> polling for new events…
                      </div>
                    ) : null}
                  </CardContent>
                </Card>
              </TabsContent>

              <TabsContent value="evidence" className="mt-0 space-y-3">
                <Card>
                  <CardHeader className="pb-2">
                    <CardTitle className="text-sm">Evidence & flags</CardTitle>
                    <CardDescription>Per-trial oracle flags, captured evidence, audit trails and workspaces.</CardDescription>
                  </CardHeader>
                  <CardContent className="space-y-3">
                    {displayTrials.length === 0 ? (
                      <div className="py-6 text-center text-sm text-muted-foreground">
                        {isActiveRun ? "No trial has finished yet — results appear here as each trial completes." : "No trials recorded."}
                      </div>
                    ) : (
                      displayTrials.map((t) => (
                        <div key={t.trial_id} className="rounded-md border p-3">
                          <div className="flex flex-wrap items-center gap-2">
                            <span className="font-mono text-xs font-medium">{t.scenario_id}</span>
                            <StatusBadge status={t.status} />
                            <span className="text-xs text-muted-foreground">
                              {t.flags_captured}/{t.flags_total} flags · {formatDuration(t.duration_seconds)} · {t.tool_calls} actions
                            </span>
                            <span className="ml-auto text-[11px] text-muted-foreground">{t.trial_id}</span>
                          </div>
                          {t.flags.length > 0 && (
                            <div className="mt-2 flex flex-wrap gap-1.5">
                              {t.flags.map((f, fi) => (
                                <Badge
                                  key={`${t.trial_id}:${fi}:${String(f.flag_id)}`}
                                  variant={f.passed ? "secondary" : "destructive"}
                                  className="font-mono text-[10px]"
                                >
                                  {String(f.flag_id ?? "flag")}: {f.passed ? "passed" : "failed"}
                                </Badge>
                              ))}
                            </div>
                          )}
                          <div className="mt-2 grid gap-1 text-xs">
                            {t.claimed_summary && (
                              <div className="text-muted-foreground">
                                <span className="font-medium text-foreground">Claimed:</span> {t.claimed_summary.slice(0, 240)}
                              </div>
                            )}
                            {t.failure_detail && (
                              <div className="text-muted-foreground">
                                <span className="font-medium text-foreground">Detail:</span> {t.failure_detail.slice(0, 300)}
                              </div>
                            )}
                            <div className="flex flex-wrap gap-3 font-mono text-[11px] text-muted-foreground">
                              {t.audit_path && <span>audit: {t.audit_path}</span>}
                              {t.workspace && <span>workspace: {t.workspace}</span>}
                              {t.evidence_refs.length > 0 && <span>evidence: {t.evidence_refs.join(", ")}</span>}
                            </div>
                          </div>
                        </div>
                      ))
                    )}
                  </CardContent>
                </Card>
              </TabsContent>

              <TabsContent value="config" className="mt-0">
                <div className="grid gap-3 lg:grid-cols-2">
                  <Card>
                    <CardHeader className="pb-2">
                      <CardTitle className="text-sm">Configuration</CardTitle>
                    </CardHeader>
                    <CardContent>
                      <dl className="grid grid-cols-2 gap-y-1.5 text-sm">
                        <dt className="text-muted-foreground">Suite</dt>
                        <dd className="font-mono text-xs">{data.config.suite}</dd>
                        <dt className="text-muted-foreground">Trials</dt>
                        <dd className="tabular-nums">{data.config.trials}</dd>
                        <dt className="text-muted-foreground">Timeout</dt>
                        <dd className="tabular-nums">{formatDuration(data.config.timeout_seconds)}</dd>
                        <dt className="text-muted-foreground">Scenarios</dt>
                        <dd className="font-mono text-xs">{data.config.scenario_ids.join(", ") || "all"}</dd>
                        {data.config.tags.length > 0 && (
                          <>
                            <dt className="text-muted-foreground">Tags</dt>
                            <dd className="font-mono text-xs">{data.config.tags.join(", ")}</dd>
                          </>
                        )}
                        <dt className="text-muted-foreground">Sandbox required</dt>
                        <dd>{data.config.sandbox_required ? "yes" : "no"}</dd>
                        <dt className="text-muted-foreground">Replay command</dt>
                        <dd className="col-span-2 font-mono text-xs text-muted-foreground break-all">
                          {manifest?.replay_command ?? "n/a"}
                        </dd>
                      </dl>
                    </CardContent>
                  </Card>
                  <Card>
                    <CardHeader className="pb-2">
                      <CardTitle className="flex items-center gap-2 text-sm">
                        <GitCommitHorizontal className="h-4 w-4" />
                        Environment (reproducibility pins)
                      </CardTitle>
                    </CardHeader>
                    <CardContent>
                      <dl className="grid grid-cols-2 gap-y-1.5 text-sm">
                        <dt className="text-muted-foreground">Git SHA</dt>
                        <dd className="font-mono text-xs">
                          {env.git_sha}
                          {env.git_dirty ? " (dirty)" : ""}
                        </dd>
                        <dt className="text-muted-foreground">Model</dt>
                        <dd className="font-mono text-xs">
                          {env.model_provider} / {env.model_id} ({env.model_alias})
                        </dd>
                        <dt className="text-muted-foreground">Model version</dt>
                        <dd className="font-mono text-xs">{env.model_version}</dd>
                        <dt className="text-muted-foreground">Config hash</dt>
                        <dd className="font-mono text-xs">{env.config_hash}</dd>
                        <dt className="text-muted-foreground">Sandbox image</dt>
                        <dd className="font-mono text-xs break-all">
                          {env.sandbox_image} @ {env.sandbox_image_digest}
                        </dd>
                        <dt className="text-muted-foreground">Sandbox</dt>
                        <dd>
                          {env.sandbox_enabled ? "enabled" : "disabled"}
                          {env.sandbox_required ? " (required)" : ""}
                        </dd>
                        <dt className="text-muted-foreground">Platform</dt>
                        <dd className="text-xs">
                          {env.platform} · Python {env.python_version}
                        </dd>
                      </dl>
                    </CardContent>
                  </Card>
                </div>
              </TabsContent>
            </div>
          </Tabs>
        </div>

        {/* Aside — like RunPage's telemetry + live summary */}
        <aside className="flex min-w-0 shrink-0 flex-col gap-2 xl:w-[320px] xl:min-h-0 xl:overflow-y-auto xl:overflow-x-hidden scrollbar-thin">
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm">Run telemetry</CardTitle>
              <CardDescription>
                {orphaned ? "Frozen (run interrupted)" : isActiveRun ? "Live until terminal" : "Frozen at completion"}
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-2 text-sm">
              <div className="grid grid-cols-2 gap-2">
                <div className="rounded-md bg-muted/40 p-2">
                  <div className="text-[11px] uppercase tracking-wide text-muted-foreground">Trials</div>
                  <div className="font-medium tabular-nums">
                    {completedTrials}/{totalTrials}
                  </div>
                  <div className="text-[11px] text-muted-foreground">{progressPct}%</div>
                </div>
                <div className="rounded-md bg-muted/40 p-2">
                  <div className="text-[11px] uppercase tracking-wide text-muted-foreground">Events</div>
                  <div className="font-medium tabular-nums">{eventCount}</div>
                  <div className="text-[11px] text-muted-foreground">{formatDuration(elapsedSec)}</div>
                </div>
                <div className="rounded-md bg-muted/40 p-2">
                  <div className="text-[11px] uppercase tracking-wide text-muted-foreground">Tokens</div>
                  <div className="font-medium tabular-nums">{summary ? summary.total_tokens.toLocaleString() : displayTrials.reduce((a, t) => a + (t.total_tokens ?? 0), 0).toLocaleString()}</div>
                  <div className="text-[11px] text-muted-foreground">{summary ? formatCost(summary.estimated_cost) : "—"}</div>
                </div>
                <div className="rounded-md bg-muted/40 p-2">
                  <div className="text-[11px] uppercase tracking-wide text-muted-foreground">Verified</div>
                  <div className="font-medium tabular-nums">{summary ? `${summary.solved}/${summary.trials_total}` : `${displayTrials.filter((t) => t.oracle_verified_success).length}/${displayTrials.length}`}</div>
                  <div className="text-[11px] text-muted-foreground">{summary ? formatPct(summary.verified_success_rate) : "—"}</div>
                </div>
              </div>
              {summary && (
                <div className="space-y-1">
                  <div className="flex justify-between text-xs"><span className="text-muted-foreground">False positives</span><span className="tabular-nums">{formatPct(summary.false_positive_rate)}</span></div>
                  <div className="flex justify-between text-xs"><span className="text-muted-foreground">Infra errors</span><span className="tabular-nums">{summary.infra_error_count}</span></div>
                  <div className="flex justify-between text-xs"><span className="text-muted-foreground">Sandbox blocks</span><span className="tabular-nums">{summary.sandbox_blocked_actions}</span></div>
                </div>
              )}
              {!summary && displayTrials.length > 0 && (
                <div className="space-y-1">
                  <div className="text-xs text-muted-foreground">Current trials</div>
                  {displayTrials.slice(0, 4).map((t) => (
                    <div key={t.trial_id} className="flex items-center justify-between rounded bg-muted/30 px-2 py-1">
                      <span className="font-mono text-[11px]">{t.scenario_id}</span>
                      <StatusBadge status={t.status} />
                    </div>
                  ))}
                  {displayTrials.length > 4 && <div className="text-center text-[11px] text-muted-foreground">+{displayTrials.length - 4} more</div>}
                </div>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm">Replay</CardTitle>
            </CardHeader>
            <CardContent className="space-y-2">
              <div className="rounded bg-muted p-2 font-mono text-xs break-all">{manifest?.replay_command ?? "n/a"}</div>
              <Button variant="outline" size="sm" className="w-full" asChild>
                <Link to="/benchmarks">Back to benchmarks</Link>
              </Button>
              {isActiveRun && <div className="flex items-center gap-1 text-xs text-muted-foreground"><Loader2 className="h-3 w-3 animate-spin" /> live updates every 2 s</div>}
              {events.isFetching && <div className="text-xs text-muted-foreground">{eventCount} events · polling…</div>}
            </CardContent>
          </Card>
        </aside>
      </div>
    </div>
  );
}
