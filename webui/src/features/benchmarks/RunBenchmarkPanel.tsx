// BreachPilot by @braydos-h — https://github.com/braydos-h/BreachPilot
// Run-benchmark panel: suite/scenario selection, trials, model, sandbox, baseline options.
//
// Selection semantics mirror the backend runner exactly: the request carries
// explicitly-checked scenario ids; an empty selection runs the whole suite.
// Tag chips are view filters for the checklist only — they are never sent to
// the API, so what the user sees checked is exactly what will run.
import { useEffect, useMemo, useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import { FlaskConical, Loader2, Play, RotateCcw } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { fetchSuiteReadiness, fetchSuiteScenarios, startBenchmarkRun } from "@/features/benchmarks/api";
import { isActiveState } from "@/features/benchmarks/format";
import type { ScenarioInfo, SuiteInfo, SuiteReadiness } from "@/features/benchmarks/types";
import { useDefaultModel, useModelOptions } from "@/components/ProviderSetup";
import { cn } from "@/lib/utils";

export interface RunBenchmarkPanelProps {
  suites: SuiteInfo[];
  active: { run_id: string | null; state: string; error: string };
  defaultModel?: string;
}

export function RunBenchmarkPanel({ suites, active, defaultModel: defaultModelProp }: RunBenchmarkPanelProps) {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  // Provider-aware picker: live + configured + default models for the active
  // provider only (single source of truth — same hooks the wizard uses).
  const modelOptions = useModelOptions();
  const hookDefault = useDefaultModel();
  const defaultModel = defaultModelProp || hookDefault;
  const [suite, setSuite] = useState(suites[0]?.suite_id ?? "");
  const [scenarios, setScenarios] = useState<ScenarioInfo[]>([]);
  const [scenariosError, setScenariosError] = useState("");
  const [scenariosReloading, setScenariosReloading] = useState(false);
  const [scenariosRetryTick, setScenariosRetryTick] = useState(0);
  const [readiness, setReadiness] = useState<SuiteReadiness | null>(null);
  const [readinessChecking, setReadinessChecking] = useState(false);
  const [selectedScenarios, setSelectedScenarios] = useState<Set<string>>(new Set());
  const [selectedTags, setSelectedTags] = useState<Set<string>>(new Set());
  const [trials, setTrials] = useState(1);
  const [model, setModel] = useState("");
  const [sandboxRequired, setSandboxRequired] = useState(true);
  const [checkRegression, setCheckRegression] = useState(false);
  const [saveBaseline, setSaveBaseline] = useState(false);

  const busy = isActiveState(active.state);

  // The panel can mount before the overview query delivers the suite list
  // (e.g. rendered directly on the "New run" sub-page) — pick the first suite
  // once suites arrive so the user never sees a stuck "Select suite…" default.
  useEffect(() => {
    const first = suites[0];
    if (!suite && first) {
      setSuite(first.suite_id);
    }
  }, [suite, suites]);

  // Load the suite's scenario checklist. Re-runs when the suite changes and
  // on retry; failures are surfaced (never silently swallowed).
  useEffect(() => {
    if (!suite) {
      setScenarios([]);
      setScenariosError("");
      return;
    }
    let cancelled = false;
    setScenariosError("");
    setScenariosReloading(true);
    fetchSuiteScenarios(suite)
      .then((data) => {
        if (cancelled) return;
        setScenarios(data.scenarios);
      })
      .catch((err: unknown) => {
        if (cancelled) return;
        setScenarios([]);
        setScenariosError(err instanceof Error ? err.message : String(err));
      })
      .finally(() => {
        if (!cancelled) setScenariosReloading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [suite, scenariosRetryTick]);

  // Lab-target readiness: host-type scenarios need the loopback lab suite up
  // or the run finishes instantly with TARGET_PROVISION_FAILED (which reads
  // as "skipped to the finished page"). Best-effort — a probe failure never
  // blocks starting a run (docker scenarios self-provision anyway).
  useEffect(() => {
    if (!suite) {
      setReadiness(null);
      return;
    }
    let cancelled = false;
    setReadinessChecking(true);
    fetchSuiteReadiness(suite)
      .then((data) => {
        if (!cancelled) setReadiness(data);
      })
      .catch(() => {
        if (!cancelled) setReadiness(null);
      })
      .finally(() => {
        if (!cancelled) setReadinessChecking(false);
      });
    return () => {
      cancelled = true;
    };
  }, [suite]);

  const onSuiteChange = (suiteId: string) => {
    setSuite(suiteId);
    setSelectedScenarios(new Set());
    setSelectedTags(new Set());
    setScenarios([]);
    setReadiness(null);
  };

  const allTags = useMemo(() => {
    const tags = new Set<string>();
    for (const s of scenarios) for (const t of s.tags) tags.add(t);
    return [...tags].sort();
  }, [scenarios]);

  const visibleScenarios = useMemo(() => {
    if (selectedTags.size === 0) return scenarios;
    return scenarios.filter((s) => s.tags.some((t) => selectedTags.has(t)));
  }, [scenarios, selectedTags]);

  const startRun = useMutation({
    mutationFn: () =>
      startBenchmarkRun({
        suite,
        scenarios: [...selectedScenarios],
        trials,
        model: model || undefined,
        sandbox_required: sandboxRequired,
        save_baseline: saveBaseline,
        check_regression: checkRegression,
      }),
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ["benchmarks"] });
      if (data.run_id) navigate(`/benchmarks/${data.run_id}`);
    },
  });

  const suiteInfo = suites.find((s) => s.suite_id === suite);
  const willRunCount = selectedScenarios.size > 0 ? selectedScenarios.size : (suiteInfo?.scenarios ?? 0);
  const unreachable = (readiness?.targets ?? []).filter((t) => !t.reachable && !t.self_provisioned);

  return (
    <Card data-testid="run-benchmark-panel">
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base">
          <FlaskConical className="h-4 w-4 text-primary" />
          Run benchmark
        </CardTitle>
        <CardDescription>
          Runs verified, sandboxed missions against lab targets and records reproducible metrics. Authorized lab
          environments only.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="grid gap-4 md:grid-cols-2">
          <div className="space-y-1.5">
            <Label htmlFor="bench-suite">Benchmark suite</Label>
            <select
              id="bench-suite"
              value={suite}
              disabled={busy}
              onChange={(e) => onSuiteChange(e.target.value)}
              className="h-9 w-full rounded-md border bg-background px-2 text-sm focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
            >
              <option value="">Select suite…</option>
              {suites.map((s) => (
                <option key={s.suite_id} value={s.suite_id}>
                  {s.suite_id} ({s.scenarios} scenarios)
                </option>
              ))}
            </select>
            {suiteInfo?.invalid_manifests ? (
              <p className="text-[11px] text-amber-500">{suiteInfo.invalid_manifests} invalid manifest(s) ignored.</p>
            ) : null}
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="bench-model">Model alias</Label>
            <select
              id="bench-model"
              value={model}
              disabled={busy}
              onChange={(e) => setModel(e.target.value)}
              className="h-9 w-full rounded-md border bg-background px-2 text-sm focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
            >
              <option value="">Server default{defaultModel ? ` (${defaultModel})` : ""}</option>
              {(model && !modelOptions.includes(model) ? [model, ...modelOptions] : modelOptions).map((m) => (
                <option key={m} value={m}>
                  {m}
                </option>
              ))}
            </select>
            <p className="text-[11px] text-muted-foreground">Server default uses the active provider's default model.</p>
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="bench-trials">Trials per scenario</Label>
            <Input
              id="bench-trials"
              type="number"
              min={1}
              max={20}
              value={trials}
              disabled={busy}
              onChange={(e) => setTrials(Math.max(1, Math.min(20, Number(e.target.value) || 1)))}
            />
            <p className="text-[11px] text-muted-foreground">Repeated trials give per-scenario confidence intervals.</p>
          </div>
          <div className="space-y-2 pt-1">
            <label className="flex items-center gap-2 text-sm">
              <Checkbox
                aria-label="Sandbox required"
                checked={sandboxRequired}
                disabled={busy}
                onCheckedChange={(v) => setSandboxRequired(v === true)}
              />
              Sandbox required
              <span className="text-[11px] text-muted-foreground">(no host-execution fallback)</span>
            </label>
            <label className="flex items-center gap-2 text-sm">
              <Checkbox
                aria-label="Save as baseline"
                checked={saveBaseline}
                disabled={busy}
                onCheckedChange={(v) => setSaveBaseline(v === true)}
              />
              Save as baseline
            </label>
            <label className="flex items-center gap-2 text-sm">
              <Checkbox
                aria-label="Check regression vs baseline"
                checked={checkRegression}
                disabled={busy}
                onCheckedChange={(v) => setCheckRegression(v === true)}
              />
              Check regression vs baseline
            </label>
          </div>
        </div>

        {scenariosReloading && <div className="text-sm text-muted-foreground">Loading scenarios…</div>}
        {readinessChecking && !readiness && <div className="text-sm text-muted-foreground">Checking lab targets…</div>}
        {readiness && !readiness.ready && unreachable.length > 0 && (
          <div
            data-testid="benchmark-lab-warning"
            className="space-y-1 rounded-md border border-amber-500/30 bg-amber-500/10 px-3 py-2 text-sm text-amber-300"
          >
            <div className="font-medium">Lab targets unreachable — a run now would finish instantly with no results.</div>
            <div className="text-xs text-amber-200/80">
              {unreachable.length} scenario target{unreachable.length === 1 ? "" : "s"} refusing connections
              {unreachable.length <= 4 ? `: ${unreachable.map((t) => t.scenario_id).join(", ")}` : ""}. Start the lab
              suite, then run again:
            </div>
            <div className="rounded bg-black/30 p-1.5 font-mono text-xs break-all">{readiness.lab_command}</div>
          </div>
        )}
        {scenariosError && (
          <div className="flex flex-wrap items-center gap-2 rounded-md border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-400">
            <span>Failed to load scenarios: {scenariosError}</span>
            <Button
              size="sm"
              variant="outline"
              className="ml-auto h-7"
              onClick={() => setScenariosRetryTick((t) => t + 1)}
            >
              <RotateCcw className="h-3 w-3" /> Retry
            </Button>
          </div>
        )}
        {visibleScenarios.length > 0 && (
          <div className="space-y-2">
            <div className="flex flex-wrap items-center gap-1.5" role="group" aria-label="Tag filters (list only)">
              {allTags.map((tag) => (
                <button
                  key={tag}
                  type="button"
                  aria-pressed={selectedTags.has(tag)}
                  disabled={busy}
                  onClick={() => {
                    setSelectedTags((prev) => {
                      const next = new Set(prev);
                      if (next.has(tag)) next.delete(tag);
                      else next.add(tag);
                      return next;
                    });
                  }}
                  className={cn(
                    "rounded-full px-2 py-0.5 text-[11px] transition-colors",
                    selectedTags.has(tag)
                      ? "bg-primary/15 text-primary"
                      : "bg-muted/60 text-muted-foreground hover:text-foreground",
                  )}
                >
                  {tag}
                </button>
              ))}
            </div>
            <div className="max-h-40 space-y-1 overflow-y-auto rounded-lg border p-2">
              {visibleScenarios.map((s) => (
                <div key={s.scenario_id} className="flex items-center gap-2 rounded px-1 py-0.5 text-sm hover:bg-muted/40">
                  <Checkbox
                    id={`bench-scenario-${s.scenario_id}`}
                    checked={selectedScenarios.has(s.scenario_id)}
                    disabled={busy}
                    onCheckedChange={(v) => {
                      setSelectedScenarios((prev) => {
                        const next = new Set(prev);
                        if (v === true) next.add(s.scenario_id);
                        else next.delete(s.scenario_id);
                        return next;
                      });
                    }}
                  />
                  <label htmlFor={`bench-scenario-${s.scenario_id}`} className="flex min-w-0 flex-1 cursor-pointer items-center gap-2">
                    <span className="font-mono text-xs">{s.scenario_id}</span>
                    <span className="truncate text-muted-foreground">{s.name}</span>
                  </label>
                  <span className="ml-auto text-[10px] uppercase tracking-wide text-muted-foreground">{s.difficulty}</span>
                </div>
              ))}
            </div>
            <p className="text-[11px] text-muted-foreground">
              Leave every scenario unchecked to run the whole suite. Tags only filter this list.
            </p>
          </div>
        )}

        {active.error && (busy || active.state === "error") && (
          <div className="rounded-md border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-400">{active.error}</div>
        )}

        <div className="flex flex-wrap items-center gap-3">
          <Button disabled={busy || !suite || startRun.isPending} onClick={() => startRun.mutate()} data-testid="run-benchmark-button">
            {startRun.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Play className="h-4 w-4" />}
            Run Benchmark
          </Button>
          {busy && <span className="text-sm text-amber-500">A benchmark run is active — watch progress on its page.</span>}
          <span className="ml-auto text-xs text-muted-foreground">
            {willRunCount > 0
              ? `${willRunCount === (suiteInfo?.scenarios ?? 0) && selectedScenarios.size === 0 ? "all " : ""}${willRunCount} scenario(s) × ${trials} trial(s)`
              : `${trials} trial(s)`}
          </span>
        </div>
        {startRun.isError && (
          <div className="rounded-md border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-400">
            {startRun.error instanceof Error ? startRun.error.message : "Failed to start benchmark run."}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
