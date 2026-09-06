// BreachPilot by @braydos-h — https://github.com/braydos-h/BreachPilot
// Benchmarks "New run" sub-page: the run-benchmark panel plus context about
// what a run does and what the regression baseline will be compared against.
import { Link } from "react-router-dom";
import { Bookmark, FlaskConical, ShieldCheck, Target } from "lucide-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { ErrorState } from "@/components/Loading";
import { RunBenchmarkPanel } from "@/features/benchmarks/RunBenchmarkPanel";
import { BenchmarksShell } from "@/features/benchmarks/BenchmarksShell";
import { useBenchmarksOverview } from "@/features/benchmarks/useBenchmarksOverview";
import { useDefaultModel } from "@/components/ProviderSetup";
import { formatCost, formatDuration, formatPct } from "@/features/benchmarks/format";

export function BenchmarksStartPage() {
  const { overview, active } = useBenchmarksOverview();
  const defaultModel = useDefaultModel();
  const baseline = overview.data?.baseline;

  return (
    <BenchmarksShell>
      {overview.isError && (
        <ErrorState
          message={overview.error instanceof Error ? overview.error.message : "Failed to load benchmark suites"}
          onRetry={() => void overview.refetch()}
        />
      )}

      <RunBenchmarkPanel suites={overview.data?.suites ?? []} active={active} defaultModel={defaultModel} />

      <div className="grid gap-3 lg:grid-cols-2">
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="flex items-center gap-2 text-sm">
              <FlaskConical className="h-3.5 w-3.5 text-primary" /> What a run does
            </CardTitle>
          </CardHeader>
          <CardContent className="grid gap-2 text-sm text-muted-foreground">
            <div className="flex items-start gap-2">
              <Target className="mt-0.5 h-3.5 w-3.5 shrink-0 text-muted-foreground" aria-hidden />
              <span>
                Provisions the suite's lab targets and runs sandboxed exploitation missions — one trial per scenario
                (repeat trials add confidence intervals).
              </span>
            </div>
            <div className="flex items-start gap-2">
              <ShieldCheck className="mt-0.5 h-3.5 w-3.5 shrink-0 text-muted-foreground" aria-hidden />
              <span>
                An independent oracle verifies captured flags afterwards; claimed-but-unverified outcomes are recorded
                as false positives, never counted as success.
              </span>
            </div>
            <div className="flex items-start gap-2">
              <FlaskConical className="mt-0.5 h-3.5 w-3.5 shrink-0 text-muted-foreground" aria-hidden />
              <span>
                Results persist under the benchmark report directory and appear in{" "}
                <Link to="/benchmarks/history" className="text-primary underline-offset-4 hover:underline">
                  Past benchmarks
                </Link>{" "}
                once the run completes.
              </span>
            </div>
          </CardContent>
        </Card>

        <Card data-testid="start-baseline-card">
          <CardHeader className="pb-2">
            <CardTitle className="flex items-center gap-2 text-sm">
              <Bookmark className="h-3.5 w-3.5 text-primary" /> Regression baseline
            </CardTitle>
            <CardDescription>What "Check regression vs baseline" compares against.</CardDescription>
          </CardHeader>
          <CardContent>
            {baseline?.exists ? (
              <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-sm">
                {baseline.run_id ? (
                  <Link to={`/benchmarks/${baseline.run_id}`} className="font-mono text-xs underline-offset-4 hover:underline">
                    {baseline.run_id}
                  </Link>
                ) : (
                  <span className="font-mono text-xs">{baseline.path}</span>
                )}
                <span className="text-muted-foreground">
                  success <span className="font-medium tabular-nums text-foreground">{formatPct(baseline.verified_success_rate)}</span>
                </span>
                <span className="text-muted-foreground">
                  FP <span className="font-medium tabular-nums text-foreground">{formatPct(baseline.false_positive_rate)}</span>
                </span>
                {typeof baseline.median_solve_time === "number" && (
                  <span className="text-muted-foreground">
                    median <span className="font-medium tabular-nums text-foreground">{formatDuration(baseline.median_solve_time)}</span>
                  </span>
                )}
                {typeof baseline.estimated_cost === "number" && (
                  <span className="text-muted-foreground">
                    cost <span className="font-medium tabular-nums text-foreground">{formatCost(baseline.estimated_cost)}</span>
                  </span>
                )}
                <span className="text-xs text-muted-foreground">
                  Tick "Save as baseline" on a completed run (its detail page) to replace this.
                </span>
              </div>
            ) : (
              <div className="text-sm text-muted-foreground">
                No baseline saved yet. Complete a run, open it, and press "Save baseline" — later runs can then be
                checked against it for regressions.
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </BenchmarksShell>
  );
}
