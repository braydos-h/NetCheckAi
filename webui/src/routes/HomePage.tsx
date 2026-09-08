import { useEffect, useState, type ReactNode } from "react";
import { Link } from "react-router-dom";
import {
  Activity,
  ArrowRight,
  CheckCircle2,
  Circle,
  Compass,
  History,
  Info,
  ListFilter,
  Loader2,
  ScanSearch,
  ShieldAlert,
  ShieldCheck,
  ShieldX,
  Target,
  Wrench,
  XCircle,
  AlertTriangle,
} from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { StatusBadge } from "@/components/StatusBadge";
import { SkeletonRows } from "@/components/Loading";
import { useRuns, useSandboxStatus, useSandboxFixPlan, useSandboxFix, useSandboxFixStatus } from "@/api/hooks";
import { useQueryClient } from "@tanstack/react-query";
import {
  isActiveState,
  isTerminalState,
  type RunListRow,
} from "@/api/types";
import { formatRelative, truncateId } from "@/lib/utils";

export const NOTICE_KEY = "breachpilot.fullNotice.shown.v1";
export const NOTICE_DISMISSED_KEY = "breachpilot.fullNotice.dismissed.v1";

function FullAccessNotice() {
  const [open, setOpen] = useState(false);

  useEffect(() => {
    try {
      if (localStorage.getItem(NOTICE_DISMISSED_KEY) === "1") return;
      if (sessionStorage.getItem(NOTICE_KEY) === "1") return;
      sessionStorage.setItem(NOTICE_KEY, "1");
      setOpen(true);
    } catch {
      // ignore
    }
  }, []);

  const handleGotIt = () => {
    setOpen(false);
  };

  const handleDontShowAgain = () => {
    try {
      localStorage.setItem(NOTICE_DISMISSED_KEY, "1");
    } catch {
      // ignore
    }
    setOpen(false);
  };

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogContent className="max-w-lg">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2 text-lg">
            <ShieldAlert className="h-5 w-5 text-red-400" />
            Read-only by default
          </DialogTitle>
          <DialogDescription className="text-sm">
            The console defaults to <span className="text-yellow-300 font-medium">Read-only</span>. Every operator decision waits for you to answer it. Use the sidebar toggle to switch to Approve (auto-answers non-destructive decisions only).
          </DialogDescription>
        </DialogHeader>
        <div className="flex items-center justify-end gap-2 pt-1">
          <Button type="button" variant="ghost" size="sm" onClick={handleDontShowAgain}>
            Don&apos;t show again
          </Button>
          <Button type="button" size="sm" onClick={handleGotIt}>
            Got it
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  );
}

const FALLBACK_HINT = "Start Docker and build the sandbox image (docker build -t breachpilot-sandbox:latest docker/sandbox) to contain execution — until then commands run directly on this machine.";

function SandboxFixDialog({
  open,
  onOpenChange,
  sandboxReason,
}: {
  open: boolean;
  onOpenChange: (o: boolean) => void;
  sandboxReason: string;
}) {
  const qc = useQueryClient();
  const planQuery = useSandboxFixPlan(open);
  const fixMutation = useSandboxFix();
  const [jobId, setJobId] = useState<string | null>(null);
  const statusQuery = useSandboxFixStatus(jobId);
  const job = statusQuery.data;
  const plan = planQuery.data;

  // Reset job when dialog closes
  useEffect(() => {
    if (!open) {
      setJobId(null);
      fixMutation.reset();
      // Don't reset statusQuery directly; jobId null handles it
    }
  }, [open]);

  // After job succeeds, refetch sandbox status but DO NOT fake contained
  useEffect(() => {
    if (job?.status === "succeeded") {
      void qc.invalidateQueries({ queryKey: ["system", "sandbox"] });
    }
    if (job?.status === "succeeded" || job?.status === "failed") {
      // Keep polls stopped already via hook's refetchInterval; also ensure sandbox status stays accurate
    }
  }, [job?.status, qc]);

  const isFixing = job ? job.status === "pending" || job.status === "running" : fixMutation.isPending;
  const isSuccess = job?.status === "succeeded";
  const isFailed = job?.status === "failed";

  const handleStartFix = async () => {
    try {
      const result = await fixMutation.mutateAsync();
      setJobId(result.job_id);
    } catch {
      // error handled via fixMutation.error
    }
  };

  const handleRetry = async () => {
    fixMutation.reset();
    setJobId(null);
    try {
      const result = await fixMutation.mutateAsync();
      setJobId(result.job_id);
    } catch {
      // handled
    }
  };

  const handleClose = () => {
    onOpenChange(false);
  };

  // Determine which steps to show: during fixing use job.steps, otherwise plan steps
  const displaySteps = job?.steps ?? plan?.steps ?? [];
  const failedStep = job?.steps?.find((s) => s.status === "failed");

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-2xl max-h-[90vh] overflow-hidden flex flex-col">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2 text-lg">
            <Wrench className="h-5 w-5" />
            Fix Docker sandbox
          </DialogTitle>
          <DialogDescription className="text-sm text-left">
            BreachPilot is currently executing commands directly on this machine because the Docker sandbox could not start.
          </DialogDescription>
        </DialogHeader>

        <div className="flex-1 overflow-y-auto space-y-4 pr-1">
          {/* Reason */}
          {sandboxReason && (
            <div className="rounded-md border border-amber-500/20 bg-amber-500/5 px-3 py-2 text-sm">
              <span className="font-medium">Reason: </span>
              <span className="text-muted-foreground">{sandboxReason}</span>
            </div>
          )}

          {/* Loading plan */}
          {planQuery.isLoading && !isFixing && !isSuccess && !isFailed && (
            <div className="space-y-2">
              <SkeletonRows count={3} />
              <p className="text-xs text-muted-foreground">Loading remediation plan…</p>
            </div>
          )}

          {planQuery.error && !isFixing && !isSuccess && !isFailed && (
            <div className="rounded-md border border-destructive/40 bg-destructive/10 px-3 py-2 text-xs text-destructive">
              Failed to load plan: {(planQuery.error as Error).message}
            </div>
          )}

          {/* Pre-fix: plan preview */}
          {!isFixing && !isSuccess && !isFailed && plan && (
            <>
              <div className="space-y-2">
                <h3 className="text-sm font-semibold">What BreachPilot will do</h3>
                {plan.steps.length === 0 ? (
                  <p className="text-xs text-muted-foreground">No remediation steps are required. Docker and the sandbox image appear ready.</p>
                ) : (
                  <ol className="space-y-2">
                    {plan.steps.map((step, idx) => (
                      <li key={step.id} className="flex gap-2 text-sm">
                        <span className="font-mono text-xs text-muted-foreground mt-0.5">{idx + 1}.</span>
                        <div className="flex-1">
                          <div className="font-medium text-sm">{step.title}</div>
                          <div className="text-xs text-muted-foreground">{step.description}</div>
                          {step.command_preview && (
                            <code className="mt-1 block rounded bg-muted px-2 py-1 text-xs font-mono break-all">
                              {step.command_preview}
                            </code>
                          )}
                          {step.requires_admin && (
                            <span className="mt-1 inline-flex items-center gap-1 text-[11px] text-amber-300">
                              <AlertTriangle className="h-3 w-3" /> Requires administrator privileges
                            </span>
                          )}
                          {step.manual && (
                            <span className="mt-1 block text-[11px] text-amber-300">Manual step – you may need to complete this by hand.</span>
                          )}
                        </div>
                      </li>
                    ))}
                  </ol>
                )}
                {/* Verify restart note in plan preview */}
                <p className="text-xs text-muted-foreground">
                  After verification, BreachPilot will need to restart before the sandbox becomes active (boot-time decision).
                </p>
              </div>

              <div className="rounded-md border border-amber-500/30 bg-amber-500/10 px-3 py-2 text-xs">
                <p className="font-medium text-amber-200">This may install software, start a system service, build a Docker image, and request administrator privileges.</p>
                <p className="mt-1 text-muted-foreground">
                  Commands shown above will be executed on this host. BreachPilot will use explicit argument lists (no shell with untrusted input) and apply timeouts. Review the steps before continuing.
                </p>
              </div>

              {fixMutation.error && (
                <div className="rounded-md border border-destructive/40 bg-destructive/10 px-3 py-2 text-xs text-destructive">
                  {(fixMutation.error as Error).message}
                </div>
              )}
            </>
          )}

          {/* Fixing: progress view */}
          {isFixing && (
            <div className="space-y-3">
              <div className="flex items-center gap-2 text-sm font-medium">
                <Loader2 className="h-4 w-4 animate-spin" />
                Fixing sandbox...
              </div>
              <ul className="space-y-1.5">
                {displaySteps.map((s) => {
                  const status = (s as unknown as { status: string }).status;
                  let icon: ReactNode;
                  if (status === "succeeded") icon = <CheckCircle2 className="h-4 w-4 text-emerald-400" />;
                  else if (status === "running") icon = <Loader2 className="h-4 w-4 animate-spin text-blue-400" />;
                  else if (status === "failed") icon = <XCircle className="h-4 w-4 text-red-400" />;
                  else if (status === "pending") icon = <Circle className="h-4 w-4 text-muted-foreground/50" />;
                  else icon = <Circle className="h-4 w-4 text-muted-foreground/30" />;
                  const isRunning = status === "running";
                  return (
                    <li key={s.id} className="flex gap-2 text-sm items-start">
                      <span className="mt-0.5">{icon}</span>
                      <div className="flex-1">
                        <div className={`text-sm ${isRunning ? "font-medium text-foreground" : status === "succeeded" ? "text-emerald-300" : status === "failed" ? "text-red-300" : "text-muted-foreground"}`}>
                          {s.title}
                          {isRunning && <span className="ml-2 text-xs text-blue-400">→ running</span>}
                          {status === "succeeded" && <span className="ml-2 text-xs text-emerald-400">✓ done</span>}
                        </div>
                        {isRunning && s.description && <p className="text-xs text-muted-foreground">{s.description}</p>}
                        {(s as { output?: string }).output && isRunning && (
                          <p className="text-xs font-mono text-muted-foreground mt-1 break-all whitespace-pre-wrap">
                            {String((s as { output?: string }).output).slice(0, 500)}
                          </p>
                        )}
                      </div>
                    </li>
                  );
                })}
              </ul>
              {/* Collapsible details */}
              {job?.steps?.some((s) => s.output || s.error) && (
                <details className="rounded border bg-muted/20 px-3 py-2">
                  <summary className="cursor-pointer text-xs font-medium">Details / Command output</summary>
                  <div className="mt-2 space-y-2 max-h-48 overflow-auto">
                    {job.steps.map((s) => (
                      <div key={s.id} className="text-xs">
                        <div className="font-medium">{s.title} — {s.status}</div>
                        {s.command_preview && <code className="block rounded bg-background px-2 py-1 font-mono break-all">{s.command_preview}</code>}
                        {s.output && <pre className="mt-1 whitespace-pre-wrap break-all text-muted-foreground">{s.output.slice(0, 2000)}</pre>}
                        {s.error && <pre className="mt-1 whitespace-pre-wrap break-all text-red-300">{s.error.slice(0, 2000)}</pre>}
                      </div>
                    ))}
                  </div>
                </details>
              )}
            </div>
          )}

          {/* Success */}
          {isSuccess && (
            <div className="space-y-3">
              <div className="flex items-center gap-2 text-sm font-medium text-emerald-300">
                <CheckCircle2 className="h-5 w-5" />
                Docker is ready
              </div>
              <p className="text-sm text-muted-foreground">
                The BreachPilot sandbox can now be used, but the current server was started in native fallback mode. Restart BreachPilot to activate containment.
              </p>
              <p className="text-xs text-muted-foreground">
                Current boot mode remains <span className="font-mono">native_fallback</span> until restart – the UI will not falsely claim this process is now contained.
              </p>
              <div className="rounded-md border border-emerald-500/20 bg-emerald-500/5 px-3 py-2 text-xs">
                To apply the fix: stop the current BreachPilot daemon and start it again (e.g., close the terminal and run <code className="font-mono">python main.py</code> again). After restart, the banner should show <span className="font-medium text-emerald-300">Sandbox active</span>.
              </div>
              {/* Progress summary for success */}
              <ul className="space-y-1">
                {job.steps.map((s) => (
                  <li key={s.id} className="flex items-center gap-2 text-xs">
                    <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400" />
                    <span className="text-muted-foreground">{s.title}</span>
                  </li>
                ))}
              </ul>
              <details className="rounded border bg-muted/20 px-3 py-2">
                <summary className="cursor-pointer text-xs font-medium">Details</summary>
                <div className="mt-2 space-y-1">
                  {job.steps.map((s) => (
                    <div key={s.id} className="text-xs">
                      <div className="font-medium">{s.title}</div>
                      {s.output && <pre className="whitespace-pre-wrap break-all text-muted-foreground">{s.output.slice(0, 1000)}</pre>}
                    </div>
                  ))}
                </div>
              </details>
            </div>
          )}

          {/* Failed */}
          {isFailed && (
            <div className="space-y-3">
              <div className="flex items-center gap-2 text-sm font-medium text-red-300">
                <XCircle className="h-5 w-5" />
                Sandbox fix failed
              </div>
              {failedStep ? (
                <div className="rounded-md border border-red-500/30 bg-red-500/5 px-3 py-2 text-sm">
                  <p className="font-medium">Failed step: {failedStep.title}</p>
                  {failedStep.command_preview && (
                    <code className="mt-1 block rounded bg-background px-2 py-1 text-xs font-mono break-all">{failedStep.command_preview}</code>
                  )}
                  {(failedStep.error || failedStep.output) && (
                    <pre className="mt-1 whitespace-pre-wrap break-all text-xs text-muted-foreground">
                      {String(failedStep.error || failedStep.output).slice(0, 2000)}
                    </pre>
                  )}
                </div>
              ) : (
                <div className="rounded-md border border-red-500/30 bg-red-500/5 px-3 py-2 text-sm">
                  <p>{job.error || "An unknown error occurred during remediation."}</p>
                </div>
              )}
              {job.error && !failedStep && (
                <p className="text-xs text-muted-foreground">Error: {job.error}</p>
              )}
              <details className="rounded border bg-muted/20 px-3 py-2">
                <summary className="cursor-pointer text-xs font-medium">Details / Command output</summary>
                <div className="mt-2 space-y-2">
                  {job.steps.map((s) => (
                    <div key={s.id} className="text-xs">
                      <div className="font-medium">{s.title} — {s.status}</div>
                      {s.command_preview && <code className="block rounded bg-background px-2 py-1 font-mono break-all">{s.command_preview}</code>}
                      {s.output && <pre className="whitespace-pre-wrap break-all text-muted-foreground">{s.output.slice(0, 1000)}</pre>}
                      {s.error && <pre className="whitespace-pre-wrap break-all text-red-300">{s.error.slice(0, 1000)}</pre>}
                    </div>
                  ))}
                </div>
              </details>
            </div>
          )}
        </div>

        {/* Footer buttons */}
        <div className="flex justify-end gap-2 border-t pt-4 mt-2">
          {!isFixing && !isSuccess && !isFailed && (
            <>
              <Button variant="outline" size="sm" onClick={handleClose}>
                Cancel
              </Button>
              <Button
                size="sm"
                onClick={handleStartFix}
                disabled={planQuery.isLoading || !plan || fixMutation.isPending}
                className="gap-1.5"
              >
                {fixMutation.isPending && <Loader2 className="h-4 w-4 animate-spin" />}
                Start fix
              </Button>
            </>
          )}
          {isFixing && (
            <Button variant="outline" size="sm" disabled>
              <Loader2 className="h-4 w-4 animate-spin" />
              Fixing…
            </Button>
          )}
          {isSuccess && (
            <Button size="sm" variant="outline" onClick={handleClose}>
              Close
            </Button>
          )}
          {isFailed && (
            <>
              <Button variant="outline" size="sm" onClick={handleClose}>
                Close
              </Button>
              <Button size="sm" onClick={handleRetry}>
                Retry
              </Button>
            </>
          )}
        </div>
      </DialogContent>
    </Dialog>
  );
}

/**
 * Sandbox posture banner for the home screen. Surfaced at startup so the
 * operator always knows the effective execution mode before launching a run.
 * The reported mode is the session's BOOT-TIME decision (the API's
 * sandbox_boot_state.json), not a live Docker probe — a session's posture is
 * fixed when its server boots and never flips mid-run:
 * - contained: quiet green line (worker container active).
 * - disabled: quiet muted line (legacy host mode as configured).
 * - native_fallback: amber card — Docker was unusable at boot, the session
 *   degraded to uncontained native execution (fallback_native=true default).
 * - blocked: red card — strict fail-closed mode, executions will be denied.
 */
export function SandboxBanner() {
  const sandbox = useSandboxStatus();
  const [fixOpen, setFixOpen] = useState(false);
  if (sandbox.isLoading || sandbox.error || !sandbox.data) return null;
  const s = sandbox.data;
  const reason: string = s.fallback_reason || s.docker_error || "";
  // Old backends (no ``mode``) or future modes: say nothing rather than
  // rendering a false alarm (the cards below assert specific postures).
  const knownMode = ["contained", "disabled", "native_fallback", "blocked"].includes(s.mode ?? "");
  if (!knownMode) return null;

  if (s.mode === "contained") {
    return (
      <p className="flex items-center gap-1.5 text-xs text-muted-foreground" data-testid="sandbox-banner-contained">
        <ShieldCheck className="h-3.5 w-3.5 text-emerald-400" />
        Sandbox active — commands run inside the disposable Docker worker.
      </p>
    );
  }
  if (s.mode === "disabled") {
    return (
      <p className="flex items-center gap-1.5 text-xs text-muted-foreground" data-testid="sandbox-banner-disabled">
        <Info className="h-3.5 w-3.5" />
        Sandbox disabled — commands execute directly on the host (legacy mode). Enable it in settings for containment.
      </p>
    );
  }
  if (s.mode === "native_fallback") {
    return (
      <>
        <Card className="border-amber-500/40 bg-amber-500/5" data-testid="sandbox-banner-fallback">
          <CardContent className="p-3 text-sm">
            <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
              <div className="space-y-1 flex-1">
                <div className="flex flex-wrap items-center gap-2">
                  <ShieldAlert className="h-4 w-4 text-amber-300" />
                  <Badge variant="warn">Sandbox unavailable</Badge>
                  <span className="font-medium text-amber-200">
                    Running natively — execution is NOT contained.
                  </span>
                </div>
                {reason && <p className="text-xs text-muted-foreground">Reason: {reason}</p>}
                <p className="text-xs text-amber-200/80">{FALLBACK_HINT}</p>
                <p className="text-xs text-amber-200/60">Commands are currently executing directly on this host.</p>
              </div>
              <div className="flex shrink-0 sm:self-center">
                <Button
                  variant="outline"
                  size="sm"
                  className="gap-1.5 border-amber-500/40 text-amber-200 hover:bg-amber-500/10"
                  onClick={() => setFixOpen(true)}
                  aria-label="Fix sandbox"
                >
                  <Wrench className="h-4 w-4" />
                  Fix sandbox
                </Button>
              </div>
            </div>
          </CardContent>
        </Card>
        <SandboxFixDialog open={fixOpen} onOpenChange={setFixOpen} sandboxReason={reason} />
      </>
    );
  }
  // blocked (fail closed): sandbox required by config but unusable.
  return (
    <>
      <Card className="border-red-500/40 bg-red-500/5" data-testid="sandbox-banner-blocked">
        <CardContent className="p-3 text-sm">
          <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
            <div className="space-y-1 flex-1">
              <div className="flex flex-wrap items-center gap-2">
                <ShieldX className="h-4 w-4 text-red-300" />
                <Badge variant="danger">Sandbox required</Badge>
                <span className="font-medium text-red-200">
                  Execution is blocked — the sandbox is unavailable and fallback is disabled.
                </span>
              </div>
              {reason && <p className="text-xs text-muted-foreground">Reason: {reason}</p>}
              <p className="text-xs text-red-200/80">
                Start Docker and build the sandbox image, or set sandbox.fallback_native: true in config.yaml to allow
                uncontained native execution.
              </p>
            </div>
            <div className="flex shrink-0 sm:self-center">
              <Button
                variant="outline"
                size="sm"
                className="gap-1.5 border-red-500/40 text-red-200 hover:bg-red-500/10"
                onClick={() => setFixOpen(true)}
                aria-label="Fix sandbox"
              >
                <Wrench className="h-4 w-4" />
                Fix sandbox
              </Button>
            </div>
          </div>
        </CardContent>
      </Card>
      <SandboxFixDialog open={fixOpen} onOpenChange={setFixOpen} sandboxReason={reason} />
    </>
  );
}

export function HomePage() {
  const runs = useRuns(50, 0);
  const rows = runs.data?.runs ?? [];
  const activeRun = rows.find((r) => isActiveState(r.state));
  const recent = rows.slice(0, 5);
  const doneCount = rows.filter((r) => isTerminalState(r.state)).length;
  const failedCount = rows.filter((r) => r.state === "failed").length;
  const returning = rows.length > 0 && !runs.isLoading;
  const lastRow = rows[0];
  const lastTarget = lastRow?.target || lastRow?.target_ip || "—";

  return (
    <div className="relative mx-auto max-w-5xl space-y-8 p-4 md:p-8">
      <FullAccessNotice />
      {/* Hero */}
      <section className="relative overflow-hidden rounded-xl border bg-card/30 animate-fade-in-up">
        <div className="absolute inset-0 bg-grid bg-radial-fade" aria-hidden />
        <div className="absolute inset-0 overflow-hidden" aria-hidden>
          <div className="absolute inset-x-0 top-0 h-px animate-scan bg-gradient-to-r from-transparent via-primary/60 to-transparent" />
        </div>
        <div
          className="absolute -top-24 left-1/2 h-48 w-[60%] -translate-x-1/2 rounded-full bg-primary/10 blur-3xl"
          aria-hidden
        />
        <div className="relative flex flex-col gap-5 p-6 md:p-10">
          <div className="space-y-2">
            <h1 className="text-3xl font-semibold leading-tight tracking-tight md:text-4xl">
              {returning ? (
                <>
                  <span className="text-gradient-primary">Mission Control</span>
                </>
              ) : (
                <>
                  <span className="text-gradient-primary">BreachPilot</span>
                  <span className="text-foreground">AI</span>
                  <span className="text-sm font-normal tracking-wide text-muted-foreground"> — Mission Console</span>
                </>
              )}
            </h1>
            <p className="max-w-2xl text-sm leading-relaxed text-muted-foreground md:text-[15px]">
              {returning
                ? `${rows.length} run${rows.length === 1 ? "" : "s"} on record${
                    lastRow ? ` · Last target ${lastTarget} · ${formatRelative(lastRow.created_at)}` : ""
                  } — resume an active session or initiate a new assessment.`
                : "Autonomous assessment platform for authorized security testing. Plan, execute, and review assessments against assets you own or are explicitly authorized to test."}
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <Button asChild size="sm" className="gap-1.5 glow-primary">
              <Link to="/runs/new?path=recon">
                <ScanSearch className="h-4 w-4" />
                New recon
              </Link>
            </Button>
            {activeRun && (
              <Button
                asChild
                size="sm"
                variant="outline"
                className="border-yellow-500/40 text-yellow-300 hover:bg-yellow-500/10"
              >
                <Link to={`/runs/${activeRun.id}`}>
                  <Activity className="h-4 w-4 animate-pulse" />
                  Resume active
                </Link>
              </Button>
            )}
            <Button
              size="sm"
              variant="outline"
              className="gap-1.5"
              onClick={() => window.dispatchEvent(new Event("breachpilot:open-welcome"))}
            >
              <Compass className="h-4 w-4" />
              Product tour
            </Button>
          </div>

          {/* Stats strip. While loading with no cached data, hold skeletons
              instead of flashing 0s; keepPreviousData in useRuns means
              refetches keep the previous rows visible. */}
          {runs.isLoading && rows.length === 0 ? (
            <div className="grid grid-cols-2 gap-px overflow-hidden rounded-lg border bg-border sm:grid-cols-4" role="status" aria-label="Loading stats">
              {[0, 1, 2, 3].map((i) => (
                <div key={i} className="bg-card/60 px-4 py-3">
                  <div className="text-[10px] uppercase tracking-wide text-muted-foreground">&nbsp;</div>
                  <div className="mt-1 h-7 w-12 animate-pulse rounded bg-muted/60" />
                </div>
              ))}
            </div>
          ) : (
          <div className="grid grid-cols-2 gap-px overflow-hidden rounded-lg border bg-border sm:grid-cols-4">
            <Stat
              label="Total runs"
              value={rows.length.toString()}
              hint={runs.isFetching && rows.length === 0 ? "loading" : undefined}
            />
            <Stat label="Active" value={activeRun ? "1" : "0"} accent={activeRun ? "yellow" : undefined} />
            <Stat label="Completed" value={doneCount.toString()} accent="emerald" />
            <Stat label="Failed" value={failedCount.toString()} accent={failedCount > 0 ? "red" : undefined} />
          </div>
          )}
        </div>
      </section>

      {/* Sandbox posture (effective execution mode for this session) */}
      <SandboxBanner />

      {/* Active run banner */}
      {activeRun && (
        <Card className="border-yellow-500/40 bg-yellow-500/5">
          <CardContent className="flex flex-wrap items-center gap-2 p-3 text-sm">
            <Activity className="h-4 w-4 animate-pulse text-yellow-300" />
            <Badge variant="warn">Active</Badge>
            <span className="truncate font-mono text-xs">{activeRun.target}</span>
            <StatusBadge state={activeRun.state} />
            <Button asChild size="sm" variant="outline" className="ml-auto">
              <Link to={`/runs/${activeRun.id}`}>Open run</Link>
            </Button>
          </CardContent>
        </Card>
      )}

      {/* Action cards */}
      <section className="grid gap-3 sm:grid-cols-2 animate-fade-in-up" style={{ animationDelay: "0.1s" }}>
        <ActionCard
          to="/runs/new?path=recon"
          icon={<ScanSearch className="h-6 w-6" />}
          title="Recon & Suggest Goals"
          desc="Scan the target first, see what's open, then pick a goal from AI-ranked suggestions."
          accent="cyan"
        />
        <ActionCard
          to="/runs/new?path=attack"
          icon={<Target className="h-6 w-6" />}
          title="Attack"
          desc="Run a full exploitation session against a target with a preset or custom goal."
          accent="cyan"
        />
      </section>

      {/* Recent sessions */}
      <section className="rounded-xl border bg-card/30 animate-fade-in-up" style={{ animationDelay: "0.2s" }}>
        <header className="flex items-center justify-between gap-2 border-b px-4 py-2.5">
          <div className="flex items-center gap-2">
            <History className="h-4 w-4 text-muted-foreground" />
            <div>
              <div className="text-sm font-medium">Recent sessions</div>
              <p className="text-xs text-muted-foreground">
                Latest {recent.length || 0} of {rows.length || 0} runs.
              </p>
            </div>
          </div>
          <Button asChild size="sm" variant="outline" className="gap-1.5">
            <Link to="/sessions">
              <ListFilter className="h-3.5 w-3.5" />
              View all
            </Link>
          </Button>
        </header>

        {runs.error && (
          <div className="flex items-center gap-2 p-4 text-sm text-destructive">
            <span>Failed to load recent sessions.</span>
            <Button size="sm" variant="outline" onClick={() => runs.refetch()}>Retry</Button>
          </div>
        )}

        {recent.length === 0 && !runs.isLoading && !runs.error && (
          <div className="flex flex-col items-center gap-2 p-6 text-center text-sm text-muted-foreground">
            <Target className="h-7 w-7 opacity-40" />
            <span>No past sessions yet. Start one above.</span>
          </div>
        )}

        {runs.isLoading && recent.length === 0 && (
          <SkeletonRows count={3} className="p-2" />
        )}

        {recent.length > 0 && (
          <ul className="divide-y">
            {recent.map((row) => (
              <RecentRow key={row.id} row={row} />
            ))}
          </ul>
        )}
      </section>

      {/* Safety footer */}
      <p className="flex items-center justify-center gap-1.5 text-center text-[11px] tracking-wide text-muted-foreground">
        <span className="inline-block h-1.5 w-1.5 rounded-full bg-muted-foreground/40" />
        Authorized use only — operate exclusively against assets you own or are explicitly authorized to test.
      </p>
    </div>
  );
}

function Stat({
  label,
  value,
  hint,
  accent,
}: {
  label: string;
  value: string;
  hint?: string;
  accent?: "yellow" | "emerald" | "red";
}) {
  const accentClass =
    accent === "yellow"
      ? "text-yellow-300"
      : accent === "emerald"
        ? "text-emerald-300"
        : accent === "red"
          ? "text-red-300"
          : "text-foreground";
  return (
    <div className="bg-card/60 px-4 py-3">
      <div className="text-[10px] uppercase tracking-wide text-muted-foreground">{label}</div>
      <div className={`font-mono text-xl tabular-nums ${accentClass}`}>{hint ?? value}</div>
    </div>
  );
}

const ACCENTS = {
  cyan: {
    ring: "hover:border-primary/50 hover:glow-primary",
    icon: "text-primary",
  },
} as const;

function ActionCard({
  to,
  icon,
  title,
  desc,
  accent,
}: {
  to: string;
  icon: ReactNode;
  title: string;
  desc: string;
  accent: keyof typeof ACCENTS;
}) {
  const a = ACCENTS[accent];
  return (
    <Link
      to={to}
      className={`group relative flex flex-col items-start gap-2 rounded-lg border bg-card/40 p-4 text-left transition-all hover:bg-accent focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring ${a.ring}`}
    >
      <div className={`rounded-md border bg-secondary/40 p-2 ${a.icon}`}>
        {icon}
      </div>
      <div className="space-y-0.5">
        <div className="text-sm font-medium">{title}</div>
        <p className="text-xs text-muted-foreground">{desc}</p>
      </div>
      <span className="mt-0.5 inline-flex items-center gap-1 text-xs text-muted-foreground transition-transform group-hover:translate-x-0.5">
        Start <ArrowRight className="h-3 w-3" />
      </span>
    </Link>
  );
}

function RecentRow({ row }: { row: RunListRow }) {
  const target = row.target || row.target_ip || "—";
  const title = row.title || "";
  return (
    <li>
      <Link
        to={`/runs/${row.id}`}
        className="flex items-center gap-3 px-4 py-2 text-sm transition-colors hover:bg-accent/40"
      >
        <span className="font-mono text-xs text-muted-foreground" title={row.id}>
          {truncateId(row.id)}
        </span>
        <StatusBadge state={row.state} />
        {title ? (
          <span className="max-w-[16rem] truncate text-xs" title={title}>{title}</span>
        ) : (
          <span className="max-w-[16rem] truncate font-mono text-xs" title={target}>{target}</span>
        )}
        <span className="ml-auto hidden text-xs text-muted-foreground sm:inline">
          {row.mode}
        </span>
        <span
          className="text-xs text-muted-foreground"
          title={row.created_at}
        >
          {formatRelative(row.created_at)}
        </span>
      </Link>
    </li>
  );
}
