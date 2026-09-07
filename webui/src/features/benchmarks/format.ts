// BreachPilot by @braydos-h — https://github.com/braydos-h/BreachPilot
// Shared formatters + status helpers for the benchmark suite.
// Single source so pages, cards, tables and charts stay consistent.

export function formatDuration(seconds: number | null | undefined): string {
  if (seconds === null || seconds === undefined || !Number.isFinite(seconds)) return "n/a";
  const s = Math.max(0, Math.round(seconds));
  const minutes = Math.floor(s / 60);
  const secs = s % 60;
  if (minutes >= 60) {
    const hours = Math.floor(minutes / 60);
    return `${hours}h ${String(minutes % 60).padStart(2, "0")}m`;
  }
  return `${minutes}m ${String(secs).padStart(2, "0")}s`;
}

export function formatCost(value: number | null | undefined): string {
  if (value === null || value === undefined || !Number.isFinite(value)) return "n/a";
  // Sub-cent precision matters for single-trial benchmark runs; avoid a
  // misleading flat "$0.00" for a real (tiny) estimate.
  if (value > 0 && value < 0.01) return `$${value.toFixed(4)}`;
  return `$${value.toFixed(2)}`;
}

export function formatPct(value: number | null | undefined, digits = 1): string {
  if (value === null || value === undefined || !Number.isFinite(value)) return "n/a";
  return `${(value * 100).toFixed(digits)}%`;
}

/** States in which a benchmark run occupies the runner (polling continues). */
export function isActiveState(state: string): boolean {
  return state === "running" || state === "starting" || state === "cancelling";
}

/** Terminal index/run status → badge status label (STATUS_META key).
 *
 * Run-level completion is NOT trial-level verification: a run that finished
 * with zero verified trials must never render VERIFIED. */
export function runStatusToBadge(status: string): string {
  switch (status) {
    case "completed":
      return "COMPLETED";
    case "cancelled":
      return "CANCELLED";
    case "running":
    case "starting":
    case "cancelling":
      return "RUNNING";
    case "failed":
    case "error":
      return "FAILED";
    default:
      return status === "" ? "FAILED" : status.toUpperCase();
  }
}

/** True for terminal run statuses (polling must stop). */
export function isTerminalStatus(status: string | undefined): boolean {
  if (!status) return false;
  return !isActiveState(status);
}

/** True when a run's persisted status still claims to be in flight but no
 *  runner owns it (the daemon was restarted mid-run): `run.json` is only
 *  finalized at the end, so an orphaned run reads "running" forever. */
export function isOrphanedRun(
  runStatus: string | undefined,
  overview: { active: { run_id: string | null; state: string } } | undefined,
  runId: string,
): boolean {
  if (!runStatus || !isActiveState(runStatus)) return false;
  if (!overview) return false; // overview unknown → give the run the benefit of the doubt
  return overview.active.run_id !== runId || !isActiveState(overview.active.state);
}
