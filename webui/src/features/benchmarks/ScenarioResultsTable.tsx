// BreachPilot by @braydos-h — https://github.com/braydos-h/BreachPilot
// Scenario results table: sortable + status-filtered trial results.
import { useMemo, useState } from "react";
import { ChevronDown, ChevronUp } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { cn } from "@/lib/utils";
import { formatCost, formatDuration } from "@/features/benchmarks/MetricCards";
import type { Trial } from "@/features/benchmarks/types";

// COMPLETED (unverified) is neutral/sky — VERIFIED alone owns emerald. REGRESSED
// is the comparison-view category badge, distinct from FALSE_POSITIVE triage.
export const STATUS_META: Record<string, { label: string; className: string }> = {
  VERIFIED: { label: "Verified", className: "bg-emerald-500/15 text-emerald-700 dark:text-emerald-300" },
  COMPLETED: { label: "Completed", className: "bg-sky-500/15 text-sky-700 dark:text-sky-300" },
  FAILED: { label: "Failed", className: "bg-red-500/15 text-red-700 dark:text-red-300" },
  FALSE_POSITIVE: { label: "False positive", className: "bg-amber-500/15 text-amber-700 dark:text-amber-300" },
  REGRESSED: { label: "Regressed", className: "bg-red-500/15 text-red-700 dark:text-red-300" },
  TIMEOUT: { label: "Timeout", className: "bg-orange-500/15 text-orange-700 dark:text-orange-300" },
  INFRASTRUCTURE_ERROR: { label: "Infra error", className: "bg-sky-500/15 text-sky-700 dark:text-sky-300" },
  RUNNING: { label: "Running", className: "bg-amber-500/15 text-amber-700 dark:text-amber-300" },
  CANCELLED: { label: "Cancelled", className: "bg-muted text-muted-foreground" },
  INTERRUPTED: { label: "Interrupted", className: "bg-orange-500/15 text-orange-700 dark:text-orange-300" },
  SKIPPED: { label: "Skipped", className: "bg-muted text-muted-foreground" },
};

export function StatusBadge({ status }: { status: string }) {
  const meta = STATUS_META[status] ?? { label: status, className: "bg-muted text-muted-foreground" };
  return (
    <span
      className={cn("inline-flex items-center rounded-full px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide", meta.className)}
    >
      {meta.label}
    </span>
  );
}

type SortKey = "scenario_id" | "status" | "duration_seconds" | "tool_calls" | "total_tokens" | "estimated_cost";

// Sort order for status — includes UI-only states (RUNNING/CANCELLED/
// INTERRUPTED) that appear on live/interrupted runs in addition to the
// backend's per-trial vocabulary.
const STATUS_ORDER: string[] = [
  "VERIFIED",
  "FAILED",
  "FALSE_POSITIVE",
  "TIMEOUT",
  "INFRASTRUCTURE_ERROR",
  "RUNNING",
  "CANCELLED",
  "INTERRUPTED",
  "SKIPPED",
];

export interface ScenarioResultsTableProps {
  trials: Trial[];
  isLoading?: boolean;
}

export function ScenarioResultsTable({ trials, isLoading }: ScenarioResultsTableProps) {
  const [statusFilter, setStatusFilter] = useState<string>("all");
  const [query, setQuery] = useState("");
  const [sortKey, setSortKey] = useState<SortKey>("scenario_id");
  const [sortAsc, setSortAsc] = useState(true);

  const filtered = useMemo(() => {
    let rows = [...trials];
    if (statusFilter !== "all") rows = rows.filter((t) => t.status === statusFilter);
    const q = query.trim().toLowerCase();
    if (q) {
      rows = rows.filter(
        (t) =>
          t.scenario_id.toLowerCase().includes(q) ||
          t.trial_id.toLowerCase().includes(q) ||
          (t.failure_category ?? "").toLowerCase().includes(q),
      );
    }
    const dir = sortAsc ? 1 : -1;
    rows.sort((a, b) => {
      if (sortKey === "status") {
        return dir * (STATUS_ORDER.indexOf(a.status) - STATUS_ORDER.indexOf(b.status));
      }
      const av = a[sortKey];
      const bv = b[sortKey];
      if (typeof av === "string" || typeof bv === "string") {
        return dir * String(av ?? "").localeCompare(String(bv ?? ""));
      }
      return dir * ((av as number | null ?? 0) - (bv as number | null ?? 0));
    });
    return rows;
  }, [trials, statusFilter, query, sortKey, sortAsc]);

  const toggleSort = (key: SortKey) => {
    if (key === sortKey) setSortAsc(!sortAsc);
    else {
      setSortKey(key);
      setSortAsc(true);
    }
  };

  const statuses = ["all", ...Object.keys(STATUS_META)];

  const header = (label: string, key?: SortKey) => {
    const isSorted = !!key && key === sortKey;
    return (
      <th
        className="px-3 py-2.5 font-medium"
        aria-sort={isSorted ? (sortAsc ? "ascending" : "descending") : key ? "none" : undefined}
      >
        {key ? (
          <button
            type="button"
            className="inline-flex cursor-pointer select-none items-center gap-1 rounded hover:text-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
            onClick={() => toggleSort(key)}
          >
            {label}
            {isSorted && (sortAsc ? <ChevronUp className="h-3 w-3" aria-hidden /> : <ChevronDown className="h-3 w-3" aria-hidden />)}
          </button>
        ) : (
          <span className="inline-flex items-center gap-1">{label}</span>
        )}
      </th>
    );
  };

  if (isLoading) {
    return <div className="py-8 text-center text-sm text-muted-foreground">Loading scenario results…</div>;
  }
  if (trials.length === 0) {
    return <div className="py-8 text-center text-sm text-muted-foreground">No trials recorded yet.</div>;
  }

  return (
    <div className="space-y-3" data-testid="scenario-results-table">
      <div className="flex flex-wrap items-center gap-2">
        <Input
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Filter by scenario…"
          className="h-8 w-48"
          aria-label="Filter scenarios"
        />
        <div className="flex flex-wrap gap-1" role="group" aria-label="Filter by status">
          {statuses.map((s) => (
            <button
              key={s}
              type="button"
              aria-pressed={statusFilter === s}
              onClick={() => setStatusFilter(s)}
              className={cn(
                "rounded-md px-2 py-1 text-[11px] font-medium uppercase tracking-wide transition-colors",
                statusFilter === s
                  ? "bg-primary/15 text-primary"
                  : "text-muted-foreground hover:bg-accent hover:text-foreground",
              )}
            >
              {s === "all" ? "All" : (STATUS_META[s]?.label ?? s)}
            </button>
          ))}
        </div>
        <span className="ml-auto text-xs text-muted-foreground">
          {filtered.length} of {trials.length} trials
        </span>
      </div>
      <div className="overflow-x-auto rounded-lg border">
        <table className="w-full text-left text-sm">
          <thead className="bg-muted/40 text-xs uppercase tracking-wide text-muted-foreground">
            <tr>
              {header("Scenario", "scenario_id")}
              {header("Status", "status")}
              <th className="px-3 py-2.5 font-medium">Verified</th>
              <th className="px-3 py-2.5 font-medium">Agent claimed</th>
              <th className="px-3 py-2.5 font-medium">FP</th>
              {header("Time", "duration_seconds")}
              {header("Actions", "tool_calls")}
              {header("Tokens", "total_tokens")}
              {header("Cost", "estimated_cost")}
            </tr>
          </thead>
          <tbody>
            {filtered.length === 0 ? (
              <tr>
                <td colSpan={9} className="px-3 py-6 text-center text-sm text-muted-foreground">
                  No trials match the current filters.
                </td>
              </tr>
            ) : (
              filtered.map((t) => (
                <tr key={t.trial_id} className="border-t hover:bg-muted/20">
                  <td className="px-3 py-2 font-mono text-xs">{t.scenario_id}</td>
                  <td className="px-3 py-2">
                    <StatusBadge status={t.status} />
                  </td>
                  <td className="px-3 py-2 tabular-nums">{t.oracle_verified_success ? "yes" : "no"}</td>
                  <td className="px-3 py-2 tabular-nums">{t.agent_claimed_success ? "yes" : "no"}</td>
                  <td className="px-3 py-2 tabular-nums">
                    {t.false_positive ? <Badge variant="destructive" className="px-1.5 py-0 text-[10px]">FP</Badge> : "—"}
                  </td>
                  <td className="px-3 py-2 tabular-nums">{formatDuration(t.duration_seconds)}</td>
                  <td className="px-3 py-2 tabular-nums">{t.tool_calls}</td>
                  <td className="px-3 py-2 tabular-nums">{t.total_tokens.toLocaleString()}</td>
                  <td className="px-3 py-2 tabular-nums">{formatCost(t.estimated_cost)}</td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
