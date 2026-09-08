import { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { ChevronLeft, ChevronRight, Loader2, Plus, RotateCw, Sparkles, Trash2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { StatusBadge } from "@/components/StatusBadge";
import { CopyButton } from "@/components/CopyButton";
import { DemoBadge } from "@/components/DemoBadge";
import { useCapabilities, useDeleteRun, useRestoreDemo, useResumeRun, useRetitleRun, useRuns } from "@/api/hooks";
import { ApiError } from "@/api/client";
import { SkeletonRows } from "@/components/Loading";
import {
  RUN_SORT_OPTIONS,
  isActiveState,
  isDemoRun,
  isTerminalState,
  type RunSortKey,
  type RunState,
} from "@/api/types";
import { formatRelative, truncateId } from "@/lib/utils";

const SORT_KEY_STORAGE = "breachpilot.runSort";
const PAGE_SIZE = 50;

const STATE_FILTER_OPTIONS: { value: string; label: string }[] = [
  { value: "", label: "All states" },
  { value: "draft", label: "Draft" },
  { value: "awaiting_confirmation", label: "Awaiting confirmation" },
  { value: "queued", label: "Queued" },
  { value: "running", label: "Running" },
  { value: "awaiting_input", label: "Awaiting input" },
  { value: "cancelling", label: "Cancelling" },
  { value: "completed", label: "Completed" },
  { value: "failed", label: "Failed" },
  { value: "cancelled", label: "Cancelled" },
  { value: "interrupted", label: "Interrupted" },
];

function loadSortKey(): RunSortKey {
  try {
    const v = localStorage.getItem(SORT_KEY_STORAGE) ?? "";
    if (RUN_SORT_OPTIONS.some((o) => o.value === v)) return v as RunSortKey;
  } catch {
    /* SSR / storage disabled — fall through to default */
  }
  return "created_desc";
}

export function RunListPage() {
  const [sortKey, setSortKey] = useState<RunSortKey>(loadSortKey);
  const [q, setQ] = useState("");
  const [debouncedQ, setDebouncedQ] = useState("");
  const [stateFilter, setStateFilter] = useState("");
  const [page, setPage] = useState(0);
  const runs = useRuns(PAGE_SIZE, page * PAGE_SIZE, sortKey, debouncedQ, stateFilter);
  const capabilities = useCapabilities();
  const maxConcurrent = capabilities.data?.constraints.max_concurrent_runs ?? 1;
  const deleteRun = useDeleteRun();
  const resumeRun = useResumeRun();
  const retitleRun = useRetitleRun();
  const restoreDemo = useRestoreDemo();
  const navigate = useNavigate();
  const [pendingDelete, setPendingDelete] = useState<string | null>(null);
  const [confirmDelete, setConfirmDelete] = useState<string | null>(null);
  const [resumeTarget, setResumeTarget] = useState<string | null>(null);
  const [retitling, setRetitling] = useState<string | null>(null);

  useEffect(() => {
    const t = setTimeout(() => setDebouncedQ(q), 300);
    return () => clearTimeout(t);
  }, [q]);

  useEffect(() => {
    setPage(0);
  }, [debouncedQ]);

  const rows = runs.data?.runs ?? [];
  const total = runs.data?.total ?? 0;
  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));
  const activeRuns = rows.filter((r) => isActiveState(r.state));
  const atCapacity = activeRuns.length >= maxConcurrent;

  const onSortChange = (v: string) => {
    const next = v as RunSortKey;
    setSortKey(next);
    setPage(0);
    try { localStorage.setItem(SORT_KEY_STORAGE, next); } catch { /* ignore */ }
  };

  const onFilterChange = (nextQ: string, nextState: string) => {
    setQ(nextQ);
    setStateFilter(nextState);
    setPage(0);
  };

  const onDelete = (runId: string) => {
    setPendingDelete(runId);
    deleteRun.mutate(
      { runId, purge: true },
      { onSettled: () => setPendingDelete(null) },
    );
  };

  const onResume = (runId: string) => {
    setResumeTarget(runId);
    resumeRun.mutate(runId, {
      onSuccess: (data) => navigate(`/runs/${data.run_id}`),
      onSettled: () => setResumeTarget(null),
    });
  };

  const onRegenTitle = (runId: string) => {
    setRetitling(runId);
    retitleRun.mutate(
      { runId, regen: true },
      { onSettled: () => setRetitling(null) },
    );
  };

  return (
    <div className="space-y-4 p-4 md:p-6">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <h1 className="text-lg font-semibold">Sessions</h1>
          <div className="flex items-center gap-2">
            {atCapacity ? (
              <Button size="sm" disabled title={`${maxConcurrent} run(s) already active (api.max_concurrent_runs)`}>
                <Plus className="h-4 w-4" />
                New run
              </Button>
            ) : (
              <Button asChild size="sm">
                <Link to="/runs/new">
                  <Plus className="h-4 w-4" />
                  New run
                </Link>
              </Button>
            )}
          </div>
        </div>

      <div className="flex flex-wrap items-center gap-2">
        <Input
          placeholder="Search title, target, mode, goal..."
          value={q}
          onChange={(e) => onFilterChange(e.target.value, stateFilter)}
          className="h-8 max-w-xs text-xs"
        />
        <select
          value={stateFilter}
          onChange={(e) => onFilterChange(q, e.target.value)}
          className="h-8 rounded-md border border-input bg-background px-2 text-xs"
          aria-label="Filter by state"
        >
          {STATE_FILTER_OPTIONS.map((o) => (
            <option key={o.value} value={o.value}>{o.label}</option>
          ))}
        </select>
        <Select value={sortKey} onValueChange={onSortChange}>
          <SelectTrigger className="h-8 w-[10rem] text-xs" aria-label="Sort sessions">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {RUN_SORT_OPTIONS.map((o) => (
              <SelectItem key={o.value} value={o.value} className="text-xs">
                {o.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        {runs.isFetching && <Loader2 className="h-3.5 w-3.5 animate-spin text-muted-foreground" />}
      </div>

      {activeRuns.length > 0 && (
        <Card className="border-yellow-500/40 bg-yellow-500/5">
          <CardContent className="space-y-2 p-3 text-sm">
            <div className="flex flex-wrap items-center gap-2">
              <Badge variant="warn">Active ({activeRuns.length})</Badge>
              {maxConcurrent > 1 && (
                <span className="text-xs text-muted-foreground">cap {maxConcurrent}</span>
              )}
            </div>
            <div className="space-y-1.5">
              {activeRuns.map((r) => (
                <div key={r.id} className="flex flex-wrap items-center gap-2">
                  <span className="truncate font-mono text-xs">{r.target}</span>
                  <StatusBadge state={r.state} />
                  <Button asChild size="sm" variant="outline" className="ml-auto">
                    <Link to={`/runs/${r.id}`}>Open</Link>
                  </Button>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {runs.isLoading && <SkeletonRows count={4} className="p-2" />}
      {runs.error && (
        <div className="flex items-center gap-2 text-sm text-destructive">
          <span>{runs.error instanceof ApiError ? runs.error.message : "Failed to load runs."}</span>
          <Button size="sm" variant="outline" onClick={() => runs.refetch()}>Retry</Button>
        </div>
      )}

      {!runs.isLoading && rows.length === 0 && activeRuns.length === 0 && (
        <div className="rounded-md border border-dashed p-8 text-center text-sm text-muted-foreground">
          <div>No past sessions yet.{" "}<Link to="/" className="text-foreground underline-offset-4 hover:underline">Start one from home.</Link></div>
          <div className="mt-4">
            <Button
              size="sm"
              variant="outline"
              onClick={() => restoreDemo.mutate(undefined)}
              disabled={restoreDemo.isPending}
            >
              {restoreDemo.isPending ? <Loader2 className="mr-1 h-3.5 w-3.5 animate-spin" /> : null}
              Restore Demo Session
            </Button>
            <p className="mt-1 text-xs">Re-create the synthetic Meridian Finance Lab demo.</p>
          </div>
        </div>
      )}

      {rows.length > 0 && (
        <div className="overflow-x-auto rounded-md border">
          <table className="w-full border-collapse text-sm">
            <caption className="sr-only">Sessions</caption>
            <thead>
              <tr>
                <th scope="col">ID</th>
                <th scope="col">Title</th>
                <th scope="col">State</th>
                <th scope="col">Target</th>
                <th scope="col">Mode</th>
                <th scope="col">Goal</th>
                <th scope="col">Model</th>
                <th scope="col">Created</th>
                <th scope="col" className="text-right">Actions</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((row) => {
                const active = isActiveState(row.state);
                const terminal = isTerminalState(row.state as RunState);
                const title = row.title || "";
                const demo = isDemoRun(row);
                return (
                  <tr key={row.id} className={demo ? "bg-[rgba(99,102,241,0.04)]" : undefined}>
                    <td>
                      <div className="flex items-center gap-1.5">
                        <Link to={`/runs/${row.id}`} className="font-mono text-xs hover:underline" title={row.id}>
                          {truncateId(row.id)}
                        </Link>
                        <CopyButton value={row.id} size="icon" label="Copy ID" />
                        {demo && <DemoBadge />}
                      </div>
                    </td>
                    <td className="max-w-[18rem]">
                      <div className="flex items-center gap-1.5">
                        {title ? (
                          <Link to={`/runs/${row.id}`} className="block truncate text-xs hover:underline" title={title}>
                            {title}
                          </Link>
                        ) : (
                          <span className="text-xs text-muted-foreground italic">untitled</span>
                        )}
                        {demo && <DemoBadge />}
                      </div>
                    </td>
                    <td><StatusBadge state={row.state} /></td>
                    <td className="font-mono text-xs">{row.target || row.target_ip || "\u2014"}</td>
                    <td className="text-xs">{row.mode}</td>
                    <td className="text-xs">{row.goal_name || "\u2014"}</td>
                    <td className="font-mono text-xs">{row.model_alias || "\u2014"}</td>
                    <td className="text-xs text-muted-foreground" title={row.created_at}>{formatRelative(row.created_at)}</td>
                    <td className="text-right">
                      <div className="inline-flex items-center gap-1">
                        <Button asChild size="sm" variant="ghost">
                          <Link to={`/runs/${row.id}`}>Open</Link>
                        </Button>
                        <Button
                          size="sm"
                          variant="ghost"
                          onClick={() => onRegenTitle(row.id)}
                          disabled={retitling === row.id}
                          aria-label="Regenerate title with AI"
                          title="Regenerate title with AI"
                          className="text-muted-foreground hover:text-foreground"
                        >
                          {retitling === row.id ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Sparkles className="h-3.5 w-3.5" />}
                        </Button>
                        {terminal && (
                          <Button
                            size="sm"
                            variant="ghost"
                            onClick={() => onResume(row.id)}
                            disabled={resumeTarget === row.id}
                            aria-label="Resume run"
                          >
                            {resumeTarget === row.id ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <RotateCw className="h-3.5 w-3.5" />}
                          </Button>
                        )}
                        <Button
                          size="sm"
                          variant="ghost"
                          onClick={() => setConfirmDelete(row.id)}
                          disabled={active || pendingDelete === row.id}
                          aria-label="Delete run"
                          className="text-muted-foreground hover:text-destructive"
                        >
                          {pendingDelete === row.id ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Trash2 className="h-3.5 w-3.5" />}
                        </Button>
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      {total > PAGE_SIZE && (
        <div className="flex items-center justify-between gap-2 text-xs text-muted-foreground">
          <span>
            {total} session{total === 1 ? "" : "s"} · page {page + 1} of {totalPages}
          </span>
          <div className="flex items-center gap-1">
            <Button size="sm" variant="outline" onClick={() => setPage((p) => Math.max(0, p - 1))} disabled={page === 0}>
              <ChevronLeft className="h-3.5 w-3.5" />
              Prev
            </Button>
            <Button size="sm" variant="outline" onClick={() => setPage((p) => Math.min(totalPages - 1, p + 1))} disabled={page >= totalPages - 1}>
              Next
              <ChevronRight className="h-3.5 w-3.5" />
            </Button>
          </div>
        </div>
      )}

      <Dialog open={confirmDelete !== null} onOpenChange={(open) => { if (!open) setConfirmDelete(null); }}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Delete run?</DialogTitle>
            <DialogDescription>
              Permanently delete run <span className="font-mono">{confirmDelete}</span> and all of its artifacts? This cannot be undone.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setConfirmDelete(null)}>Cancel</Button>
            <Button
              variant="destructive"
              disabled={pendingDelete !== null}
              onClick={() => {
                if (confirmDelete) onDelete(confirmDelete);
                setConfirmDelete(null);
              }}
            >
              {pendingDelete !== null && <Loader2 className="h-4 w-4 animate-spin" />}
              Delete
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}