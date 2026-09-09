import { useMemo, useState } from "react";
import { Link, useParams, useSearchParams } from "react-router-dom";
import { ChevronLeft, FileText, RefreshCw } from "lucide-react";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Badge } from "@/components/ui/badge";
import { ArtifactViewer } from "@/components/ArtifactViewer";
import { WorkspaceViewer } from "@/components/WorkspaceViewer";
import { AuditRecordsTable } from "@/components/AuditRecordsTable";
import { EmptyState, SkeletonRows, Spinner } from "@/components/Loading";
import { useArtifacts, useAudit, useRunLog, useWorkspace } from "@/api/hooks";
import { ApiError } from "@/api/client";
import { formatBytes } from "@/lib/utils";

const RUN_LOGS = ["mcp_exploit_server.log", "session_error.log", "recon_first_error.log"];
const ATTEMPT_LOGS = ["terminal.log", "python_run.log", "msf_output.log", "run_active_check.ps1"];

export function ArtifactsPage() {
  const { runId } = useParams<{ runId: string }>();
  const [searchParams] = useSearchParams();
  // Deep-link support: /runs/:id/artifacts?log=session_error.log opens the
  // Logs tab with that log preselected (used by the failed-run card).
  const deepLog = searchParams.get("log") ?? "";
  const [tab, setTab] = useState(deepLog ? "logs" : "artifacts");
  const artifacts = useArtifacts(runId ?? null);
  const audit = useAudit(runId ?? null, tab === "audit");
  const workspace = useWorkspace(runId ?? null);
  const [selected, setSelected] = useState<string>("");

  const artifactNames = artifacts.data?.artifacts.map((a) => a.name) ?? [];
  const effectiveSelected = selected || artifactNames[0] || "";
  const artifactBytes = useMemo(
    () => new Map((artifacts.data?.artifacts ?? []).map((a) => [a.name, a.bytes])),
    [artifacts.data],
  );

  // The artifacts endpoint returns run-level names only — attempt dirs come
  // from the workspace listing, split on "/" (no regex needed).
  const attemptCandidates = useMemo(() => {
    const out: Array<{ target: string; attempt: string }> = [];
    const seen = new Set<string>();
    for (const f of workspace.data?.files ?? []) {
      const parts = f.path.split("/");
      if (parts[0] !== "exploit_workspace" || parts.length < 3) continue;
      const target = parts[1] ?? "";
      const attempt = parts[2] ?? "";
      if (!target || !attempt) continue;
      const key = `${target}|${attempt}`;
      if (!seen.has(key)) {
        seen.add(key);
        out.push({ target, attempt });
      }
    }
    return out;
  }, [workspace.data]);

  return (
    <div className="space-y-4 p-4 md:p-6">
      <div className="flex items-center gap-2">
        <Button asChild size="sm" variant="ghost">
          <Link to={`/runs/${runId}`}><ChevronLeft className="h-4 w-4" />Back to run</Link>
        </Button>
        <h1 className="text-sm font-mono text-muted-foreground">{runId}</h1>
        <Button size="sm" variant="ghost" onClick={() => artifacts.refetch()} disabled={artifacts.isFetching}>
          <RefreshCw className={cn("h-3.5 w-3.5", artifacts.isFetching && "animate-spin")} />
        </Button>
      </div>

      <Tabs value={tab} onValueChange={setTab}>
        <ScrollArea type="scroll" className="w-full">
          <TabsList>
            <TabsTrigger value="artifacts">Artifacts</TabsTrigger>
            <TabsTrigger value="workspace">Workspace</TabsTrigger>
            <TabsTrigger value="audit">Audit</TabsTrigger>
            <TabsTrigger value="logs">Logs</TabsTrigger>
          </TabsList>
        </ScrollArea>

        <TabsContent value="artifacts" className="grid gap-4 md:grid-cols-[260px_minmax(0,1fr)]">
          <div className="space-y-1">
            {artifacts.isLoading && <SkeletonRows count={4} />}
            {artifacts.error && <div className="text-sm text-destructive">Failed to load artifacts.</div>}
            {!artifacts.isLoading && artifactNames.length === 0 && (
              <div className="rounded-md border border-dashed p-4 text-sm text-muted-foreground">
                No artifacts yet. They appear as the run writes reports.
              </div>
            )}
            {artifactNames.map((name) => (
              <button
                key={name}
                type="button"
                onClick={() => setSelected(name)}
                className={cn(
                  "flex w-full items-center gap-2 rounded-md border px-2 py-1.5 text-left text-xs transition-colors",
                  effectiveSelected === name ? "border-primary bg-accent" : "hover:bg-accent/50",
                )}
              >
                <FileText className="h-3.5 w-3.5 shrink-0 text-muted-foreground" />
                <span className="truncate font-mono">{name}</span>
                <span className="ml-auto text-muted-foreground">{formatBytes(artifactBytes.get(name) ?? 0)}</span>
              </button>
            ))}
          </div>
          <div>
            {effectiveSelected ? (
              <Card>
                <CardHeader className="pb-2">
                  <CardTitle className="text-xs font-mono text-muted-foreground">{effectiveSelected}</CardTitle>
                </CardHeader>
                <CardContent>
                  <ArtifactViewer runId={runId ?? ""} name={effectiveSelected} />
                </CardContent>
              </Card>
            ) : (
              <div className="rounded-md border border-dashed p-8 text-center text-sm text-muted-foreground">
                Select an artifact to view it.
              </div>
            )}
          </div>
        </TabsContent>

        <TabsContent value="workspace">
          <WorkspacePanel runId={runId ?? ""} />
        </TabsContent>

        <TabsContent value="audit" className="space-y-3">
          <div className={cn("rounded-md border p-3 text-sm", audit.data?.chain_valid ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-200" : "border-destructive/40 bg-destructive/10 text-red-200")}>
            <div className="flex items-center gap-2 text-xs uppercase tracking-wide">
              <Badge variant={audit.data?.chain_valid ? "success" : "danger"}>
                {audit.data?.chain_valid ? "Chain valid" : "Chain invalid"}
              </Badge>
            </div>
            <div className="mt-1 text-xs">{audit.data?.chain_reason ?? ""}</div>
          </div>
          {audit.isLoading && <SkeletonRows count={3} />}
          {audit.error && <div className="text-sm text-destructive">Failed to load audit.</div>}
          {!audit.isLoading && !audit.error && (audit.data?.records.length ?? 0) === 0 && (
            <EmptyState message="No audit records." />
          )}
          {(audit.data?.records.length ?? 0) > 0 && <AuditRecordsTable records={audit.data?.records ?? []} />}
        </TabsContent>

        <TabsContent value="logs">
          <LogsPanel runId={runId ?? ""} attemptCandidates={attemptCandidates} initialLog={deepLog} />
        </TabsContent>
      </Tabs>
    </div>
  );
}

function WorkspacePanel({ runId }: { runId: string }) {
  const workspace = useWorkspace(runId);
  const [selected, setSelected] = useState<string>("");
  const [filter, setFilter] = useState<string>("");

  const files = workspace.data?.files ?? [];
  const filtered = useMemo(() => {
    const q = filter.trim().toLowerCase();
    if (!q) return files;
    return files.filter((f) => f.path.toLowerCase().includes(q));
  }, [files, filter]);

  const effectiveSelected = selected || filtered[0]?.path || "";

  return (
    <div className="grid gap-4 md:grid-cols-[260px_minmax(0,1fr)]">
      <div className="space-y-2">
        <Input placeholder="Filter files..." value={filter} onChange={(e) => setFilter(e.target.value)} />
        <div className="max-h-[70vh] space-y-1 overflow-auto">
          {workspace.isLoading && <SkeletonRows count={4} />}
          {workspace.error && <div className="text-sm text-destructive">Failed to load workspace.</div>}
          {!workspace.isLoading && filtered.length === 0 && (
            <div className="rounded-md border border-dashed p-4 text-sm text-muted-foreground">
              No workspace files yet.
            </div>
          )}
          {filtered.map((f) => (
            <button
              key={f.path}
              type="button"
              onClick={() => setSelected(f.path)}
              className={cn(
                "flex w-full items-center gap-2 rounded-md border px-2 py-1.5 text-left text-xs transition-colors",
                effectiveSelected === f.path ? "border-primary bg-accent" : "hover:bg-accent/50",
              )}
            >
              <FileText className="h-3.5 w-3.5 shrink-0 text-muted-foreground" />
              <span className="truncate font-mono">{f.path}</span>
              <span className="ml-auto text-muted-foreground">{formatBytes(f.bytes)}</span>
            </button>
          ))}
        </div>
      </div>
      <div>
        {effectiveSelected ? (
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-xs font-mono text-muted-foreground">{effectiveSelected}</CardTitle>
            </CardHeader>
            <CardContent>
              <WorkspaceViewer runId={runId} path={effectiveSelected} />
            </CardContent>
          </Card>
        ) : (
          <div className="rounded-md border border-dashed p-8 text-center text-sm text-muted-foreground">
            Select a file to view it.
          </div>
        )}
      </div>
    </div>
  );
}

interface LogsPanelProps {
  runId: string;
  attemptCandidates: Array<{ target: string; attempt: string }>;
}

function LogsPanel({ runId, attemptCandidates, initialLog = "" }: LogsPanelProps & { initialLog?: string }) {
  const [name, setName] = useState<string>(
    [...RUN_LOGS, ...ATTEMPT_LOGS].includes(initialLog) ? initialLog : (RUN_LOGS[0] ?? ""),
  );
  const [tail, setTail] = useState<number>(200);
  const [attempt, setAttempt] = useState<string>(attemptCandidates[0]?.attempt ?? "");
  const [target, setTarget] = useState<string>(attemptCandidates[0]?.target ?? "");
  const isAttemptLog = ATTEMPT_LOGS.includes(name);
  const log = useRunLog(runId, name, tail, attempt, target, true);

  return (
    <div className="space-y-3">
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <div className="space-y-1.5">
          <Label className="text-xs">Log</Label>
          <select
            value={name}
            onChange={(e) => setName(e.target.value)}
            className="h-9 w-full rounded-md border border-input bg-background px-2 text-sm"
          >
            <optgroup label="Run-level">
              {RUN_LOGS.map((n) => <option key={n} value={n}>{n}</option>)}
            </optgroup>
            <optgroup label="Per-attempt">
              {ATTEMPT_LOGS.map((n) => <option key={n} value={n}>{n}</option>)}
            </optgroup>
          </select>
        </div>
        <div className="space-y-1.5">
          <Label className="text-xs">Tail (lines)</Label>
          <Input type="number" min={1} max={2000} value={tail} onChange={(e) => { const v = Number(e.target.value); setTail(Number.isFinite(v) ? Math.min(2000, Math.max(1, v)) : 1); }} />
        </div>
        {isAttemptLog && (
          <>
            <div className="space-y-1.5">
              <Label className="text-xs">Attempt ID</Label>
              <select
                value={attempt}
                onChange={(e) => setAttempt(e.target.value)}
                className="h-9 w-full rounded-md border border-input bg-background px-2 text-sm"
              >
                {attemptCandidates.length === 0 && <option value="">(none discovered)</option>}
                {attemptCandidates.map((c) => (
                  <option key={`${c.target}|${c.attempt}`} value={c.attempt}>{c.attempt}</option>
                ))}
              </select>
            </div>
            <div className="space-y-1.5">
              <Label className="text-xs">Target IP</Label>
              <select
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                className="h-9 w-full rounded-md border border-input bg-background px-2 text-sm"
              >
                {attemptCandidates.length === 0 && <option value="">(none discovered)</option>}
                {attemptCandidates.map((c) => (
                  <option key={`${c.target}|${c.attempt}`} value={c.target}>{c.target}</option>
                ))}
              </select>
            </div>
          </>
        )}
      </div>

      {isAttemptLog && attemptCandidates.length === 0 && (
        <div className="rounded-md border border-amber-500/30 bg-amber-500/10 p-3 text-xs text-amber-700 dark:text-amber-200">
          Per-attempt logs require attempt_id and target_ip. No attempt directories were found in the
          workspace listing yet — they appear once the run writes exploit output.
        </div>
      )}

      <div className="space-y-2">
        <div className="flex items-center gap-2">
          <Badge variant="outline" className="text-xs">{name}</Badge>
          {log.data && <span className="text-xs text-muted-foreground">{log.data.total_lines_returned}/{log.data.total_lines_in_file} lines</span>}
          <Button size="sm" variant="ghost" onClick={() => log.refetch()} disabled={log.isFetching}>
            <RefreshCw className={cn("h-3.5 w-3.5", log.isFetching && "animate-spin")} />
          </Button>
        </div>
        {log.isLoading && <Spinner label="Loading log..." />}
        {log.error && (
          <div className="rounded-md border border-destructive/40 bg-destructive/10 p-3 text-sm text-red-200">
            {log.error instanceof ApiError ? log.error.message : "Failed to load log."}
          </div>
        )}
        {log.data && (
          <pre className="max-h-[60vh] overflow-auto rounded-md border bg-muted/30 p-3 font-mono text-xs whitespace-pre-wrap break-words scrollbar-thin">
            {log.data.lines.join("\n") || "(empty)"}
          </pre>
        )}
      </div>
    </div>
  );
}