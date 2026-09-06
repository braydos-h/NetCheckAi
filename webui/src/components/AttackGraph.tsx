import { useEffect, useMemo, useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { CheckCircle2, Clock, Loader2, Network, Wrench, XCircle } from "lucide-react";
import { cn } from "@/lib/utils";
import { useCallTool, useFetchArtifactBlob } from "@/api/hooks";
import { ApiError } from "@/api/client";
import type {
  AttackTimelineEntry,
  EnhancedReport,
  ExploitationChain,
  FailureAnalysisEntry,
  TechnicalFinding,
} from "@/api/types";

// B2: attack-graph view. Renders exploitation_chains[] from the enhanced
// report JSON (Flow A writes reports/<run_id>/enhanced/enhanced_report.json).
// Pure SVG — no graph library. Chains are short (3-10 nodes) so a hand-rolled
// left-to-right column layout reads better than a force-directed graph.

interface AttackGraphProps {
  runId: string;
  className?: string;
  ready?: boolean;
}

export function AttackGraph({ runId, className, ready = true }: AttackGraphProps) {
  const fetchArtifact = useFetchArtifactBlob(runId);
  const [report, setReport] = useState<EnhancedReport | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string>("");
  const mutate = fetchArtifact.mutate;

  useEffect(() => {
    // Don't fetch the enhanced report until the run is terminal or the artifact
    // list confirms it exists -- otherwise an in-progress run 404s on every
    // mount (StrictMode double-mount + tab remounts).
    if (!ready) {
      setLoading(false);
      setReport(null);
      setError("");
      return;
    }
    setLoading(true);
    setError("");
    setReport(null);
    mutate("enhanced/enhanced_report.json", {
      onSuccess: async (blob) => {
        try {
          const text = await blob.text();
          setReport(JSON.parse(text) as EnhancedReport);
        } catch {
          setError("enhanced_report.json is not valid JSON.");
        }
        setLoading(false);
      },
      onError: (err) => {
        setError(
          err instanceof ApiError && err.isNotFound
            ? "No enhanced report yet for this run."
            : "Failed to load enhanced report.",
        );
        setReport(null);
        setLoading(false);
      },
    });
  }, [mutate, runId, ready]);

  if (loading) {
    return (
      <div className="flex items-center gap-2 p-4 text-sm text-muted-foreground">
        <Loader2 className="h-4 w-4 animate-spin" />
        Loading attack graph...
      </div>
    );
  }
  if (!ready && !report && !error) {
    return (
      <div className="rounded-md border border-dashed p-4 text-sm text-muted-foreground">
        Attack path report is generated when the run completes.
      </div>
    );
  }
  if (error) {
    return (
      <div className="rounded-md border border-dashed p-4 text-sm text-muted-foreground">
        {error}
      </div>
    );
  }
  if (!report) return null;

  const chains = report.exploitation_chains ?? [];
  const findings = report.technical_findings ?? [];
  const timeline = report.attack_timeline ?? [];
  const failures = report.failure_analysis ?? [];

  if (chains.length === 0 && findings.length === 0 && timeline.length === 0 && failures.length === 0) {
    return (
      <div className="rounded-md border border-dashed p-4 text-sm text-muted-foreground">
        No exploitation chains or findings in this report.
      </div>
    );
  }

  return (
    <div className={cn("space-y-4", className)}>
      <div className="flex flex-wrap items-center gap-3">
        <Badge variant="outline" className="tabular-nums">{chains.length} chains</Badge>
        <Badge variant="outline" className="tabular-nums">{findings.length} findings</Badge>
        {timeline.length > 0 && (
          <Badge variant="outline" className="tabular-nums">{timeline.length} timeline events</Badge>
        )}
        {failures.length > 0 && (
          <Badge variant="outline" className="tabular-nums">{failures.length} failure groups</Badge>
        )}
        {report.report_metadata && (
          <span className="text-xs text-muted-foreground">
            generated: {String(report.report_metadata.generated_at ?? "—")}
          </span>
        )}
      </div>

      {chains.map((chain) => (
        <ChainCard key={chain.chain_id} chain={chain} />
      ))}

      {findings.length > 0 && <FindingsTable findings={findings} runId={runId} />}

      {timeline.length > 0 && <TimelineCard entries={timeline} />}

      {failures.length > 0 && <FailurePanel failures={failures} />}
    </div>
  );
}

// ── Chain SVG ──────────────────────────────────────────────────────────────

const NODE_W = 150;
const NODE_H = 46;
const NODE_GAP_X = 36;
const PADDING = 16;

function ChainCard({ chain }: { chain: ExploitationChain }) {
  const entries = chain.entries ?? [];
  const width = Math.max(entries.length * (NODE_W + NODE_GAP_X) - NODE_GAP_X + PADDING * 2, 320);
  const height = NODE_H + PADDING * 2;
  const markerId = `arrow-${chain.chain_id}`;

  return (
    <Card className="border-border/60">
      <CardHeader className="pb-2">
        <CardTitle className="flex flex-wrap items-center gap-2 text-sm">
          <Network className="h-4 w-4" />
          <span className="font-mono">{chain.chain_id}</span>
          <Badge variant="outline" className="font-mono text-xs">{chain.target}</Badge>
          {chain.successful ? (
            <Badge variant="success" className="text-xs">successful</Badge>
          ) : (
            <Badge variant="danger" className="text-xs">failed</Badge>
          )}
          {chain.final_privilege && chain.final_privilege !== "none" && (
            <Badge variant="outline" className="text-xs">priv: {chain.final_privilege}</Badge>
          )}
        </CardTitle>
      </CardHeader>
      <CardContent>
        {entries.length === 0 ? (
          <p className="text-xs text-muted-foreground">No chain entries.</p>
        ) : (
          <div className="overflow-x-auto">
            <svg
              width={width}
              height={height}
              role="img"
              aria-label={`Attack chain ${chain.chain_id} for ${chain.target}`}
              className="max-w-full"
            >
              {entries.map((entry, i) => {
                const x = PADDING + i * (NODE_W + NODE_GAP_X);
                const y = PADDING;
                const success = (entry.result ?? "").toLowerCase() === "success";
                const fill = success ? "rgba(16,185,129,0.12)" : "rgba(239,68,68,0.12)";
                const stroke = success ? "rgb(52,211,153)" : "rgb(248,113,113)";
                return (
                  <g key={i}>
                    {i > 0 && (
                      <line
                        x1={x - NODE_GAP_X}
                        y1={y + NODE_H / 2}
                        x2={x}
                        y2={y + NODE_H / 2}
                        stroke="currentColor"
                        strokeWidth={1.5}
                        className="text-muted-foreground/60"
                        markerEnd={`url(#${markerId})`}
                      />
                    )}
                    <rect
                      x={x}
                      y={y}
                      width={NODE_W}
                      height={NODE_H}
                      rx={6}
                      fill={fill}
                      stroke={stroke}
                      strokeWidth={1.5}
                    />
                    <text
                      x={x + 8}
                      y={y + 18}
                      className="fill-foreground font-mono"
                      style={{ fontSize: 11 }}
                    >
                      {truncate(String(entry.module ?? "?"), 18)}
                    </text>
                    <text
                      x={x + 8}
                      y={y + 34}
                      className={success ? "fill-emerald-400" : "fill-red-400"}
                      style={{ fontSize: 10 }}
                    >
                      {entry.result ?? "—"}
                    </text>
                  </g>
                );
              })}
              <defs>
                <marker
                  id={markerId}
                  viewBox="0 0 10 10"
                  refX="8"
                  refY="5"
                  markerWidth="6"
                  markerHeight="6"
                  orient="auto-start-reverse"
                >
                  <path d="M 0 0 L 10 5 L 0 10 z" className="fill-muted-foreground/60" />
                </marker>
              </defs>
            </svg>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

// ── Findings table ─────────────────────────────────────────────────────────

function severityVariant(sev: string): "danger" | "info" | "success" | "outline" {
  const s = sev.toLowerCase();
  if (s === "critical" || s === "high") return "danger";
  if (s === "medium") return "info";
  if (s === "low") return "outline";
  return "outline";
}

function retestVariant(v: string): "danger" | "success" | "outline" {
  if (v === "STILL_OPEN") return "danger";
  if (v === "FIXED") return "success";
  return "outline";
}

function FindingsTable({ findings, runId }: { findings: TechnicalFinding[]; runId: string }) {
  const rows = useMemo(
    () => [...findings].sort((a, b) => (b.cvss?.base_score ?? 0) - (a.cvss?.base_score ?? 0)),
    [findings],
  );
  // Closed-loop retest: one Retest button per finding calls retest_finding
  // through the existing tool-call path; the returned verdict shows inline.
  const callTool = useCallTool(runId);
  const [verdicts, setVerdicts] = useState<Record<string, string>>({});
  const [pendingId, setPendingId] = useState<string | null>(null);
  const [errors, setErrors] = useState<Record<string, string>>({});

  const retest = (f: TechnicalFinding) => {
    setPendingId(f.finding_id);
    callTool.mutate(
      { tool: "retest_finding", arguments: { target_ip: f.affected_asset, finding_id: f.finding_id } },
      {
        onSuccess: (data) => {
          const m = /VERDICT:\s*(STILL_OPEN|FIXED|INCONCLUSIVE)/.exec(data.result || "");
          setVerdicts((v) => ({ ...v, [f.finding_id]: m?.[1] ?? data.result ?? "(no output)" }));
          setErrors((e) => {
            const next = { ...e };
            delete next[f.finding_id];
            return next;
          });
          setPendingId(null);
        },
        onError: (err) => {
          setErrors((e) => ({
            ...e,
            [f.finding_id]: err instanceof ApiError ? err.message : "Tool call failed.",
          }));
          setPendingId(null);
        },
      },
    );
  };

  return (
    <Card className="border-border/60">
      <CardHeader className="pb-2">
        <CardTitle className="text-sm">Technical Findings</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="overflow-x-auto rounded-md border">
          <table className="w-full border-collapse text-xs">
            <caption className="sr-only">Technical findings</caption>
            <thead>
              <tr className="bg-muted/40">
                <th scope="col" className="p-2 text-left">Severity</th>
                <th scope="col" className="p-2 text-left">CVSS</th>
                <th scope="col" className="p-2 text-left">Finding</th>
                <th scope="col" className="p-2 text-left">Asset</th>
                <th scope="col" className="p-2 text-left">Class</th>
                <th scope="col" className="p-2 text-left">Retest</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((f) => {
                const live = verdicts[f.finding_id];
                const stored = f.retest_status || "";
                const shown = live || stored;
                return (
                  <tr key={f.finding_id} className="border-t border-border/40">
                    <td className="p-2">
                      <Badge variant={severityVariant(f.severity)} className="text-[10px]">
                        {f.severity}
                      </Badge>
                    </td>
                    <td className="p-2 font-mono tabular-nums">
                      {f.cvss?.base_score?.toFixed(1) ?? "—"}
                    </td>
                    <td className="p-2 max-w-md truncate" title={f.title}>{f.title}</td>
                    <td className="p-2 font-mono">{f.affected_asset}</td>
                    <td className="p-2">{f.vuln_class}</td>
                    <td className="p-2">
                      <div className="flex flex-wrap items-center gap-1.5">
                        <Button
                          size="sm"
                          variant="outline"
                          className="h-6 px-2 text-[10px]"
                          disabled={pendingId === f.finding_id || callTool.isPending}
                          onClick={() => retest(f)}
                          aria-label={`Retest ${f.finding_id}`}
                        >
                          {pendingId === f.finding_id ? (
                            <Loader2 className="h-3 w-3 animate-spin" />
                          ) : (
                            "Retest"
                          )}
                        </Button>
                        {shown && (
                          <Badge variant={retestVariant(shown)} className="text-[10px]">
                            {shown}
                          </Badge>
                        )}
                      </div>
                      {errors[f.finding_id] && (
                        <p className="mt-1 text-destructive" role="alert">{errors[f.finding_id]}</p>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </CardContent>
    </Card>
  );
}

function truncate(s: string, n: number): string {
  return s.length <= n ? s : s.slice(0, n - 1) + "…";
}

// ── Attack timeline ─────────────────────────────────────────────────────────

/** Icon keyed off event_type, mirroring enhanced_reporting.py's markdown
 *  timeline (✅/❌/⏳). The JSON's `result` field is derived ("failure" for
 *  any non-success event), so it would paint neutral events red. */
function timelineIcon(eventType: string) {
  const t = eventType.toLowerCase();
  if (t.includes("success")) return <CheckCircle2 className="h-3.5 w-3.5 shrink-0 text-emerald-400" />;
  if (t.includes("fail") || t.includes("error")) return <XCircle className="h-3.5 w-3.5 shrink-0 text-red-400" />;
  return <Clock className="h-3.5 w-3.5 shrink-0 text-muted-foreground" />;
}

/** Vertical-rail timeline. The markdown report sorts ascending client-side;
 *  the JSON artifact does not guarantee order, so sort here too. */
function TimelineCard({ entries }: { entries: AttackTimelineEntry[] }) {
  const rows = useMemo(
    () =>
      [...entries].sort((a, b) =>
        (a.timestamp ?? "").localeCompare(b.timestamp ?? ""),
      ),
    [entries],
  );
  return (
    <Card className="border-border/60">
      <CardHeader className="pb-2">
        <CardTitle className="text-sm">Attack Timeline</CardTitle>
      </CardHeader>
      <CardContent>
        <ol className="relative space-y-2 border-l pl-4">
          {rows.map((e, i) => (
            <li key={i} className="relative flex flex-wrap items-start gap-2 text-xs">
              <span
                aria-hidden
                className="absolute -left-[1.31rem] top-1 h-2 w-2 rounded-full bg-muted-foreground/50"
              />
              <span className="shrink-0 font-mono text-muted-foreground tabular-nums">
                {e.timestamp || "—"}
              </span>
              {timelineIcon(e.event_type ?? "")}
              <span className="shrink-0 font-mono text-muted-foreground">{e.event_type}</span>
              <span className="min-w-0 break-words">{e.description}</span>
              {e.target && <Badge variant="outline" className="font-mono text-[10px]">{e.target}</Badge>}
              {e.module && <Badge variant="outline" className="font-mono text-[10px]">{e.module}</Badge>}
            </li>
          ))}
        </ol>
      </CardContent>
    </Card>
  );
}

// ── Failure analysis ────────────────────────────────────────────────────────

function FailurePanel({ failures }: { failures: FailureAnalysisEntry[] }) {
  const rows = useMemo(
    () => [...failures].sort((a, b) => (b.failure_count ?? 0) - (a.failure_count ?? 0)),
    [failures],
  );
  return (
    <Card className="border-border/60">
      <CardHeader className="pb-2">
        <CardTitle className="flex items-center gap-2 text-sm">
          <Wrench className="h-4 w-4" /> Failure Analysis
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-2">
        {rows.map((f, i) => {
          const breakdown = Object.entries(f.error_breakdown ?? {});
          return (
            <div key={i} className="rounded-md border p-2 text-xs">
              <div className="flex flex-wrap items-center gap-2">
                <span className="font-mono font-medium">{f.operation}</span>
                <Badge variant="danger" className="tabular-nums text-[10px]">
                  {f.failure_count} failure{f.failure_count === 1 ? "" : "s"}
                </Badge>
              </div>
              {f.primary_error && (
                <p className="mt-1 break-words text-muted-foreground">{f.primary_error}</p>
              )}
              {breakdown.length > 0 && (
                <div className="mt-1 flex flex-wrap gap-1">
                  {breakdown.map(([err, count]) => (
                    <Badge key={err} variant="outline" className="max-w-full font-mono text-[10px]" title={err}>
                      <span className="truncate">{truncate(err, 60)}</span>
                      <span className="tabular-nums">×{count}</span>
                    </Badge>
                  ))}
                </div>
              )}
              {f.mitigation_suggestion && (
                <p className="mt-1 break-words">
                  <span className="font-medium">Mitigation: </span>
                  <span className="text-muted-foreground">{f.mitigation_suggestion}</span>
                </p>
              )}
            </div>
          );
        })}
      </CardContent>
    </Card>
  );
}