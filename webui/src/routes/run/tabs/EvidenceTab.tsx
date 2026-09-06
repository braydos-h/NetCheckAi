import { useMemo, useState } from "react";
import { Check, FileCheck, X } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { SkeletonRows } from "@/components/Loading";
import { ApiError } from "@/api/client";
import { useDecideFinding, useProposed } from "@/api/hooks";
import type { ProposedFinding } from "@/api/types";

interface EvidenceTabProps {
  runId: string;
}

function sevVariant(sev: string): "danger" | "warn" | "info" | "muted" {
  switch (sev.toLowerCase()) {
    case "critical":
    case "high":
      return "danger";
    case "medium":
      return "warn";
    case "low":
      return "info";
    default:
      return "muted";
  }
}

function ProofCapsule({ finding }: { finding: ProposedFinding }) {
  const proof = finding.proof;
  return (
    <div className="space-y-2 rounded-md border bg-muted/20 p-2 text-xs">
      <div>
        <div className="mb-1 font-medium text-muted-foreground">Probe exec</div>
        <code className="block break-all rounded bg-background p-1.5">{proof.probe_exec || "—"}</code>
      </div>
      <div className="flex flex-wrap gap-1.5">
        <Badge variant="info">verify: {proof.verify_status || "HOLDING"}</Badge>
        {proof.retest_status && <Badge variant="secondary">retest: {proof.retest_status}</Badge>}
        {proof.proof_runs > 0 && <Badge variant="muted">proof runs: {proof.proof_runs}</Badge>}
        {proof.proof_sha256 && (
          <Badge variant="muted" title={proof.proof_sha256}>
            sha {proof.proof_sha256.slice(0, 12)}…
          </Badge>
        )}
      </div>
      {(proof.verify_detail || proof.retest_detail) && (
        <div className="text-muted-foreground">
          {[proof.verify_detail, proof.retest_detail].filter(Boolean).join(" · ")}
        </div>
      )}
      {proof.output_excerpt && (
        <pre className="max-h-40 overflow-auto whitespace-pre-wrap break-all rounded bg-background p-1.5 text-[11px]">
          {proof.output_excerpt}
        </pre>
      )}
    </div>
  );
}

function ProposalRow({
  finding,
  runId,
}: {
  finding: ProposedFinding;
  runId: string;
}) {
  const [expanded, setExpanded] = useState(false);
  const [note, setNote] = useState("");
  const decide = useDecideFinding(runId);

  const submit = (decision: "APPROVED" | "REJECTED") => {
    decide.mutate(
      { findingId: finding.finding_id, decision, note },
      { onSuccess: () => setExpanded(false) },
    );
  };

  return (
    <div className="rounded-md border p-2">
      <button
        type="button"
        onClick={() => setExpanded((v) => !v)}
        className="flex w-full flex-wrap items-center gap-2 text-left"
        aria-expanded={expanded}
      >
        <Badge variant="warn">PROPOSED</Badge>
        <Badge variant={sevVariant(finding.severity)}>{finding.severity || "Medium"}</Badge>
        <span className="min-w-0 flex-1 truncate text-sm font-medium">{finding.title}</span>
        <span className="text-xs text-muted-foreground">{finding.affected_asset}</span>
      </button>
      {expanded && (
        <div className="mt-2 space-y-2">
          {finding.summary && <p className="text-xs text-muted-foreground">{finding.summary}</p>}
          <ProofCapsule finding={finding} />
          <Input
            value={note}
            onChange={(e) => setNote(e.target.value)}
            placeholder="Reviewer note (optional)"
            className="h-7 text-xs"
            aria-label="Reviewer note"
          />
          {decide.error && (
            <div className="text-xs text-destructive">
              {decide.error instanceof ApiError ? decide.error.message : "Decision failed."}
            </div>
          )}
          <div className="flex gap-2">
            <Button size="sm" onClick={() => submit("APPROVED")} disabled={decide.isPending}>
              <Check className="mr-1 h-3 w-3" />
              {decide.isPending ? "Saving…" : "Approve"}
            </Button>
            <Button size="sm" variant="destructive" onClick={() => submit("REJECTED")} disabled={decide.isPending}>
              <X className="mr-1 h-3 w-3" />
              Reject
            </Button>
          </div>
        </div>
      )}
    </div>
  );
}

export function EvidenceTab({ runId }: EvidenceTabProps) {
  const [filter, setFilter] = useState("");
  const proposed = useProposed(runId, true);

  const rows = useMemo(() => {
    const q = filter.trim().toLowerCase();
    const all = proposed.data?.proposed ?? [];
    if (!q) return all;
    return all.filter(
      (f) =>
        f.title.toLowerCase().includes(q) || f.affected_asset.toLowerCase().includes(q),
    );
  }, [proposed.data, filter]);

  if (proposed.isLoading) return <SkeletonRows count={3} />;
  if (proposed.error) {
    return <div className="text-sm text-destructive">Failed to load proposals.</div>;
  }
  const total = proposed.data?.proposed.length ?? 0;

  return (
    <div className="space-y-2">
      <div className="flex flex-wrap items-center gap-2">
        <Badge variant="info">
          <FileCheck className="mr-1 h-3 w-3" />
          {total} awaiting review
        </Badge>
        <span className="text-xs text-muted-foreground">Agents propose — only a human Approve/Reject lands a finding.</span>
        <div className="ml-auto w-full sm:w-56">
          <Input
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            placeholder="Filter by title or asset…"
            className="h-7 text-xs"
            aria-label="Filter proposals"
          />
        </div>
      </div>
      {rows.length === 0 ? (
        <p className="text-sm text-muted-foreground">
          {total === 0
            ? "No proposals awaiting review — the agent has not proposed any candidate findings for this run."
            : "No proposals match this filter."}
        </p>
      ) : (
        rows.map((f) => <ProposalRow key={f.finding_id} finding={f} runId={runId} />)
      )}
    </div>
  );
}
