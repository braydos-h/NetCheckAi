import { Link, useParams } from "react-router-dom";
import { ChevronLeft } from "lucide-react";
import { Button } from "@/components/ui/button";
import { AttackGraphDag } from "@/components/AttackGraphDag";
import { AttackGraph } from "@/components/AttackGraph";
import { useArtifacts, useRunGraph } from "@/api/hooks";
import { ApiError } from "@/api/client";
import { truncateId } from "@/lib/utils";

const DAG_HEIGHT = Math.min(640, Math.max(320, (typeof window !== "undefined" ? window.innerHeight : 640) - 220));

export function GraphPage() {
  const { runId } = useParams<{ runId: string }>();
  const artifacts = useArtifacts(runId ?? null);
  const artifactNames = artifacts.data?.artifacts.map((a) => a.name) ?? [];
  const enhancedReady = artifactNames.includes("enhanced/enhanced_report.json");
  // Same cached query the DAG reads — no extra fetch. Live DAG first; the
  // static report is the fallback, not a second copy below it.
  const graphQuery = useRunGraph(runId ?? null);
  const dagHasNodes = (graphQuery.data?.nodes.length ?? 0) > 0;
  const dagUnavailable =
    !!graphQuery.error || (!graphQuery.isLoading && !dagHasNodes);

  return (
    <div className="space-y-4 p-4 md:p-6">
      <div className="flex items-center gap-2">
        <Button asChild size="sm" variant="ghost">
          <Link to={`/runs/${runId}`}><ChevronLeft className="h-4 w-4" />Back to run</Link>
        </Button>
        <h1 className="text-sm font-mono text-muted-foreground" title={runId}>{truncateId(runId ?? "")}</h1>
        <span className="text-sm font-medium">Attack Path</span>
      </div>

      {artifacts.error && (
        <div className="flex items-center gap-2 text-sm text-destructive">
          <span>Failed to load artifacts.</span>
          <Button size="sm" variant="outline" onClick={() => artifacts.refetch()}>Retry</Button>
        </div>
      )}

      {!dagUnavailable && <AttackGraphDag runId={runId ?? ""} height={DAG_HEIGHT} />}
      {dagUnavailable && (
        <>
          {graphQuery.error && !(graphQuery.error instanceof ApiError && graphQuery.error.isNotFound) && (
            <div className="flex items-center gap-2 text-sm text-destructive">
              <span>Failed to load the live graph.</span>
              <Button size="sm" variant="outline" onClick={() => graphQuery.refetch()}>Retry</Button>
            </div>
          )}
          <AttackGraph runId={runId ?? ""} ready={enhancedReady} />
        </>
      )}
    </div>
  );
}