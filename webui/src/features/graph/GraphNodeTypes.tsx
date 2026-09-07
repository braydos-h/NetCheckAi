import { memo } from "react";
import type { NodeProps } from "reactflow";
import { BadgeCheck, Ban, CircleHelp, Eye, GitBranch, SearchCheck } from "lucide-react";
import { cn } from "@/lib/utils";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import type { GraphExplorerNode, GraphNodeStatus } from "@/features/graph/graphTypes";
import { nodeTypeMeta, severityMeta, statusMeta } from "@/features/graph/graphTransforms";

// Status icons shared with GraphLegend — status is never color-alone.
export function statusIcon(status: GraphNodeStatus) {
  switch (status) {
    case "confirmed":
      return BadgeCheck;
    case "likely":
      return SearchCheck;
    case "suspected":
      return Eye;
    case "refuted":
      return Ban;
    case "exhausted":
      return GitBranch;
    case "unknown":
    default:
      return CircleHelp;
  }
}

export interface GraphFlowNodeData {
  label: string;
  node: GraphExplorerNode;
  /** part of the active attack-path overlay */
  path?: boolean;
  /** search-result focus highlight (transient) */
  focus?: boolean;
  /** path start endpoint */
  start?: boolean;
  /** path destination endpoint */
  end?: boolean;
  /** de-emphasized by path/selection context */
  dimmed?: boolean;
  /** selected node id from the page (source of truth) */
  selected?: boolean;
}

// Custom node for the explorer canvas. Selected state is shown with BOTH a
// color ring AND a solid outline + dot (non-color-only). Path-emphasis nodes
// get a dashed outer ring; path endpoints get labelled START/DEST chips; the
// focus (search-result) node pulses its icon dot. Nodes are focusable
// [data-id] elements so keyboard users can select them with Enter/Space.
export const GraphFlowNode = memo(function GraphFlowNode({ data, selected }: NodeProps<GraphFlowNodeData>) {
  const meta = nodeTypeMeta(data.node.node_type);
  const status = statusMeta(data.node.status);
  const props = data.node.properties;
  const cvss = typeof props.cvss_score === "number" ? props.cvss_score : null;
  const severity = typeof props.severity === "string" && props.severity ? (props.severity as string) : null;
  const sevMeta = severity ? severityMeta(severity) : null;
  const Icon = meta.icon;
  const StatusIcon = statusIcon(data.node.status);
  const isSelected = selected || data.selected;
  const detailLabel = [
    `${meta.label}: ${data.node.value}`,
    data.node.status !== "unknown" ? `Status ${status.label}` : null,
    severity ? `Severity ${severity}` : null,
    cvss !== null ? `CVSS ${cvss.toFixed(1)}` : null,
    `${data.node.evidence_refs.length} evidence refs`,
  ]
    .filter(Boolean)
    .join(" · ");

  return (
    <Tooltip>
      <TooltipTrigger asChild>
    <div
      data-id={data.node.node_id}
      role="button"
      tabIndex={0}
      aria-label={`${meta.label} node: ${data.node.value}${data.node.status !== "unknown" ? ` (${status.label})` : ""}`}
      title={data.node.value}
      className={cn(
        "relative flex min-w-[150px] max-w-[240px] cursor-pointer flex-col gap-1 rounded-md px-2 py-1.5 font-mono text-[11px] leading-tight transition-opacity focus-visible:outline-2 focus-visible:outline-ring",
        data.dimmed && "opacity-40",
        isSelected && "ring-2 ring-foreground shadow-lg",
      )}
      style={{
        background: meta.bg,
        border: `1.5px solid ${meta.color}`,
        outline: data.path && !isSelected ? "1.5px dashed rgb(52,211,153)" : undefined,
      }}
    >
      <div className="flex items-center gap-1.5">
        {data.focus ? (
          <span
            className="h-2 w-2 shrink-0 animate-pulse rounded-full bg-amber-400 motion-reduce:animate-none"
            aria-hidden
          />
        ) : (
          <Icon className="h-3 w-3 shrink-0" style={{ color: meta.color }} aria-hidden />
        )}
        <span className="truncate font-medium">{data.label}</span>
        {isSelected && (
          <span className="ml-auto h-1.5 w-1.5 shrink-0 rounded-full bg-foreground" aria-label="Selected node" />
        )}
      </div>
      <div className="flex flex-wrap items-center gap-1">
        <span className="rounded bg-black/20 px-1 text-[9px] uppercase tracking-wide text-muted-foreground dark:bg-white/10">
          <span className="mr-0.5 inline-block h-1.5 w-1.5 rounded-full align-middle" style={{ background: meta.color }} aria-hidden />
          {meta.label}
        </span>
        {data.start && (
          <span className="rounded bg-emerald-500/15 px-1 text-[9px] font-semibold uppercase tracking-wide text-emerald-700 dark:text-emerald-300">
            start
          </span>
        )}
        {data.end && (
          <span className="rounded bg-rose-500/15 px-1 text-[9px] font-semibold uppercase tracking-wide text-rose-700 dark:text-rose-300">
            dest
          </span>
        )}
        {status.label !== "Unknown" && (
          <span className="rounded bg-black/20 px-1 text-[9px] uppercase tracking-wide text-muted-foreground dark:bg-white/10">
            <StatusIcon className="mr-0.5 inline h-2.5 w-2.5 align-middle" style={{ color: status.color }} aria-hidden />
            {status.label}
          </span>
        )}
        {cvss !== null && (
          <span className="rounded bg-black/20 px-1 text-[9px] tabular-nums text-muted-foreground dark:bg-white/10">CVSS {cvss.toFixed(1)}</span>
        )}
        {severity && sevMeta && (
          <span className="rounded bg-black/20 px-1 text-[9px] uppercase text-muted-foreground dark:bg-white/10">
            <span className="mr-0.5 inline-block h-1.5 w-1.5 rounded-full align-middle" style={{ background: sevMeta.color }} aria-hidden />
            {severity}
          </span>
        )}
      </div>
    </div>
      </TooltipTrigger>
      <TooltipContent side="top" className="max-w-[16rem]">
        {detailLabel}
      </TooltipContent>
    </Tooltip>
  );
});
