import { Crosshair, GitMerge } from "lucide-react";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import type { GraphSummaryResponse } from "@/features/graph/graphTypes";

export interface GraphStatsProps {
  summary: GraphSummaryResponse | undefined;
  onFocusNode?: (id: string) => void;
  onOpenConflicts?: () => void;
}

type ChipTone = "default" | "accent" | "emerald" | "danger";

interface StatChip {
  key: string;
  label: string;
  value: number;
  tone?: ChipTone;
  onClick?: () => void;
}

// Compact investigation summary: real counts only (from the backend /summary
// response). The hub chip focuses a node on the graph; the conflict chip opens
// the conflicts panel. Renders nothing before a run is selected.
export function GraphStats({ summary, onFocusNode, onOpenConflicts }: GraphStatsProps) {
  const stats = summary?.stats;
  if (!stats || !summary) return null;

  const chips: StatChip[] = [
    { key: "nodes", label: "Nodes", value: summary.summary.total_nodes },
    { key: "edges", label: "Edges", value: summary.summary.total_edges },
    { key: "findings", label: "Findings", value: stats.findings, tone: "accent" },
    { key: "vulns", label: "Vulns", value: stats.vulnerability_candidates, tone: "danger" },
    { key: "confirmed", label: "Confirmed", value: stats.confirmed, tone: "emerald" },
  ];
  if (stats.conflict_count > 0) {
    chips.push({
      key: "conflicts",
      label: "Conflicts",
      value: stats.conflict_count,
      tone: "danger",
      onClick: onOpenConflicts,
    });
  }

  const hub = stats.highest_degree_node;

  return (
    <div className="flex flex-wrap items-center gap-1.5" role="list" aria-label="Graph statistics">
      {chips.map((c) => (
        <Chip
          key={c.key}
          label={c.label}
          value={c.value}
          tone={c.tone}
          onClick={c.onClick}
          icon={c.key === "conflicts" ? GitMerge : undefined}
        />
      ))}
      {hub && (
        <Button
          variant="outline"
          size="sm"
          className="h-6 gap-1.5 px-2 font-mono text-[11px] tabular-nums"
          onClick={() => onFocusNode?.(hub.node_id)}
          disabled={!onFocusNode}
          title={`Highest-degree node · degree ${hub.degree}`}
          role="listitem"
        >
          <Crosshair className="h-3 w-3 text-primary" aria-hidden />
          <span className="text-muted-foreground">Hub</span>
          <span className="max-w-40 truncate">{hub.value}</span>
          <span className="text-muted-foreground">deg {hub.degree}</span>
        </Button>
      )}
    </div>
  );
}

function Chip({
  label,
  value,
  tone = "default",
  onClick,
  icon,
}: {
  label: string;
  value: number;
  tone?: ChipTone;
  onClick?: () => void;
  icon?: React.ComponentType<{ className?: string }>;
}) {
  const Icon = icon;
  const tones = {
    default: "border-border/70 bg-card/40 text-foreground",
    accent: "border-amber-500/30 bg-amber-500/10 text-amber-700 dark:text-amber-200",
    emerald: "border-emerald-500/30 bg-emerald-500/10 text-emerald-700 dark:text-emerald-200",
    danger: "border-red-500/40 bg-red-500/10 text-red-700 dark:text-red-200",
  } as const;
  const cls = cn(
    "inline-flex items-center gap-1.5 rounded-md border px-2 py-0.5 font-mono text-[11px] tabular-nums",
    tones[tone],
    onClick && "cursor-pointer transition-colors hover:brightness-125",
  );

  if (!onClick) {
    return (
      <span role="listitem" className={cls}>
        {Icon && <Icon className="h-3 w-3" aria-hidden />}
        <span className="text-muted-foreground">{label}</span>
        <span>{value}</span>
      </span>
    );
  }
  return (
    <button
      type="button"
      role="listitem"
      className={cls}
      onClick={onClick}
      aria-label={`${label}: ${value} — click to inspect`}
    >
      {Icon && <Icon className="h-3 w-3" aria-hidden />}
      <span className="text-muted-foreground">{label}</span>
      <span>{value}</span>
    </button>
  );
}
