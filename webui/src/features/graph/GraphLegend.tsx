import { X } from "lucide-react";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import {
  ATTACK_PATH_COLOR,
  NODE_STATUS_ORDER,
  NODE_TYPE_CATEGORIES,
  edgeMeta,
  nodeTypeMeta,
  statusMeta,
} from "@/features/graph/graphTransforms";
import { statusIcon } from "@/features/graph/GraphNodeTypes";
import type { GraphEdgeType } from "@/features/graph/graphTypes";

export interface GraphLegendProps {
  onClose: () => void;
  className?: string;
}

const STATE_ROWS = [
  { key: "selected", label: "Selected node", swatch: <SelectedSwatch /> },
  { key: "path", label: "Attack-path node", swatch: <PathSwatch /> },
  { key: "start", label: "Path start / destination", swatch: <EndpointSwatch /> },
  { key: "focus", label: "Search result (focus)", swatch: <FocusSwatch /> },
];

const LEGEND_EDGES: Array<{ key: string; label: string; edgeType?: GraphEdgeType; path?: boolean }> = [
  { key: "relation", label: "Relationship (e.g. hosts, affects)", edgeType: "hosts" },
  { key: "provenance", label: "Provenance / evidence", edgeType: "supported_by" },
  { key: "conflict", label: "Contradiction (dashed)", edgeType: "contradicted_by" },
  { key: "path-edge", label: "Attack-path edge", path: true },
];

// Legend content is generated from the same node/status/edge metadata maps the
// rest of the UI uses — no duplicated mappings to drift out of sync.
export function GraphLegend({ onClose, className }: GraphLegendProps) {
  return (
    <div
      role="complementary"
      aria-label="Graph legend"
      className={cn(
        "z-20 w-64 overflow-hidden rounded-lg border bg-background/95 shadow-lg backdrop-blur",
        className,
      )}
    >
      <div className="flex items-center justify-between border-b px-3 py-1.5">
        <h3 className="text-[11px] font-semibold uppercase tracking-wide text-muted-foreground">Legend</h3>
        <Button variant="ghost" size="sm" className="h-6 w-6 p-0" onClick={onClose} aria-label="Close legend">
          <X className="h-3.5 w-3.5" />
        </Button>
      </div>

      <div className="max-h-[calc(100dvh-16rem)] overflow-y-auto p-3">
        {/* Node types, grouped by category */}
        <section className="mb-3">
          <h4 className="mb-1 text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">Node types</h4>
          <div className="space-y-1.5">
            {NODE_TYPE_CATEGORIES.map((cat) => (
              <div key={cat.key}>
                <div className="text-[9px] uppercase tracking-wide text-muted-foreground/70">{cat.label}</div>
                <div className="grid grid-cols-2 gap-x-2 gap-y-0.5">
                  {cat.types.map((t) => {
                    const meta = nodeTypeMeta(t);
                    const Icon = meta.icon;
                    return (
                      <span key={t} className="flex items-center gap-1.5 text-[10px] leading-tight">
                        <Icon className="h-3 w-3 shrink-0" style={{ color: meta.color }} aria-hidden />
                        <span className="truncate">{meta.label}</span>
                      </span>
                    );
                  })}
                </div>
              </div>
            ))}
          </div>
        </section>

        {/* Statuses */}
        <section className="mb-3">
          <h4 className="mb-1 text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">Status</h4>
          <div className="grid grid-cols-2 gap-x-2 gap-y-0.5">
            {NODE_STATUS_ORDER.map((s) => {
              const StatusIcon = statusIcon(s);
              return (
                <span key={s} className="flex items-center gap-1.5 text-[10px]">
                  <StatusIcon className="h-3 w-3 shrink-0" style={{ color: statusMeta(s).color }} aria-hidden />
                  <span className="truncate">{statusMeta(s).label}</span>
                </span>
              );
            })}
          </div>
        </section>

        {/* UI states */}
        <section className="mb-3">
          <h4 className="mb-1 text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">States</h4>
          <div className="space-y-0.5">
            {STATE_ROWS.map((r) => (
              <span key={r.key} className="flex items-center gap-1.5 text-[10px]">
                {r.swatch}
                <span>{r.label}</span>
              </span>
            ))}
          </div>
        </section>

        {/* Edges */}
        <section>
          <h4 className="mb-1 text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">Edges</h4>
          <div className="space-y-0.5">
            {LEGEND_EDGES.map((e) => {
              const meta = e.edgeType ? edgeMeta(e.edgeType) : null;
              const stroke = e.path ? ATTACK_PATH_COLOR : (meta?.color ?? "rgb(148,163,184)");
              return (
                <span key={e.key} className="flex items-center gap-1.5 text-[10px]">
                  <svg width="22" height="6" viewBox="0 0 22 6" className="shrink-0" aria-hidden>
                    <line
                      x1="0"
                      y1="3"
                      x2="18"
                      y2="3"
                      stroke={stroke}
                      strokeWidth={e.path ? 2 : 1.25}
                      strokeDasharray={e.path || e.edgeType === "contradicted_by" ? "4 2" : undefined}
                    />
                    <polygon points="18,0 22,3 18,6" fill={stroke} />
                  </svg>
                  <span className="truncate">{e.label}</span>
                </span>
              );
            })}
          </div>
        </section>
      </div>
    </div>
  );
}

function SelectedSwatch() {
  return <span className="h-3 w-3 shrink-0 rounded border-2 border-foreground" aria-hidden />;
}
function PathSwatch() {
  return <span className="h-3 w-3 shrink-0 rounded border border-dashed border-emerald-400" aria-hidden />;
}
function EndpointSwatch() {
  return (
    <span className="flex h-3 w-6 shrink-0 items-center gap-0.5" aria-hidden>
      <span className="flex-1 rounded bg-emerald-500/25 text-center text-[6px] font-bold leading-3 text-emerald-300">S</span>
      <span className="flex-1 rounded bg-rose-500/25 text-center text-[6px] font-bold leading-3 text-rose-300">D</span>
    </span>
  );
}
function FocusSwatch() {
  return <span className="h-2 w-2 shrink-0 animate-pulse rounded-full bg-amber-400 motion-reduce:animate-none" aria-hidden />;
}
