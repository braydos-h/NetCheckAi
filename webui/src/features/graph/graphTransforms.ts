// Pure transforms between the explorer API DTOs and reactflow / UI shapes.
// Nothing here mutates graph facts — it only maps them for display.

import type { Edge, Node } from "reactflow";
import { MarkerType, Position } from "reactflow";
import type { LucideIcon } from "lucide-react";
import {
  AlertTriangle,
  AppWindow,
  BadgeCheck,
  Box,
  Boxes,
  Bug,
  Cpu,
  Eye,
  FileText,
  Globe,
  Hash,
  HelpCircle,
  KeyRound,
  Layers,
  Link2,
  Network,
  Plug,
  Server,
  Shield,
  ShieldCheck,
  User,
  Zap,
} from "lucide-react";
import type {
  GraphExplorerEdge,
  GraphExplorerNode,
  GraphNodeStatus,
  GraphNodeType,
  GraphSummaryStats,
  GraphEdgeType,
} from "@/features/graph/graphTypes";

// ── node/status presentation metadata ───────────────────────────────────────

export type NodeTypeCategory = "infrastructure" | "application" | "identity" | "intelligence" | "defense";

export interface NodeTypeMeta {
  label: string;
  color: string;
  bg: string;
  icon: LucideIcon;
  category: NodeTypeCategory;
}

const NODE_TYPE_META: Partial<Record<GraphNodeType, NodeTypeMeta>> = {
  ip: { label: "IP", color: "rgb(96,165,250)", bg: "rgba(59,130,246,0.14)", icon: Network, category: "infrastructure" },
  host: { label: "Host", color: "rgb(94,234,212)", bg: "rgba(45,212,191,0.14)", icon: Server, category: "infrastructure" },
  domain: { label: "Domain", color: "rgb(94,234,212)", bg: "rgba(45,212,191,0.14)", icon: Globe, category: "infrastructure" },
  service: { label: "Service", color: "rgb(74,222,128)", bg: "rgba(34,197,94,0.14)", icon: Layers, category: "infrastructure" },
  port: { label: "Port", color: "rgb(74,222,128)", bg: "rgba(34,197,94,0.14)", icon: Plug, category: "infrastructure" },
  endpoint: { label: "Endpoint", color: "rgb(74,222,128)", bg: "rgba(34,197,94,0.14)", icon: Link2, category: "application" },
  application: { label: "App", color: "rgb(125,211,252)", bg: "rgba(56,189,248,0.14)", icon: AppWindow, category: "application" },
  technology: { label: "Technology", color: "rgb(125,211,252)", bg: "rgba(56,189,248,0.14)", icon: Cpu, category: "application" },
  version: { label: "Version", color: "rgb(125,211,252)", bg: "rgba(56,189,248,0.14)", icon: Hash, category: "application" },
  identity: { label: "Identity", color: "rgb(167,139,250)", bg: "rgba(139,92,246,0.14)", icon: User, category: "identity" },
  role: { label: "Role", color: "rgb(167,139,250)", bg: "rgba(139,92,246,0.14)", icon: BadgeCheck, category: "identity" },
  credential_reference: {
    label: "Credential ref",
    color: "rgb(167,139,250)",
    bg: "rgba(139,92,246,0.14)",
    icon: KeyRound,
    category: "identity",
  },
  trust_boundary: { label: "Trust boundary", color: "rgb(103,232,249)", bg: "rgba(34,211,238,0.14)", icon: Shield, category: "identity" },
  network_segment: { label: "Network", color: "rgb(103,232,249)", bg: "rgba(34,211,238,0.14)", icon: Boxes, category: "infrastructure" },
  vulnerability_candidate: {
    label: "Vuln candidate",
    color: "rgb(251,146,60)",
    bg: "rgba(249,115,22,0.14)",
    icon: Bug,
    category: "intelligence",
  },
  finding: { label: "Finding", color: "rgb(248,113,113)", bg: "rgba(239,68,68,0.14)", icon: AlertTriangle, category: "intelligence" },
  hypothesis: { label: "Hypothesis", color: "rgb(192,132,252)", bg: "rgba(168,85,247,0.14)", icon: HelpCircle, category: "intelligence" },
  evidence: { label: "Evidence", color: "rgb(251,191,36)", bg: "rgba(245,158,11,0.14)", icon: FileText, category: "intelligence" },
  observation: { label: "Obs", color: "rgb(148,163,184)", bg: "rgba(100,116,139,0.14)", icon: Eye, category: "intelligence" },
  capability: { label: "Capability", color: "rgb(52,211,153)", bg: "rgba(16,185,129,0.14)", icon: Zap, category: "defense" },
  security_control: {
    label: "Security control",
    color: "rgb(52,211,153)",
    bg: "rgba(16,185,129,0.14)",
    icon: ShieldCheck,
    category: "defense",
  },
  asset: { label: "Asset", color: "rgb(148,163,184)", bg: "rgba(100,116,139,0.14)", icon: Box, category: "defense" },
};

const FALLBACK_NODE_META: NodeTypeMeta = {
  label: "Node",
  color: "rgb(148,163,184)",
  bg: "rgba(100,116,139,0.14)",
  icon: Box,
  category: "intelligence",
};

export function nodeTypeMeta(nodeType: GraphNodeType): NodeTypeMeta {
  return NODE_TYPE_META[nodeType] ?? FALLBACK_NODE_META;
}

export const NODE_TYPE_CATEGORIES: Array<{ key: NodeTypeCategory; label: string; types: GraphNodeType[] }> = [
  { key: "infrastructure", label: "Infrastructure", types: ["domain", "host", "ip", "network_segment", "service", "port"] },
  { key: "application", label: "Application", types: ["application", "technology", "version", "endpoint"] },
  { key: "identity", label: "Identity & access", types: ["identity", "role", "credential_reference", "trust_boundary"] },
  { key: "intelligence", label: "Findings & evidence", types: ["vulnerability_candidate", "finding", "hypothesis", "evidence", "observation"] },
  { key: "defense", label: "Controls & assets", types: ["capability", "security_control", "asset"] },
];

export const ATTACK_PATH_COLOR = "rgb(34,211,238)";

const STATUS_META: Record<GraphNodeStatus, { label: string; color: string }> = {
  confirmed: { label: "Confirmed", color: "rgb(52,211,153)" },
  likely: { label: "Likely", color: "rgb(96,165,250)" },
  suspected: { label: "Suspected", color: "rgb(251,191,36)" },
  unknown: { label: "Unknown", color: "rgb(148,163,184)" },
  refuted: { label: "Refuted", color: "rgb(248,113,113)" },
  // Slate-blue, not amber — the old yellow-600 sat next to suspected amber
  // below any usable separation floor.
  exhausted: { label: "Exhausted", color: "rgb(129,140,248)" },
};

export function statusMeta(status: GraphNodeStatus): { label: string; color: string } {
  return STATUS_META[status] ?? STATUS_META.unknown;
}

export const NODE_TYPE_ORDER: GraphNodeType[] = [
  "domain", "host", "ip", "service", "port", "endpoint",
  "application", "technology", "version", "identity", "role",
  "vulnerability_candidate", "finding", "hypothesis", "evidence",
  "observation", "capability", "security_control", "asset",
];

export const NODE_STATUS_ORDER: GraphNodeStatus[] = [
  "confirmed", "likely", "suspected", "unknown", "refuted", "exhausted",
];

// ── severity metadata (presentation of a real backend property) ─────────────

export interface SeverityMeta {
  label: string;
  color: string;
  order: number;
}

const SEVERITY_META: Record<string, SeverityMeta> = {
  critical: { label: "Critical", color: "rgb(248,113,113)", order: 0 },
  high: { label: "High", color: "rgb(251,146,60)", order: 1 },
  medium: { label: "Medium", color: "rgb(251,191,36)", order: 2 },
  low: { label: "Low", color: "rgb(74,222,128)", order: 3 },
  info: { label: "Info", color: "rgb(96,165,250)", order: 4 },
};

export function severityMeta(severity: string): SeverityMeta {
  return SEVERITY_META[severity.trim().toLowerCase()] ?? { label: severity, color: "rgb(148,163,184)", order: 99 };
}

// ── edge-type presentation metadata ─────────────────────────────────────────

export interface EdgeTypeMeta {
  label: string;
  color: string;
  dashed?: boolean;
}

const EDGE_TYPE_META: Partial<Record<GraphEdgeType, EdgeTypeMeta>> = {
  resolves_to: { label: "resolves to", color: "rgb(96,165,250)" },
  hosts: { label: "hosts", color: "rgb(45,212,191)" },
  exposes: { label: "exposes", color: "rgb(251,146,60)" },
  runs: { label: "runs", color: "rgb(45,212,191)" },
  depends_on: { label: "depends on", color: "rgb(125,211,252)" },
  reachable_from: { label: "reachable from", color: "rgb(96,165,250)" },
  authenticates_to: { label: "authenticates to", color: "rgb(45,212,191)" },
  has_role: { label: "has role", color: "rgb(167,139,250)" },
  trusts: { label: "trusts", color: "rgb(103,232,249)" },
  related_to: { label: "related to", color: "rgb(148,163,184)" },
  supported_by: { label: "supported by", color: "rgb(52,211,153)" },
  contradicted_by: { label: "contradicted by", color: "rgb(248,113,113)", dashed: true },
  derived_from: { label: "derived from", color: "rgb(167,139,250)" },
  affected_by: { label: "affected by", color: "rgb(251,191,36)" },
  protected_by: { label: "protected by", color: "rgb(52,211,153)" },
  connected_to: { label: "connected to", color: "rgb(148,163,184)" },
  same_as: { label: "same as", color: "rgb(148,163,184)" },
  observed_on: { label: "observed on", color: "rgb(125,211,252)" },
};

export function edgeMeta(edgeType: GraphEdgeType): EdgeTypeMeta {
  return EDGE_TYPE_META[edgeType] ?? { label: edgeType, color: "rgb(148,163,184)" };
}

// ── reactflow mapping ───────────────────────────────────────────────────────

interface FlowNodeData {
  label: string;
  node: GraphExplorerNode;
}

// ponytail: virtualization caps — the canvas only renders this many.
export const MAX_FLOW_NODES = 400;
export const MAX_FLOW_EDGES = 800;

export function toFlowNodes(nodes: GraphExplorerNode[]): Node<FlowNodeData>[] {
  // Deterministic wrapped grid (6 per row, not one column per type — the old
  // col*250 sprawled to ~5k px wide). Capped so reactflow never mounts
  // thousands of DOM nodes.
  const COLS = 6;
  const X_GAP = 220;
  const Y_GAP = 88;
  const counts: Record<string, number> = {};
  const colOf: Record<string, number> = {};
  for (let i = 0; i < NODE_TYPE_ORDER.length; i += 1) {
    const t = NODE_TYPE_ORDER[i];
    if (t !== undefined) colOf[t] = i;
  }
  return nodes.slice(0, MAX_FLOW_NODES).map((n) => {
    const col = colOf[n.node_type] ?? NODE_TYPE_ORDER.length;
    const count = counts[n.node_type] ?? 0;
    counts[n.node_type] = count + 1;
    return {
      id: n.node_id,
      data: { label: n.value, node: n },
      position: { x: (col % COLS) * X_GAP, y: Math.floor(col / COLS) * 720 + (count % 24) * Y_GAP },
      style: { minWidth: 150, maxWidth: 240 },
      sourcePosition: Position.Right,
      targetPosition: Position.Left,
    };
  });
}

interface FlowEdgeData {
  edgeType: GraphEdgeType;
}

export function toFlowEdges(edges: GraphExplorerEdge[]): Edge<FlowEdgeData>[] {
  return edges.slice(0, MAX_FLOW_EDGES).map((e) => {
    const meta = edgeMeta(e.edge_type);
    return {
      id: e.edge_id,
      source: e.source_node_id,
      target: e.target_node_id,
      label: e.edge_type,
      type: "smoothstep",
      data: { edgeType: e.edge_type } as FlowEdgeData,
      style: {
        stroke: meta.color,
        strokeWidth: 1.25,
        ...(meta.dashed ? { strokeDasharray: "5 4" } : {}),
      },
      markerEnd: { type: MarkerType.ArrowClosed, width: 14, height: 14, color: meta.color },
      labelStyle: { fontSize: 9, fill: "hsl(var(--popover-foreground))" },
      labelBgStyle: { fill: "hsl(var(--popover))", fillOpacity: 1 },
      labelBgPadding: [3, 2] as [number, number],
      labelBgBorderRadius: 3,
    };
  });
}

// ── search + evidence helpers ───────────────────────────────────────────────

/** Case-insensitive substring search across the fields operators search for. */
export function nodeMatchesQuery(node: GraphExplorerNode, q: string): boolean {
  const needle = q.trim().toLowerCase();
  if (!needle) return true;
  const props = node.properties;
  const haystack = [
    node.value,
    node.node_type,
    node.status,
    node.source,
    node.node_id,
    ...node.evidence_refs,
    typeof props.cvss_score === "number" ? String(props.cvss_score) : "",
    typeof props.severity === "string" ? (props.severity as string) : "",
    typeof props.vuln_class === "string" ? (props.vuln_class as string) : "",
    ...(Array.isArray(props.tags) ? (props.tags as unknown[]).map(String) : []),
  ]
    .join("\n")
    .toLowerCase();
  return haystack.includes(needle);
}

/** Search relevance ranking for the local find-node results list. */
export function rankNodeMatches(nodes: GraphExplorerNode[], q: string): GraphExplorerNode[] {
  const needle = q.trim().toLowerCase();
  if (!needle) return [];
  const valueLower = (v: string) => v.toLowerCase();
  const scored = nodes
    .filter((n) => nodeMatchesQuery(n, q))
    .map((n) => {
      const v = valueLower(n.value);
      let score = 100;
      if (v === needle) score -= 20; // exact value wins
      else if (v.startsWith(needle)) score -= 10;
      return { n, score };
    });
  return scored
    .sort((a, b) => a.score - b.score || a.n.value.localeCompare(b.n.value))
    .map((s) => s.n);
}

/** Parse an evidence ref `ev:<tool>:<target>:<hash12>:<timestamp>` (lenient). */
export interface ParsedEvidenceRef {
  raw: string;
  tool: string;
  target: string;
  hash: string;
  timestamp: string;
}

export function parseEvidenceRef(ref: string): ParsedEvidenceRef {
  const parts = ref.split(":");
  return {
    raw: ref,
    tool: parts[0] === "ev" ? (parts[1] ?? "") : "",
    target: parts[0] === "ev" ? (parts[2] ?? "") : "",
    hash: parts[0] === "ev" ? (parts[3] ?? "") : "",
    timestamp: parts[0] === "ev" ? (parts[4] ?? "") : "",
  };
}

/** Rich summary chips for the stats bar. */
export function summaryChips(stats: GraphSummaryStats | undefined): Array<{ label: string; value: number; key: string }> {
  if (!stats) return [];
  return [
    { label: "Nodes", value: stats.hosts + stats.domains + stats.ips + stats.services + stats.findings + stats.hypotheses + stats.evidence + stats.observations + stats.vulnerability_candidates, key: "nodes" },
    { label: "Hosts", value: stats.hosts, key: "hosts" },
    { label: "Services", value: stats.services, key: "services" },
    { label: "Findings", value: stats.findings, key: "findings" },
    { label: "Confirmed", value: stats.confirmed, key: "confirmed" },
    { label: "Hypotheses", value: stats.hypotheses, key: "hypotheses" },
  ];
}
