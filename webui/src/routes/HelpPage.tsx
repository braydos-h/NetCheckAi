import { useEffect, useMemo, useRef, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import {
  Activity,
  AlertTriangle,
  ArrowRight,
  BarChart3,
  BookOpen,
  Brain,
  CheckCircle2,
  ChevronDown,
  Compass,
  Crosshair,
  ExternalLink,
  FileText,
  Files,
  FlaskConical,
  FolderSearch,
  GitBranch,
  HelpCircle,
  KeyRound,
  List,
  Network,
  PlugZap,
  Rocket,
  ScanSearch,
  ScrollText,
  Search,
  SearchX,
  Settings,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Target,
  Wrench,
  X,
  Zap,
  ClipboardList,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Separator } from "@/components/ui/separator";
import {
  DIRECTORY_ITEMS,
  DOC_CATEGORIES,
  DOC_LINKS,
  FAQ,
  HELP_TOPICS,
  LIFECYCLE_STAGES,
  PERMISSION_ROWS,
  QUICK_START_CARDS,
  SECTION_META,
  TROUBLESHOOTING,
  WORKFLOWS,
  type DocLink,
  type HelpTopic,
} from "@/features/help/helpContent";

// ── icon maps ────────────────────────────────────────────────────────────────
const QUICK_ICON: Record<string, typeof Rocket> = {
  Rocket,
  Activity,
  FolderSearch,
  Settings,
};

const DIR_ICON: Record<string, typeof List> = {
  List,
  Target,
  Crosshair,
  Sparkles,
  Brain,
  BarChart3,
  GitBranch,
  PlugZap,
  FlaskConical,
  Settings,
  Files,
  KeyRound,
  ScrollText,
};

const LIFECYCLE_ICON: Record<string, typeof Target> = {
  target: Target,
  recon: ScanSearch,
  decision: Compass,
  attack: Zap,
  evidence: Files,
  report: ClipboardList,
};

const WORKFLOW_ICON: Record<string, typeof ScanSearch> = {
  ScanSearch,
  ShieldCheck,
  ClipboardList,
  Wrench,
};

// ── helpers ─────────────────────────────────────────────────────────────────
function scrollToAnchor(anchor: string) {
  const id = anchor.replace(/^#/, "");
  const el = document.getElementById(id);
  if (el) el.scrollIntoView({ behavior: "smooth", block: "start" });
}

function isTypingTarget(el: Element | null) {
  if (!el) return false;
  const tag = el.tagName;
  return tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT" || (el as HTMLElement).isContentEditable;
}

// ── HelpPage ─────────────────────────────────────────────────────────────────
export function HelpPage() {
  const [query, setQuery] = useState("");
  const [showResults, setShowResults] = useState(false);
  const navigate = useNavigate();
  const inputRef = useRef<HTMLInputElement>(null);
  const searchWrapRef = useRef<HTMLDivElement>(null);
  const [expandedTrouble, setExpandedTrouble] = useState<Set<string>>(new Set());
  const [expandedFaq, setExpandedFaq] = useState<Set<string>>(new Set());

  const normalized = query.trim().toLowerCase();
  const results: HelpTopic[] = useMemo(() => {
    if (!normalized) return [];
    return HELP_TOPICS.filter((t) => {
      const hay = [t.title, t.description, ...t.keywords].join(" ").toLowerCase();
      return hay.includes(normalized);
    }).slice(0, 10);
  }, [normalized]);

  // "/" to focus search, Escape to clear/unfocus
  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if (e.key === "/" && !isTypingTarget(document.activeElement) && !e.metaKey && !e.ctrlKey && !e.altKey) {
        e.preventDefault();
        inputRef.current?.focus();
        setShowResults(true);
      }
      if (e.key === "Escape" && document.activeElement === inputRef.current) {
        if (query) {
          setQuery("");
          setShowResults(false);
        } else {
          (document.activeElement as HTMLElement)?.blur();
          setShowResults(false);
        }
      }
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [query]);

  // close dropdown on outside click
  useEffect(() => {
    function onDown(e: MouseEvent) {
      if (!searchWrapRef.current?.contains(e.target as Node)) setShowResults(false);
    }
    document.addEventListener("mousedown", onDown);
    return () => document.removeEventListener("mousedown", onDown);
  }, []);

  const hasQuery = normalized.length > 0;

  return (
    <div className="mx-auto w-full max-w-[1100px] space-y-6 p-4 md:p-6">
      {/* ── header ──────────────────────────────────────────────────────── */}
      <header className="space-y-4">
        <div className="flex flex-wrap items-start gap-3">
          <div className="flex items-center gap-2.5">
            <div className="flex h-9 w-9 items-center justify-center rounded-lg border bg-card">
              <BookOpen className="h-5 w-5 text-primary" />
            </div>
            <div>
              <h1 className="text-lg font-semibold leading-tight">Help &amp; Reference</h1>
              <p className="max-w-xl text-sm leading-relaxed text-muted-foreground">
                Operator help center — find how to start a run, follow it live, and recover when something fails. Loopback only.
              </p>
            </div>
          </div>
          <div className="ml-auto flex flex-wrap items-center gap-1.5">
            <Button asChild size="sm" className="h-8 gap-1.5 text-xs">
              <Link to="/runs/new">
                <Rocket className="h-3.5 w-3.5" /> Start a run
              </Link>
            </Button>
            <Button asChild size="sm" variant="outline" className="h-8 gap-1.5 text-xs">
              <Link to="/sessions">
                <List className="h-3.5 w-3.5" /> View sessions
              </Link>
            </Button>
            <Button asChild size="sm" variant="outline" className="h-8 gap-1.5 text-xs">
              <a href="https://github.com/braydos-h/BreachPilot/blob/main/docs/README.md" target="_blank" rel="noopener noreferrer">
                <ExternalLink className="h-3.5 w-3.5" /> Documentation
              </a>
            </Button>
          </div>
        </div>

        {/* search */}
        <div ref={searchWrapRef} className="relative">
          <label htmlFor="help-search" className="sr-only">
            Search help topics
          </label>
          <div className="relative">
            <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" aria-hidden />
            <Input
              id="help-search"
              ref={inputRef}
              value={query}
              onChange={(e) => {
                setQuery(e.target.value);
                setShowResults(true);
              }}
              onFocus={() => setShowResults(true)}
              placeholder="What do you need help with? Try “allowlist”, “artifact”, “provider”, “decision”…"
              aria-label="Search help topics"
              aria-expanded={hasQuery && showResults}
              aria-controls="help-search-results"
              aria-autocomplete="list"
              className="h-10 rounded-lg border bg-card pl-10 pr-[88px] text-sm shadow-sm focus-visible:ring-2"
            />
            <div className="absolute right-1.5 top-1/2 flex -translate-y-1/2 items-center gap-1">
              {query ? (
                <button
                  type="button"
                  onClick={() => {
                    setQuery("");
                    inputRef.current?.focus();
                    setShowResults(false);
                  }}
                  aria-label="Clear search"
                  className="inline-flex h-7 w-7 items-center justify-center rounded-md text-muted-foreground hover:bg-accent hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
                >
                  <X className="h-4 w-4" />
                </button>
              ) : null}
              <span className="hidden items-center gap-1 rounded-md border bg-muted px-1.5 py-1 font-mono text-[11px] leading-none text-muted-foreground sm:inline-flex" aria-hidden>
                <span className="rounded bg-background px-1 py-0.5 text-[10px] leading-none">/</span> to focus
              </span>
            </div>
          </div>

          {/* results dropdown */}
          {hasQuery && showResults && (
            <div
              id="help-search-results"
              role="listbox"
              aria-label="Search results"
              className="absolute left-0 right-0 z-20 mt-2 max-h-[420px] overflow-auto rounded-lg border bg-popover p-1.5 shadow-lg scrollbar-thin"
            >
              {results.length === 0 ? (
                <div className="flex flex-col items-center gap-1.5 px-4 py-8 text-center">
                  <SearchX className="h-6 w-6 text-muted-foreground/50" aria-hidden />
                  <p className="text-sm font-medium">No results for “{query.trim()}”</p>
                  <p className="max-w-sm text-xs leading-relaxed text-muted-foreground">
                    Try “allowlist”, “recon”, “artifact”, “provider”, “audit”, or “goal”. Search covers titles, descriptions and keywords.
                  </p>
                  <Button size="sm" variant="outline" className="mt-1 h-7 text-xs" onClick={() => setQuery("")}>
                    Clear search
                  </Button>
                </div>
              ) : (
                <div className="space-y-1">
                  <div className="px-2 py-1 text-xs text-muted-foreground" aria-live="polite">
                    {results.length} result{results.length === 1 ? "" : "s"} — press Escape to clear
                  </div>
                  {results.map((t) => (
                    <button
                      key={t.id}
                      type="button"
                      role="option"
                      aria-selected={false}
                      onClick={() => {
                        setShowResults(false);
                        if (t.href) {
                          window.open(t.href, "_blank", "noopener,noreferrer");
                          return;
                        }
                        if (t.route) {
                          // internal route: navigate via scroll if on same page anchor exists, else use Link behavior via location
                          // For file-only topics that have both anchor and route, prefer anchor scroll when the section is visible.
                          const anchorEl = document.getElementById(t.anchor.replace(/^#/, ""));
                          if (anchorEl) {
                            scrollToAnchor(t.anchor);
                          } else {
                            window.location.hash = t.anchor;
                          }
                        } else {
                          scrollToAnchor(t.anchor);
                        }
                      }}
                      className="flex w-full items-start gap-2.5 rounded-md px-2.5 py-2 text-left transition-colors hover:bg-accent focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
                    >
                      <span className="mt-0.5 flex h-6 w-6 shrink-0 items-center justify-center rounded-md border bg-card text-muted-foreground">
                        <span className="text-[10px] font-medium uppercase tracking-wide">{SECTION_META[t.section].label.slice(0, 2)}</span>
                      </span>
                      <span className="min-w-0 flex-1">
                        <span className="block text-sm font-medium leading-tight">{t.title}</span>
                        <span className="line-clamp-1 block text-xs leading-relaxed text-muted-foreground">{t.description}</span>
                        <span className="mt-1 inline-flex items-center gap-1 text-[11px] text-muted-foreground">
                          <span className="rounded bg-muted px-1 py-0.5 font-mono text-[10px]">{SECTION_META[t.section].label}</span>
                          {t.route && <span className="font-mono">· {t.route}</span>}
                        </span>
                      </span>
                      <ArrowRight className="mt-1 h-3.5 w-3.5 shrink-0 text-muted-foreground" aria-hidden />
                    </button>
                  ))}
                </div>
              )}
            </div>
          )}
          {hasQuery && showResults && results.length > 0 && (
            <p className="sr-only" aria-live="polite">
              {results.length} results found.
            </p>
          )}
        </div>

        <div className="flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
          <span className="inline-flex items-center gap-1 rounded-full border bg-card px-2.5 py-1">
            <ShieldCheck className="h-3 w-3 text-emerald-500" /> Loopback only — authorized assets
          </span>
          <span className="inline-flex items-center gap-1">
            <HelpCircle className="h-3 w-3" /> Press <kbd className="rounded border bg-muted px-1 py-0.5 font-mono text-[10px]">/</kbd> to focus search, <kbd className="rounded border bg-muted px-1 py-0.5 font-mono text-[10px]">Esc</kbd> to clear
          </span>
        </div>
      </header>

      {/* quick start cards */}
      <section id="start-here" aria-labelledby="start-heading" className="scroll-mt-6">
        <div className="mb-3 flex items-center gap-2">
          <Zap className="h-4 w-4 text-primary" aria-hidden />
          <h2 id="start-heading" className="text-sm font-semibold">
            Start here
          </h2>
          <span className="text-xs text-muted-foreground">— pick a task and go</span>
        </div>
        <div className="grid gap-3 sm:grid-cols-2">
          {QUICK_START_CARDS.map((c) => {
            const Icon = QUICK_ICON[c.icon] ?? Rocket;
            return (
              <Card key={c.id} className="group flex flex-col bg-card/40 transition-colors hover:border-primary/30 hover:bg-card/60">
                <CardContent className="flex flex-1 flex-col p-4">
                  <div className="flex items-start gap-3">
                    <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-md border bg-secondary/40 text-primary transition-colors group-hover:bg-primary group-hover:text-primary-foreground">
                      <Icon className="h-4 w-4" aria-hidden />
                    </div>
                    <div className="min-w-0 flex-1">
                      <div className="text-sm font-semibold leading-tight">{c.title}</div>
                      <p className="mt-1 text-xs leading-relaxed text-muted-foreground">{c.description}</p>
                    </div>
                  </div>
                  <ol className="mt-3 flex flex-wrap gap-1.5">
                    {c.steps.map((s) => (
                      <li key={s} className="inline-flex items-center gap-1 rounded-full border bg-muted/40 px-2 py-0.5 text-[11px] text-muted-foreground">
                        <span className="h-1 w-1 rounded-full bg-primary/60" aria-hidden />
                        {s}
                      </li>
                    ))}
                  </ol>
                  <div className="mt-3 flex items-center gap-2">
                    {c.cta ? (
                      <Button asChild size="sm" variant={c.id === "first-run" ? "default" : "outline"} className="h-7 gap-1.5 text-xs">
                        <Link to={c.cta.to}>
                          {c.cta.label} <ArrowRight className="h-3 w-3" />
                        </Link>
                      </Button>
                    ) : (
                      <span className="text-xs text-muted-foreground">Open a run → Artifacts / Loot tabs in the header</span>
                    )}
                  </div>
                </CardContent>
              </Card>
            );
          })}
        </div>
      </section>

      {/* two-column main */}
      <div className="flex flex-col gap-6 lg:flex-row lg:gap-8">
        {/* primary */}
        <div className="min-w-0 flex-1 space-y-8">
          {/* lifecycle */}
          <section id="lifecycle" aria-labelledby="lifecycle-heading" className="scroll-mt-6">
            <div className="mb-3 flex items-center gap-2">
              <Network className="h-4 w-4 text-primary" aria-hidden />
              <h2 id="lifecycle-heading" className="text-sm font-semibold">
                How a run flows
              </h2>
              <span className="hidden text-xs text-muted-foreground sm:inline">— from target to report</span>
            </div>
            <Card className="overflow-hidden bg-card/40">
              <CardContent className="p-0">
                {/* desktop horizontal */}
                <div className="hidden lg:block">
                  <div className="relative flex items-stretch gap-0 divide-x">
                    {LIFECYCLE_STAGES.map((s) => {
                      const Icon = LIFECYCLE_ICON[s.id] ?? Target;
                      return (
                        <div key={s.id} className="flex flex-1 flex-col gap-2 p-3">
                          <div className="flex items-center gap-2">
                            <span className="flex h-7 w-7 items-center justify-center rounded-md border bg-card text-primary">
                              <Icon className="h-3.5 w-3.5" />
                            </span>
                            <span className="text-xs font-semibold uppercase tracking-wide">{s.label}</span>
                          </div>
                          <p className="text-xs font-medium leading-snug text-foreground/90">{s.doing}</p>
                          <p className="text-xs leading-relaxed text-muted-foreground">
                            <span className="font-medium text-foreground/80">You:</span> {s.operator}
                          </p>
                          <p className="mt-auto font-mono text-[11px] leading-relaxed text-muted-foreground">
                            {s.output}
                          </p>
                        </div>
                      );
                    })}
                  </div>
                  <div className="flex items-center justify-between gap-1 border-t bg-muted/20 px-3 py-2 text-[11px] text-muted-foreground">
                    {LIFECYCLE_STAGES.map((s, i) => (
                      <span key={s.id} className="inline-flex items-center gap-1">
                        <span className="font-mono text-foreground/70">{s.shortLabel}</span>
                        {i < LIFECYCLE_STAGES.length - 1 && <ArrowRight className="h-3 w-3 text-muted-foreground/50" />}
                      </span>
                    ))}
                  </div>
                </div>
                {/* mobile vertical */}
                <div className="divide-y lg:hidden">
                  {LIFECYCLE_STAGES.map((s, i) => {
                    const Icon = LIFECYCLE_ICON[s.id] ?? Target;
                    return (
                      <div key={s.id} className="flex gap-3 p-3">
                        <div className="flex flex-col items-center">
                          <span className="flex h-7 w-7 items-center justify-center rounded-full border bg-card text-primary">
                            <Icon className="h-3.5 w-3.5" />
                          </span>
                          {i < LIFECYCLE_STAGES.length - 1 && <span className="mt-1 w-px flex-1 bg-border" />}
                        </div>
                        <div className="min-w-0 flex-1 pb-1">
                          <div className="flex items-center gap-2">
                            <span className="text-sm font-semibold">{s.label}</span>
                            <span className="text-[11px] text-muted-foreground">· {s.hint}</span>
                          </div>
                          <p className="mt-1 text-xs leading-relaxed text-muted-foreground">{s.doing}</p>
                          <p className="mt-1 text-xs leading-relaxed">
                            <span className="font-medium">You:</span> <span className="text-muted-foreground">{s.operator}</span>
                          </p>
                          <p className="mt-1 font-mono text-[11px] text-muted-foreground">{s.output}</p>
                        </div>
                      </div>
                    );
                  })}
                </div>
              </CardContent>
            </Card>
          </section>

          {/* permissions */}
          <section id="permissions" aria-labelledby="permissions-heading" className="scroll-mt-6">
            <div className="mb-3 flex items-center gap-2">
              <ShieldAlert className="h-4 w-4 text-primary" aria-hidden />
              <h2 id="permissions-heading" className="text-sm font-semibold">
                Permission modes
              </h2>
              <span className="text-xs text-muted-foreground">— who answers each decision</span>
            </div>

            {/* matrix - desktop table */}
            <Card className="hidden overflow-hidden bg-card/40 md:block">
              <CardContent className="p-0">
                <div className="overflow-x-auto">
                  <table className="w-full text-left">
                    <thead>
                      <tr className="border-b bg-muted/30">
                        <th className="w-[36%] px-3 py-2.5 text-xs font-medium uppercase tracking-wide text-muted-foreground">Behavior</th>
                        <th className="px-3 py-2.5 text-xs font-medium">
                          <span className="inline-flex items-center gap-1.5">
                            <Badge variant="muted" className="text-[10px]">Read-only</Badge>
                          </span>
                        </th>
                        <th className="px-3 py-2.5 text-xs font-medium">
                          <span className="inline-flex items-center gap-1.5">
                            <Badge variant="warn" className="text-[10px]">Approve</Badge>
                          </span>
                        </th>
                        <th className="px-3 py-2.5 text-xs font-medium">
                          <span className="inline-flex items-center gap-1.5">
                            <Badge variant="danger" className="text-[10px]">Full access</Badge>
                          </span>
                        </th>
                      </tr>
                    </thead>
                    <tbody>
                      {PERMISSION_ROWS.map((r) => (
                        <tr key={r.criteria} className="border-t">
                          <th scope="row" className="px-3 py-2 text-xs font-medium text-foreground">
                            {r.criteria}
                          </th>
                          <td className="px-3 py-2 text-xs text-muted-foreground">{r.readOnly}</td>
                          <td className="px-3 py-2 text-xs text-muted-foreground">
                            {r.approve === "Waits" ? <span className="text-muted-foreground">{r.approve}</span> : <span className="text-yellow-600 dark:text-yellow-300">{r.approve}</span>}
                          </td>
                          <td className="px-3 py-2 text-xs">
                            {r.fullAccess === "Waits" ? <span className="text-muted-foreground">{r.fullAccess}</span> : r.fullAccess.includes("required_text") ? <span className="font-mono text-red-600 dark:text-red-300">{r.fullAccess}</span> : <span className="text-red-600 dark:text-red-300">{r.fullAccess}</span>}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
                <div className="flex items-start gap-2 border-t bg-amber-500/5 px-3 py-2.5 text-xs leading-relaxed text-amber-800 dark:text-amber-200">
                  <KeyRound className="mt-0.5 h-3.5 w-3.5 shrink-0" />
                  <p>
                    <span className="font-medium">The target-IP allowlist lock applies in every mode</span> — nothing escapes the allowlist configured for the run, regardless of permission mode. Full access auto-answers scope-checked decisions but still cannot touch a host outside the allowlist.
                  </p>
                </div>
              </CardContent>
            </Card>

            {/* mobile cards */}
            <div className="grid gap-2 md:hidden">
              {[
                { name: "Read-only", variant: "muted" as const, desc: "Every decision waits for you. Nothing auto-answered. Safest.", icon: ShieldCheck, tint: "border-border", rows: PERMISSION_ROWS.map((r) => ({ k: r.criteria, v: r.readOnly })) },
                { name: "Approve", variant: "warn" as const, desc: "Non-destructive start & tool approvals auto yes. Destructive & goals still wait.", icon: ShieldAlert, tint: "border-yellow-500/30 bg-yellow-500/5", rows: PERMISSION_ROWS.map((r) => ({ k: r.criteria, v: r.approve })) },
                { name: "Full access", variant: "danger" as const, desc: "Every start_confirm and tool_approval auto-answered — destructive sends required_text. Goals still wait.", icon: ShieldAlert, tint: "border-red-500/30 bg-red-500/5", rows: PERMISSION_ROWS.map((r) => ({ k: r.criteria, v: r.fullAccess })) },
              ].map((m) => (
                <Card key={m.name} className={`bg-card/40 ${m.tint}`}>
                  <CardContent className="p-3">
                    <div className="flex items-center gap-2">
                      <m.icon className="h-4 w-4 text-primary" />
                      <span className="text-sm font-semibold">{m.name}</span>
                      <Badge variant={m.variant} className="ml-auto text-[10px]">
                        {m.name}
                      </Badge>
                    </div>
                    <p className="mt-1 text-xs leading-relaxed text-muted-foreground">{m.desc}</p>
                    <div className="mt-2 divide-y rounded-md border bg-card/40">
                      {m.rows.map((r) => (
                        <div key={r.k} className="flex items-center justify-between gap-2 px-2.5 py-1.5 text-xs">
                          <span className="text-muted-foreground">{r.k}</span>
                          <span className="shrink-0 font-medium">{r.v}</span>
                        </div>
                      ))}
                    </div>
                  </CardContent>
                </Card>
              ))}
              <div className="flex items-start gap-2 rounded-lg border border-yellow-500/30 bg-yellow-500/10 p-3 text-xs leading-relaxed text-yellow-800 dark:text-yellow-200">
                <KeyRound className="mt-0.5 h-3.5 w-3.5 shrink-0" />
                <p>The target-IP allowlist lock applies in every mode — nothing escapes the allowlist configured for the run.</p>
              </div>
            </div>

            <p className="mt-2 text-xs leading-relaxed text-muted-foreground">
              Goal selection (<span className="font-mono">goal_select</span>) and campaign checkpoints (
              <span className="font-mono">campaign_next_step</span>) are never auto-answered — the operator must choose. See{" "}
              <span className="font-mono">tools/exploit_agent/policy.py</span> and{" "}
              <span className="font-mono">webui/src/lib/permissionMode.ts</span> for the exact rules.
            </p>
          </section>

          {/* directory */}
          <section id="directory" aria-labelledby="directory-heading" className="scroll-mt-6">
            <div className="mb-3 flex items-center gap-2">
              <Compass className="h-4 w-4 text-primary" aria-hidden />
              <h2 id="directory-heading" className="text-sm font-semibold">
                Where do I find…?
              </h2>
              <span className="text-xs text-muted-foreground">— page directory</span>
            </div>
            <div className="grid gap-2 sm:grid-cols-2">
              {DIRECTORY_ITEMS.map((d) => {
                const Icon = DIR_ICON[d.icon] ?? List;
                const content = (
                  <div className="group flex gap-3 rounded-lg border bg-card/40 p-3 transition-colors hover:border-primary/30 hover:bg-card/60">
                    <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-md border bg-secondary/40 text-muted-foreground transition-colors group-hover:text-primary">
                      <Icon className="h-4 w-4" />
                    </div>
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center gap-2">
                        <span className="text-sm font-medium leading-tight group-hover:text-primary">{d.label}</span>
                        {d.to ? <ArrowRight className="h-3 w-3 text-muted-foreground opacity-0 transition-opacity group-hover:opacity-100" /> : null}
                        {d.note ? <span className="rounded bg-muted px-1.5 py-0.5 font-mono text-[10px] text-muted-foreground">{d.note}</span> : null}
                      </div>
                      <p className="mt-1 text-xs leading-relaxed text-muted-foreground">{d.desc}</p>
                      {d.to && <span className="mt-1 inline-block font-mono text-[11px] text-muted-foreground">{d.to}</span>}
                    </div>
                  </div>
                );
                return d.to ? (
                  <Link key={d.id} to={d.to} className="focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-1 rounded-lg">
                    {content}
                  </Link>
                ) : (
                  <div key={d.id}>{content}</div>
                );
              })}
            </div>
          </section>

          {/* workflows */}
          <section id="workflows" aria-labelledby="workflows-heading" className="scroll-mt-6">
            <div className="mb-3 flex items-center gap-2">
              <Wrench className="h-4 w-4 text-primary" aria-hidden />
              <h2 id="workflows-heading" className="text-sm font-semibold">
                Common workflows
              </h2>
            </div>
            <div className="grid gap-3 sm:grid-cols-2">
              {WORKFLOWS.map((w) => {
                const Icon = WORKFLOW_ICON[w.icon] ?? Wrench;
                return (
                  <Card key={w.id} className="bg-card/40">
                    <CardContent className="p-4">
                      <div className="flex items-start gap-2.5">
                        <span className="flex h-7 w-7 shrink-0 items-center justify-center rounded-md border bg-secondary/40 text-primary">
                          <Icon className="h-3.5 w-3.5" />
                        </span>
                        <div>
                          <div className="text-sm font-semibold leading-tight">{w.title}</div>
                          <p className="mt-1 text-xs leading-relaxed text-muted-foreground">{w.desc}</p>
                        </div>
                      </div>
                      <ol className="mt-3 space-y-1.5">
                        {w.steps.map((step, idx) => (
                          <li key={idx} className="flex gap-2 text-xs leading-relaxed">
                            <span className="flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-primary/10 text-[11px] font-semibold text-primary">
                              {idx + 1}
                            </span>
                            <span className="text-muted-foreground">{step}</span>
                          </li>
                        ))}
                      </ol>
                    </CardContent>
                  </Card>
                );
              })}
            </div>
          </section>

          {/* troubleshooting */}
          <section id="troubleshooting" aria-labelledby="trouble-heading" className="scroll-mt-6">
            <div className="mb-3 flex items-center gap-2">
              <AlertTriangle className="h-4 w-4 text-primary" aria-hidden />
              <h2 id="trouble-heading" className="text-sm font-semibold">
                Troubleshooting
              </h2>
              <span className="text-xs text-muted-foreground">— symptom → check → next action</span>
            </div>
            <div className="space-y-2">
              {TROUBLESHOOTING.map((t) => {
                const open = expandedTrouble.has(t.id);
                return (
                  <div key={t.id} className="overflow-hidden rounded-lg border bg-card/40">
                    <button
                      type="button"
                      onClick={() => {
                        setExpandedTrouble((prev) => {
                          const next = new Set(prev);
                          if (next.has(t.id)) next.delete(t.id);
                          else next.add(t.id);
                          return next;
                        });
                      }}
                      aria-expanded={open}
                      aria-controls={`trouble-${t.id}`}
                      className="flex w-full items-center gap-3 px-3 py-2.5 text-left transition-colors hover:bg-accent/40 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-ring"
                    >
                      <span className="flex h-6 w-6 shrink-0 items-center justify-center rounded-md border bg-secondary/40 text-muted-foreground">
                        <SearchX className="h-3.5 w-3.5" />
                      </span>
                      <span className="flex-1 text-sm font-medium leading-snug">{t.symptom}</span>
                      <ChevronDown className={`h-4 w-4 shrink-0 text-muted-foreground transition-transform ${open ? "rotate-180" : ""}`} />
                    </button>
                    {open && (
                      <div id={`trouble-${t.id}`} className="space-y-2 border-t bg-muted/10 px-3 py-3">
                        <div className="flex gap-2 text-xs">
                          <span className="shrink-0 rounded bg-primary/10 px-1.5 py-0.5 font-medium text-primary">Check</span>
                          <span className="leading-relaxed text-muted-foreground">{t.check}</span>
                        </div>
                        <div className="flex gap-2 text-xs">
                          <span className="shrink-0 rounded bg-emerald-500/10 px-1.5 py-0.5 font-medium text-emerald-700 dark:text-emerald-300">Next</span>
                          <span className="leading-relaxed text-muted-foreground">{t.next}</span>
                        </div>
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
            <p className="mt-2 text-xs leading-relaxed text-muted-foreground">
              For the full reference see{" "}
              <a href="https://github.com/braydos-h/BreachPilot/blob/main/docs/troubleshooting.md" target="_blank" rel="noopener noreferrer" className="font-mono underline-offset-4 hover:underline">
                docs/troubleshooting.md
              </a>
              . Run <span className="font-mono">python main.py --doctor</span> first — it names the failing subsystem and prints its own hint.
            </p>
          </section>

          {/* faq */}
          <section id="faq" aria-labelledby="faq-heading" className="scroll-mt-6">
            <div className="mb-3 flex items-center gap-2">
              <HelpCircle className="h-4 w-4 text-primary" aria-hidden />
              <h2 id="faq-heading" className="text-sm font-semibold">
                FAQ &amp; concepts
              </h2>
            </div>
            <div className="space-y-2">
              {FAQ.map((f) => {
                const open = expandedFaq.has(f.id);
                return (
                  <div key={f.id} className="overflow-hidden rounded-lg border bg-card/40">
                    <button
                      type="button"
                      onClick={() => {
                        setExpandedFaq((prev) => {
                          const next = new Set(prev);
                          if (next.has(f.id)) next.delete(f.id);
                          else next.add(f.id);
                          return next;
                        });
                      }}
                      aria-expanded={open}
                      aria-controls={`faq-${f.id}`}
                      className="flex w-full items-center gap-3 px-3 py-2.5 text-left transition-colors hover:bg-accent/40 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-ring"
                    >
                      <span className="flex-1 text-sm font-medium leading-snug">{f.q}</span>
                      <ChevronDown className={`h-4 w-4 shrink-0 text-muted-foreground transition-transform ${open ? "rotate-180" : ""}`} />
                    </button>
                    {open && (
                      <div id={`faq-${f.id}`} className="border-t bg-muted/10 px-3 py-3 text-xs leading-relaxed text-muted-foreground">
                        {f.a}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </section>

          {/* docs */}
          <section id="docs" aria-labelledby="docs-heading" className="scroll-mt-6">
            <div className="mb-3 flex items-center gap-2">
              <BookOpen className="h-4 w-4 text-primary" aria-hidden />
              <h2 id="docs-heading" className="text-sm font-semibold">
                Documentation library
              </h2>
              <span className="text-xs text-muted-foreground">— {DOC_LINKS.length} guides</span>
            </div>
            {DOC_CATEGORIES.map((cat) => {
              const inCat = DOC_LINKS.filter((d: DocLink) => d.category === cat);
              if (inCat.length === 0) return null;
              return (
                <div key={cat} className="mb-5">
                  <div className="mb-2 flex items-center gap-2">
                    <h3 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">{cat}</h3>
                    <Separator className="flex-1" />
                    <span className="text-xs tabular-nums text-muted-foreground">{inCat.length}</span>
                  </div>
                  <div className="grid gap-2 sm:grid-cols-2">
                    {inCat.map((d) => (
                      <a
                        key={d.href}
                        href={d.href}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="group flex flex-col gap-1 rounded-lg border bg-card/40 p-3 transition-colors hover:border-primary/30 hover:bg-card/60 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
                      >
                        <span className="flex items-center justify-between gap-2">
                          <span className="text-sm font-medium leading-tight group-hover:text-primary">{d.title}</span>
                          <ExternalLink className="h-3.5 w-3.5 shrink-0 text-muted-foreground group-hover:text-primary" />
                        </span>
                        <span className="text-xs leading-relaxed text-muted-foreground">{d.desc}</span>
                        <span className="mt-1 inline-flex">
                          <Badge variant="muted" className="text-[10px] font-normal">
                            {cat}
                          </Badge>
                        </span>
                      </a>
                    ))}
                  </div>
                </div>
              );
            })}
            <div className="flex items-center gap-2 rounded-lg border bg-muted/20 px-3 py-2.5 text-xs text-muted-foreground">
              <FileText className="h-3.5 w-3.5 shrink-0" />
              All links point to <span className="font-mono">docs/</span> on the main branch. No external search service is used.
            </div>
          </section>

          <Separator />
          <footer className="flex flex-wrap items-center justify-between gap-2 text-xs text-muted-foreground">
            <span className="inline-flex items-center gap-1.5">
              <CheckCircle2 className="h-3 w-3" /> Help content is typed in <span className="font-mono">features/help/helpContent.ts</span> — search indexes title + description + keywords.
            </span>
            <span className="inline-flex items-center gap-1">
              <a href="https://github.com/braydos-h/BreachPilot" target="_blank" rel="noopener noreferrer" className="underline-offset-4 hover:underline">
                GitHub
              </a>
              <span>·</span>
              <Link to="/system" className="underline-offset-4 hover:underline">
                System
              </Link>
            </span>
          </footer>
        </div>

        {/* sticky sidebar */}
        <aside className="hidden w-[200px] shrink-0 lg:block">
          <div className="sticky top-6 space-y-4">
            <nav aria-labelledby="on-this-page" className="rounded-lg border bg-card/40 p-3">
              <div id="on-this-page" className="mb-2 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
                On this page
              </div>
              <ul className="space-y-0.5">
                {Object.entries(SECTION_META).map(([key, meta]) => (
                  <li key={key}>
                    <a
                      href={meta.anchor}
                      onClick={(e) => {
                        e.preventDefault();
                        scrollToAnchor(meta.anchor);
                      }}
                      className="block rounded-md px-2 py-1.5 text-xs text-muted-foreground transition-colors hover:bg-accent hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
                    >
                      {meta.label}
                    </a>
                  </li>
                ))}
              </ul>
              <Separator className="my-3" />
              <div className="space-y-1.5">
                <div className="text-xs font-medium">Quick links</div>
                <div className="grid gap-1">
                  <Link to="/runs/new" className="inline-flex items-center gap-1.5 rounded-md border bg-card px-2.5 py-1.5 text-xs hover:bg-accent focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring">
                    <Rocket className="h-3 w-3" /> New run
                  </Link>
                  <Link to="/sessions" className="inline-flex items-center gap-1.5 rounded-md border bg-card px-2.5 py-1.5 text-xs hover:bg-accent focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring">
                    <List className="h-3 w-3" /> Sessions
                  </Link>
                  <Link to="/system" className="inline-flex items-center gap-1.5 rounded-md border bg-card px-2.5 py-1.5 text-xs hover:bg-accent focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring">
                    <Settings className="h-3 w-3" /> Settings
                  </Link>
                </div>
              </div>
            </nav>

            <div className="rounded-lg border bg-muted/20 p-3">
              <div className="text-xs font-medium">Operator reminder</div>
              <p className="mt-1 text-xs leading-relaxed text-muted-foreground">
                Every target shown to the agent must be in{" "}
                <span className="font-mono">exploit.allowed_targets</span> or the MCP tool returns{" "}
                <span className="font-mono">BLOCKED</span>. See the allowlist note in Permissions.
              </p>
              <Link to="/system" className="mt-2 inline-flex items-center gap-1 text-xs text-primary underline-offset-4 hover:underline">
                Open settings <ArrowRight className="h-3 w-3" />
              </Link>
            </div>

            <div className="rounded-lg border bg-card/40 p-3">
              <div className="text-xs font-medium">Keyboard</div>
              <ul className="mt-1.5 space-y-1 text-xs text-muted-foreground">
                <li className="flex items-center justify-between gap-2">
                  <span>Focus search</span>
                  <kbd className="rounded border bg-muted px-1 py-0.5 font-mono text-[10px]">/</kbd>
                </li>
                <li className="flex items-center justify-between gap-2">
                  <span>Clear / unfocus</span>
                  <kbd className="rounded border bg-muted px-1 py-0.5 font-mono text-[10px]">Esc</kbd>
                </li>
                <li className="flex items-center justify-between gap-2">
                  <span>Jump to section</span>
                  <span className="font-mono text-[10px]">#hash</span>
                </li>
              </ul>
            </div>
          </div>
        </aside>
      </div>

      {/* mobile on-this-page */}
      <nav aria-label="On this page (mobile)" className="rounded-lg border bg-card/40 p-3 lg:hidden">
        <div className="mb-2 text-xs font-semibold uppercase tracking-wide text-muted-foreground">On this page</div>
        <div className="flex flex-wrap gap-1.5">
          {Object.entries(SECTION_META).map(([key, meta]) => (
            <a
              key={key}
              href={meta.anchor}
              onClick={(e) => {
                e.preventDefault();
                scrollToAnchor(meta.anchor);
              }}
              className="rounded-full border bg-card px-2.5 py-1 text-xs text-muted-foreground transition-colors hover:bg-accent hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
            >
              {meta.label}
            </a>
          ))}
        </div>
      </nav>
    </div>
  );
}
