import { useEffect, useMemo, useRef, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { ClipboardList, FileCheck, Flag, FlaskConical, Globe, Loader2, Network, ScanSearch, ScrollText, Share2, ShieldCheck, Square, Wrench } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { ScrollArea } from "@/components/ui/scroll-area";
import { EventViewer } from "@/components/events/EventViewer";
import { LiveRunSummary } from "@/components/LiveRunSummary";
import { PhaseTracker } from "@/components/PhaseTracker";
import { Skeleton, SkeletonCards } from "@/components/Loading";
import { RunCommandHeader } from "@/components/run/RunCommandHeader";
import { RunNowCard } from "@/components/run/RunNowCard";
import { RunTelemetryCard } from "@/components/run/RunTelemetryCard";
import { RunOutcomeCard } from "@/components/run/RunOutcomeCard";
import { RunAttentionBanner } from "@/components/run/RunAttentionBanner";
import { PendingDecisionPanel } from "@/components/run/PendingDecisionPanel";
import { deriveRunState } from "@/lib/deriveRun";
import { FastReconProgress } from "@/components/FastReconProgress";
import { useRunEvents } from "@/api/ws";
import {
  useAnswerDecision,
  useArtifacts,
  useAudit,
  useCallTool,
  useCancelRun,
  useCapabilities,
  useConfig,
  useDecisions,
  useFetchArtifactBlob,
  useResumeRun,
  useRun,
  useRunSandbox,
  useRunTools,
  useSwarmState,
  useCampaignState,
  useWitness,
} from "@/api/hooks";
import { ApiError } from "@/api/client";
import { isActiveState, isTerminalState, type RunState, type RunResult, type DecisionListRow } from "@/api/types";
import { autoAnswerFor, usePermissionMode } from "@/lib/permissionMode";
import { ReconTab } from "@/routes/run/tabs/ReconTab";
import { GraphTab } from "@/routes/run/tabs/GraphTab";
import { SummaryTab } from "@/routes/run/tabs/SummaryTab";
import { ManualToolPanel } from "@/routes/run/tabs/ToolsTab";
import { AdvisoryPanel } from "@/routes/run/tabs/AdvisoryTab";
import { AuditView } from "@/routes/run/tabs/AuditTab";
import { BrowserTab } from "@/routes/run/tabs/BrowserTab";
import { SandboxTab } from "@/routes/run/tabs/SandboxTab";
import { SwarmTab } from "@/routes/run/tabs/SwarmTab";
import { CampaignTab } from "@/routes/run/tabs/CampaignTab";
import { EvidenceTab } from "@/routes/run/tabs/EvidenceTab";
import { DecisionHistoryCard } from "@/routes/run/DecisionHistoryCard";

export function RunPage() {
  const { runId } = useParams<{ runId: string }>();
  const navigate = useNavigate();
  const [tab, setTab] = useState("recon");
  const run = useRun(runId ?? null);
  const decisions = useDecisions(runId ?? null);
  const events = useRunEvents(runId ?? null);
  const cancel = useCancelRun();
  const resume = useResumeRun();
  const audit = useAudit(runId ?? null, tab === "audit" || tab === "browser");
  const sandbox = useRunSandbox(tab === "sandbox" ? (runId ?? null) : null);
  const capabilities = useCapabilities();
  const swarm = useSwarmState(runId ?? null, tab === "swarm", isActiveState(run.data?.state as RunState) ? 3000 : false);
  const campaign = useCampaignState(runId ?? null, tab === "campaign", isActiveState(run.data?.state as RunState) ? 3000 : false);
  const witness = useWitness(runId ?? null, tab === "swarm" && capabilities.data?.features.includes("witness") === true);
  const config = useConfig();
  const tools = useRunTools(runId ?? null, (tab === "tools" || tab === "advisory" || tab === "campaign") && isActiveState(run.data?.state as RunState));
  const callTool = useCallTool(runId ?? "");
  const fetchArtifact = useFetchArtifactBlob(runId ?? "");
  const artifacts = useArtifacts(runId ?? null);

  const artifactNames = useMemo(() => new Set((artifacts.data?.artifacts ?? []).map((a) => a.name)), [artifacts.data]);
  const runIsActive = isActiveState(run.data?.state as RunState);
  const artifactReady = (name: string) => !runIsActive || artifactNames.has(name);

  const [showCancel, setShowCancel] = useState(false);
  const [selectedTool, setSelectedTool] = useState<string>("");
  const [toolArgs, setToolArgs] = useState<string>("{}");
  const [toolResult, setToolResult] = useState<string>("");
  const [advisoryResult, setAdvisoryResult] = useState<string>("");

  // Navigating between runs reuses this component (same route, new param).
  // Reset per-run UI state so the previous run's tab/tool results never
  // render against the new run's data.
  useEffect(() => {
    setTab("recon");
    setSelectedTool("");
    setToolArgs("{}");
    setToolResult("");
    setAdvisoryResult("");
  }, [runId]);

  const mergedDecisions = useMemo(() => {
    const rows = decisions.data?.decisions ?? [];
    const byId = new Map(rows.map((row) => [row.id, row]));
    const answeredOverrides = new Map<string, string | null>();
    const wsAdded: DecisionListRow[] = [];
    for (const ev of events.events) {
      if (ev.type !== "approval") continue;
      const id = ev.payload.decision_id;
      if (typeof id !== "string") continue;
      const existing = byId.get(id);
      if (ev.payload.status === "answered") {
        if (existing) answeredOverrides.set(id, typeof ev.payload.answer === "string" ? ev.payload.answer : null);
        continue;
      }
      if (existing) continue;
      const row = {
        id,
        kind: String(ev.payload.kind ?? "tool_approval"),
        status: "pending" as const,
        answer: "",
        prompt_text: String(ev.payload.prompt_text ?? ""),
        required_text: String(ev.payload.required_text ?? ""),
        options: Array.isArray(ev.payload.options) ? ev.payload.options : [],
      };
      byId.set(id, row);
      wsAdded.push(row);
    }
    const merged = rows.map((row) => {
      if (!answeredOverrides.has(row.id)) return row;
      const answer = answeredOverrides.get(row.id) ?? null;
      return answer === null ? { ...row, status: "answered" as const } : { ...row, status: "answered" as const, answer };
    });
    return [...wsAdded, ...merged];
  }, [decisions.data, events.events]);

  const pendingDecisions = mergedDecisions.filter((d) => d.status === "pending");
  const currentState = (events.events.findLast((e) => e.type === "state")?.payload?.state as RunState | undefined) ?? run.data?.state;
  const active = isActiveState(currentState as RunState);
  const terminal = isTerminalState(currentState as RunState);
  const derived = useMemo(() => deriveRunState(events.events), [events.events]);
  const telemetry = useMemo(() => derived.lastTelemetry ?? (run.data?.result?.telemetry ?? null), [derived, run.data?.result]);

  const { mode } = usePermissionMode();
  const answerDecision = useAnswerDecision(runId ?? "");
  const inFlight = useRef<Set<string>>(new Set());
  useEffect(() => {
    if (mode === "read_only") return;
    for (const d of pendingDecisions) {
      if (inFlight.current.has(d.id)) continue;
      const ans = autoAnswerFor(d, mode);
      if (ans === null) continue;
      inFlight.current.add(d.id);
      answerDecision.mutate(
        { decisionId: d.id, answer: ans },
        { onError: () => { inFlight.current.delete(d.id); } },
      );
    }
  }, [mode, pendingDecisions, answerDecision]);

  const autoAnsweringIds = new Set(pendingDecisions.filter((d) => mode !== "read_only" && inFlight.current.has(d.id)).map((d) => d.id));

  const transportLabel =
    events.transport === "sse" ? "SSE" : events.transport === "websocket" ? "WS" : events.status === "reconnecting" ? "reconnecting" : events.status === "closed" ? "offline" : events.status === "connecting" ? "connecting" : events.status === "error" ? "error" : "—";

  if (run.isLoading) {
    return (
      <div className="flex min-h-0 flex-col gap-2 p-2 xl:h-full xl:overflow-hidden" role="status" aria-live="polite">
        <div className="rounded-md border bg-card/50 px-2.5 py-2">
          <div className="flex items-center gap-2">
            <Skeleton className="h-5 w-40" />
            <Skeleton className="h-4 w-16 rounded-full" />
          </div>
          <div className="mt-1.5 flex flex-wrap gap-x-2 gap-y-1">
            <Skeleton className="h-3 w-32" />
            <Skeleton className="h-3 w-24" />
            <Skeleton className="h-3 w-28" />
          </div>
        </div>
        <div className="flex flex-1 gap-2 xl:overflow-hidden">
          <div className="flex flex-1 flex-col gap-2">
            <Skeleton className="h-20 rounded-md" />
            <Skeleton className="h-[40vh] flex-1 rounded-md xl:min-h-0" />
          </div>
          <div className="hidden w-[280px] xl:block">
            <SkeletonCards count={2} />
          </div>
        </div>
      </div>
    );
  }
  if (run.error || !run.data) {
    const notFound = run.error instanceof ApiError && run.error.isNotFound;
    return (
      <div className="flex flex-col items-start gap-3 p-6 text-sm">
        <div className="text-destructive">{notFound ? "Run not found." : "Failed to load run."}</div>
        <div className="flex gap-2">
          <Button asChild variant="outline" size="sm">
            <Link to="/sessions">Back to runs</Link>
          </Button>
          <Button size="sm" onClick={() => run.refetch()}>Retry</Button>
        </div>
      </div>
    );
  }

  const runData = run.data;
  const gotoSummary = () => setTab("summary");
  const resumeRun = () => resume.mutate(runData.id, { onSuccess: (data) => navigate(`/runs/${data.run_id}`) });

  return (
    <div className="flex min-h-0 flex-col gap-2 p-2 xl:h-full xl:flex-1 xl:overflow-hidden">
      <RunCommandHeader run={runData} state={currentState as RunState} active={active} terminal={terminal} transportLabel={transportLabel} eventsStatus={events.status} derived={derived} onCancelRequest={() => setShowCancel(true)} cancelPending={cancel.isPending} onResume={resumeRun} resumePending={resume.isPending} />
      <RunAttentionBanner authError={events.authError} pendingCount={pendingDecisions.length} active={active} eventsStatus={events.status} stale={events.stale} />
      {(runData.request?.mode === "fast" || runData.preview?.mode === "fast" || (runData as unknown as Record<string, unknown>).mode === "fast") && <FastReconProgress events={events.events} />}
      <div className="flex min-h-0 flex-1 flex-col gap-2 xl:flex-row xl:overflow-hidden">
        <div className="flex min-w-0 flex-1 flex-col gap-2 xl:min-h-0 xl:overflow-hidden">
          {pendingDecisions.length > 0 && (
            <div className="shrink-0">
              <PendingDecisionPanel decisions={pendingDecisions} runId={runData.id} autoAnsweringIds={autoAnsweringIds} />
            </div>
          )}
          <div className="shrink-0">
            {terminal ? <RunOutcomeCard run={runData} state={currentState as RunState} derived={derived} onShowSummary={gotoSummary} onResume={resumeRun} resumePending={resume.isPending} /> : <RunNowCard derived={derived} active={active} state={currentState as RunState} />}
          </div>
          <div className="flex min-h-0 flex-1 flex-col gap-2 xl:overflow-hidden">
            <EventViewer events={events.events} decisions={mergedDecisions} runId={runData.id} status={events.status} transport={events.transport} authError={events.authError} stale={events.stale} dropped={events.dropped} terminal={terminal} className="flex min-h-[280px] flex-col overflow-hidden xl:min-h-0 xl:flex-[1.35] xl:h-full" />
            <Tabs value={tab} onValueChange={setTab} className="flex min-h-[200px] flex-col overflow-hidden rounded-md border bg-card/30 xl:min-h-0 xl:flex-1 xl:max-h-[44%]">
              <div className="shrink-0 border-b bg-muted/30">
                <ScrollArea type="scroll" className="w-full">
                  <TabsList className="h-7 bg-transparent p-0.5">
                    <TabsTrigger value="recon" className="h-6 px-2 py-0 text-xs"><ScanSearch className="mr-1 h-3 w-3" />Recon</TabsTrigger>
                    <TabsTrigger value="graph" className="h-6 px-2 py-0 text-xs"><Network className="mr-1 h-3 w-3" />Attack Path</TabsTrigger>
                    <TabsTrigger value="summary" className="h-6 px-2 py-0 text-xs"><ClipboardList className="mr-1 h-3 w-3" />Summary</TabsTrigger>
                    <span aria-hidden className="mx-1 hidden h-5 w-px bg-border sm:block" />
                    <TabsTrigger value="tools" className="h-6 px-2 py-0 text-xs"><Wrench className="mr-1 h-3 w-3" />Tools</TabsTrigger>
                    <TabsTrigger value="advisory" className="h-6 px-2 py-0 text-xs"><FlaskConical className="mr-1 h-3 w-3" />Advisory</TabsTrigger>
                    <TabsTrigger value="audit" className="h-6 px-2 py-0 text-xs"><ScrollText className="mr-1 h-3 w-3" />Audit</TabsTrigger>
                    <TabsTrigger value="sandbox" className="h-6 px-2 py-0 text-xs"><ShieldCheck className="mr-1 h-3 w-3" />Sandbox</TabsTrigger>
                    <TabsTrigger value="browser" className="h-6 px-2 py-0 text-xs"><Globe className="mr-1 h-3 w-3" />Browser</TabsTrigger>
                    <TabsTrigger value="swarm" className="h-6 px-2 py-0 text-xs"><Share2 className="mr-1 h-3 w-3" />Swarm</TabsTrigger>
                    <TabsTrigger value="campaign" className="h-6 px-2 py-0 text-xs"><Flag className="mr-1 h-3 w-3" />Campaign</TabsTrigger>
                    <TabsTrigger value="evidence" className="h-6 px-2 py-0 text-xs"><FileCheck className="mr-1 h-3 w-3" />Evidence</TabsTrigger>
                  </TabsList>
                </ScrollArea>
              </div>
              <div className="min-h-0 flex-1 overflow-y-auto overflow-x-hidden p-2 scrollbar-thin">
                <TabsContent value="recon" className="mt-0 space-y-2"><ReconTab fetchArtifact={fetchArtifact} ready={artifactReady("recon_assessment.json")} /></TabsContent>
                <TabsContent value="graph" className="mt-0 space-y-2"><GraphTab runId={runData.id} ready={artifactReady("enhanced/enhanced_report.json")} /></TabsContent>
                <TabsContent value="summary" className="mt-0 space-y-2"><SummaryTab result={(runData.result ?? {}) as RunResult} title={runData.title} /></TabsContent>
                <TabsContent value="tools" className="mt-0 space-y-2">
                  <ManualToolPanel runId={runData.id} tools={tools.data?.tools ?? []} isLoading={tools.isLoading} selectedTool={selectedTool} onSelect={setSelectedTool} args={toolArgs} onArgs={setToolArgs} result={toolResult} onResult={setToolResult} onCall={(name: string, parsedArgs: Record<string, unknown>) => callTool.mutate({ tool: name, arguments: parsedArgs }, { onSuccess: (data) => setToolResult(data.result || "(no output)"), onError: (err) => setToolResult(err instanceof ApiError ? err.message : "Tool call failed.") })} calling={callTool.isPending} />
                </TabsContent>
                <TabsContent value="advisory" className="mt-0 space-y-2">
                  <AdvisoryPanel tools={tools.data?.tools ?? []} toolsLoading={tools.isLoading} features={capabilities.data?.features ?? []} runActive={active} onCall={(name: string, parsedArgs: Record<string, unknown>) => callTool.mutate({ tool: name, arguments: parsedArgs }, { onSuccess: (data) => setAdvisoryResult(data.result || "(no output)"), onError: (err) => setAdvisoryResult(err instanceof ApiError ? err.message : "Tool call failed.") })} calling={callTool.isPending} lastResult={advisoryResult} />
                </TabsContent>
                <TabsContent value="audit" className="mt-0 space-y-2"><AuditView loading={audit.isLoading} error={audit.error} records={audit.data?.records ?? []} chainValid={audit.data?.chain_valid ?? false} chainReason={audit.data?.chain_reason ?? ""} /></TabsContent>
                <TabsContent value="sandbox" className="mt-0 space-y-2"><SandboxTab loading={sandbox.isLoading} error={sandbox.error} data={sandbox.data} /></TabsContent>
                <TabsContent value="browser" className="mt-0 space-y-2"><BrowserTab runId={runData.id} records={audit.data?.records ?? []} loading={audit.isLoading} error={audit.error} /></TabsContent>
                <TabsContent value="swarm" className="mt-0"><SwarmTab loading={swarm.isLoading} error={swarm.error} state={swarm.data?.state} witnessFlags={witness.data?.flags} witnessLoading={witness.isLoading} negotiationRounds={Number((config.data?.swarm as Record<string, unknown> | undefined)?.negotiation_rounds ?? 0) || 0} /></TabsContent>
                <TabsContent value="campaign" className="mt-0"><CampaignTab loading={campaign.isLoading} error={campaign.error} state={campaign.data?.state} runId={runData.id} target={runData.request?.target || ""} runActive={active} tools={(tools.data?.tools ?? []).map((t) => t.function?.name ?? "")} /></TabsContent>
                <TabsContent value="evidence" className="mt-0 space-y-2"><EvidenceTab runId={runData.id} /></TabsContent>
              </div>
            </Tabs>
          </div>
        </div>
        <aside className="flex min-w-0 shrink-0 flex-col gap-2 xl:w-[280px] xl:min-h-0 xl:overflow-y-auto xl:overflow-x-hidden scrollbar-thin">
          <RunTelemetryCard telemetry={telemetry} derived={derived} />
          <LiveRunSummary derived={derived} runState={currentState as RunState} />
          <PhaseTracker derived={derived} runState={currentState as RunState} orientation="vertical" />
          <DecisionHistoryCard decisions={mergedDecisions} />
        </aside>
      </div>
      <Dialog open={showCancel} onOpenChange={setShowCancel}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Cancel this run?</DialogTitle>
            <DialogDescription>Cancellation is cooperative. The agent stops at the next boundary and tears down MCP/swarm children.</DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowCancel(false)}>Keep running</Button>
            <Button variant="destructive" onClick={() => { cancel.mutate(runData.id, { onSettled: () => setShowCancel(false) }); }} disabled={cancel.isPending}>
              {cancel.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Square className="h-4 w-4" />}
              Cancel run
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
