import {
  useMutation,
  useQuery,
  useQueryClient,
  keepPreviousData,
} from "@tanstack/react-query";
import { useCallback, useEffect, useState } from "react";
import {
  apiFetch,
  ApiError,
} from "@/api/client";
import type {
  ArtifactListResponse,
  AttackModulesResponse,
  AuditResponse,
  BrowserCapabilityRecord,
  Capabilities,
  ChatgptLoginResponse,
  ChatgptProxyResponse,
  ConfigPatchResponse,
  ConfigSchema,
  CampaignStateResponse,
  ConnectionListenerResponse,
  ConnectionsListResponse,
  CreateRunResponse,
  CredentialRevealResponse,
  CredentialsResponse,
  DecisionAnswerResponse,
  DecisionListRow,
  DecisionOut,
  DecideFindingResponse,
  DeleteRunResponse,
  CustomGoal,
  DiagnosticsResponse,
  GoalsResponse,
  LiveModelsResponse,
  LogResponse,
  LootResponse,
  MemoryResponse,
  ModelRegistryInfo,
  ModelsSyncResponse,
  OperatorConnection,
  PluginSummary,
  ProposedResponse,
  ProvidersResponse,
  RemoveConnectionResponse,
  ResumeRunResponse,
  RunCreateRequest,
  RunDetail,
  RunListResponse,
  RunListRow,
  RunGraphResponse,
  RunSandboxResponse,
  SecretsStatus,
  SkillDetail,
  SkillInstallRequest,
  SkillInstallResponse,
  SkillRemoveResponse,
  SkillSearchResult,
  SkillSummary,
  SwarmStateResponse,
  SystemInfoResponse,
  HostPlatformResponse,
  TelemetryResponse,
  ToolCallRequest,
  ToolCallResponse,
  ToolsResponse,
  WitnessResponse,
  WorkspaceListResponse,
} from "@/api/types";
import { isActiveState } from "@/api/types";

export const queryKeys = {
  capabilities: ["capabilities"] as const,
  config: ["config"] as const,
  configSchema: ["config", "schema"] as const,
  secrets: ["secrets"] as const,
  models: ["models"] as const,
  modelsLive: ["models", "live"] as const,
  providers: ["providers"] as const,
  telemetry: ["telemetry"] as const,
  memory: ["memory"] as const,
  plugins: ["plugins"] as const,
  goals: ["goals"] as const,
  hostPlatform: ["system", "platform"] as const,
  skills: ["skills"] as const,
  skillsSearch: (q: string) => ["skills", "search", q] as const,
  skill: (name: string) => ["skills", name] as const,
  connections: ["connections"] as const,
  connection: (id: string) => ["connections", id] as const,
  connectionListener: (id: string) => ["connections", id, "listener"] as const,
  runs: (limit: number, offset: number, sort: string = "created_desc", q: string = "", state: string = "") =>
    ["runs", { limit, offset, sort, q, state }] as const,
  run: (runId: string) => ["runs", runId] as const,
  runDecisions: (runId: string) => ["runs", runId, "decisions"] as const,
  decision: (runId: string, decisionId: string) => ["runs", runId, "decisions", decisionId] as const,
  runTools: (runId: string) => ["runs", runId, "tools"] as const,
  runArtifacts: (runId: string) => ["runs", runId, "artifacts"] as const,
  runAudit: (runId: string) => ["runs", runId, "audit"] as const,
  runSandbox: (runId: string) => ["runs", runId, "sandbox"] as const,
  runSwarm: (runId: string) => ["runs", runId, "swarm"] as const,
  runCampaign: (runId: string) => ["runs", runId, "campaign"] as const,
  runLog: (runId: string, name: string, tail: number, attempt?: string, target?: string) =>
    ["runs", runId, "logs", name, tail, attempt ?? "", target ?? ""] as const,
  runCredentials: (runId: string) => ["runs", runId, "credentials"] as const,
  runLoot: (runId: string) => ["runs", runId, "loot"] as const,
  runWorkspace: (runId: string) => ["runs", runId, "workspace"] as const,
  runGraph: (runId: string) => ["runs", runId, "graph"] as const,
  runWitness: (runId: string) => ["runs", runId, "witness"] as const,
  runProposed: (runId: string) => ["runs", runId, "proposed"] as const,
};

const DEFAULT_RETRY = (failureCount: number, error: unknown) => {
  if (error instanceof ApiError) {
    if (error.status === 0) return failureCount < 3;
    if (error.status >= 400 && error.status < 500 && error.status !== 408 && error.status !== 429) {
      return false;
    }
  }
  return failureCount < 2;
};

export const defaultQueryOptions = {
  retry: DEFAULT_RETRY,
  staleTime: 15_000,
  gcTime: 5 * 60_000,
  meta: { onErrorAuthClear: true } as const,
};

export function useCapabilities(enabled = true) {
  return useQuery<Capabilities>({
    queryKey: queryKeys.capabilities,
    queryFn: () => apiFetch<Capabilities>("/capabilities"),
    ...defaultQueryOptions,
    enabled,
    staleTime: 60_000,
  });
}

export function useConfig() {
  return useQuery<Record<string, unknown>>({
    queryKey: queryKeys.config,
    queryFn: () => apiFetch<Record<string, unknown>>("/config"),
    ...defaultQueryOptions,
    staleTime: 30_000,
  });
}

export function useConfigSchema() {
  return useQuery<ConfigSchema>({
    queryKey: queryKeys.configSchema,
    queryFn: () => apiFetch<ConfigSchema>("/config/schema"),
    ...defaultQueryOptions,
    staleTime: Infinity,
  });
}

export function usePatchConfig() {
  const qc = useQueryClient();
  return useMutation<ConfigPatchResponse, ApiError, Record<string, unknown>>({
    mutationFn: (patch) =>
      apiFetch<ConfigPatchResponse>("/config", { method: "PATCH", body: patch }),
    onSuccess: (data, variables) => {
      qc.setQueryData<Record<string, unknown>>(queryKeys.config, data.config);
      // Only refetch models/live/providers when the patch actually touches
      // provider/model config; skills-only edits must not trigger provider probing.
      const keys = Object.keys(variables);
      const touchesModels =
        keys.some((k) => ["models", "ollama", "chatgpt", "opencode_go", "provider"].includes(k)) ||
        (variables.models != null &&
          typeof variables.models === "object" &&
          "provider" in (variables.models as Record<string, unknown>)) ||
        variables.opencode_go != null;
      if (touchesModels) {
        void qc.invalidateQueries({ queryKey: queryKeys.models });
        void qc.invalidateQueries({ queryKey: queryKeys.modelsLive });
        void qc.invalidateQueries({ queryKey: queryKeys.providers });
      }
    },
    // 401 handling is global now — App.tsx's MutationCache.onError funnels any
    // mutation 401 through expireSession().
  });
}

export function useSecrets() {
  return useQuery<SecretsStatus>({
    queryKey: queryKeys.secrets,
    queryFn: () => apiFetch<SecretsStatus>("/secrets"),
    ...defaultQueryOptions,
    staleTime: 30_000,
  });
}

export function usePutSecrets() {
  const qc = useQueryClient();
  return useMutation<unknown, ApiError, Record<string, string>>({
    mutationFn: (secrets) =>
      apiFetch<unknown>("/secrets", { method: "PUT", body: { secrets } }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: queryKeys.secrets });
    },
  });
}

export function useModels() {
  return useQuery<ModelRegistryInfo>({
    queryKey: queryKeys.models,
    queryFn: () => apiFetch<ModelRegistryInfo>("/models"),
    ...defaultQueryOptions,
    staleTime: 60_000,
  });
}

export function useLiveModels() {
  return useQuery<LiveModelsResponse>({
    queryKey: queryKeys.modelsLive,
    queryFn: async () => {
      try {
        return await apiFetch<LiveModelsResponse>("/models/live", { raw: false });
      } catch (error) {
        if (error instanceof ApiError && error.status === 503 && error.raw) {
          const fallback: LiveModelsResponse = error.raw;
          return fallback;
        }
        throw error;
      }
    },
    ...defaultQueryOptions,
    staleTime: 30_000,
  });
}

export function useAddModel() {
  const qc = useQueryClient();
  return useMutation<unknown, ApiError, { alias: string; model: string }>({
    mutationFn: (body) => apiFetch<unknown>("/models", { method: "POST", body }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: queryKeys.models });
    },
  });
}

export function useRemoveModel() {
  const qc = useQueryClient();
  return useMutation<unknown, ApiError, string>({
    mutationFn: (alias) => apiFetch<unknown>(`/models/${encodeURIComponent(alias)}`, { method: "DELETE" }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: queryKeys.models });
    },
  });
}

export function useSetModelProvider() {
  const qc = useQueryClient();
  return useMutation<unknown, ApiError, string>({
    mutationFn: (provider) => apiFetch<unknown>("/models/provider", { method: "POST", body: { provider } }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: queryKeys.models });
      void qc.invalidateQueries({ queryKey: queryKeys.modelsLive });
      void qc.invalidateQueries({ queryKey: queryKeys.providers });
    },
  });
}

/** POST /models/refresh — bump models.registry to the newest Ollama versions. */
export function useSyncModels() {
  const qc = useQueryClient();
  return useMutation<ModelsSyncResponse, ApiError, void>({
    mutationFn: () => apiFetch<ModelsSyncResponse>("/models/refresh", { method: "POST" }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: queryKeys.models });
      void qc.invalidateQueries({ queryKey: queryKeys.modelsLive });
    },
  });
}

export function useProviders() {
  return useQuery<ProvidersResponse>({
    queryKey: queryKeys.providers,
    queryFn: () => apiFetch<ProvidersResponse>("/providers"),
    ...defaultQueryOptions,
    staleTime: 15_000,
  });
}

export function useSystemInfo() {
  return useQuery<SystemInfoResponse>({
    queryKey: ["system", "info"],
    queryFn: () => apiFetch<SystemInfoResponse>("/system/info"),
    ...defaultQueryOptions,
    staleTime: 60_000,
  });
}

export function useHostPlatform() {
  return useQuery<HostPlatformResponse>({
    queryKey: queryKeys.hostPlatform,
    queryFn: () => apiFetch<HostPlatformResponse>("/system/platform"),
    ...defaultQueryOptions,
    staleTime: 5 * 60_000,
    gcTime: 30 * 60_000,
    retry: false,
    refetchOnWindowFocus: false,
  });
}

export function useTelemetry() {
  return useQuery<TelemetryResponse>({
    queryKey: queryKeys.telemetry,
    queryFn: () => apiFetch<TelemetryResponse>("/system/telemetry"),
    ...defaultQueryOptions,
    staleTime: 15_000,
    refetchInterval: 8_000,
    refetchIntervalInBackground: true,
  });
}

export function useMemory() {
  return useQuery<MemoryResponse>({
    queryKey: queryKeys.memory,
    queryFn: () => apiFetch<MemoryResponse>("/system/memory"),
    ...defaultQueryOptions,
    staleTime: 15_000,
  });
}

export interface SandboxStatusResponse {
  enabled: boolean;
  backend: string;
  image: string;
  user: string;
  read_only_rootfs: boolean;
  /** Effective execution posture: disabled | contained | native_fallback | blocked. */
  mode: string;
  /** sandbox.fallback_native config value (true = degrade to host mode, false = fail closed). */
  fallback_native: boolean;
  /** Why the sandbox degraded (Docker down / image missing); "" when contained. */
  fallback_reason: string;
  docker_available: boolean;
  docker_error: string;
  /** null = unknowable (sandbox disabled / daemon down); true/false when probed. */
  image_present: boolean | null;
  network: {
    enforce: boolean;
    fail_closed: boolean;
    allow_dns: string;
    map_host_loopback: boolean;
    extra_allow_cidrs: string[];
  };
  resources: {
    memory_mb: number;
    cpus: number;
    pids: number;
    timeout_seconds: number;
    output_max_bytes: number;
  };
  cleanup: {
    remove_on_exit: boolean;
    remove_stale_on_startup: boolean;
  };
  note?: string;
}

/** Disposable-sandbox status (System UI). Read-only; no Docker controls. */
export function useSandboxStatus() {
  return useQuery<SandboxStatusResponse>({
    queryKey: ["system", "sandbox"],
    queryFn: () => apiFetch<SandboxStatusResponse>("/system/sandbox"),
    ...defaultQueryOptions,
    staleTime: 30_000,
  });
}

export interface BrowserHealth {
  name: string;
  ok: boolean;
  detail: string;
  playwright_present: boolean;
  playwright_version: string;
  chromium_present: boolean;
}

/** Playwright browser-agent status (System UI). Read-only; never launches. */
export interface BrowserSystemStatus {
  enabled: boolean;
  backend: string;
  available: boolean;
  health: BrowserHealth;
  capabilities: BrowserCapabilityRecord[];
  config: {
    headless: boolean;
    max_sessions: number;
    allow_mutating_actions: boolean;
    capture_screenshots: boolean;
    capture_network: boolean;
    capture_console: boolean;
  };
}

/** Browser-agent status (Advanced settings + status overview). Read-only. */
export function useBrowserStatus() {
  return useQuery<BrowserSystemStatus>({
    queryKey: ["system", "browser"],
    queryFn: () => apiFetch<BrowserSystemStatus>("/system/browser"),
    ...defaultQueryOptions,
    staleTime: 30_000,
  });
}

export interface SandboxFixPlanStep {
  id: string;
  title: string;
  description: string;
  command_preview: string | null;
  requires_admin?: boolean;
  manual?: boolean;
}

export interface SandboxFixPlanResponse {
  platform: string;
  reason: string;
  docker_cli_present: boolean;
  docker_daemon_running: boolean;
  image_present: boolean | null;
  requires_admin: boolean;
  steps: SandboxFixPlanStep[];
  image?: string;
  mode?: string;
  docker_error?: string;
}

export interface SandboxFixJobStepStatus {
  id: string;
  title: string;
  description: string;
  command_preview: string | null;
  requires_admin?: boolean;
  manual?: boolean;
  status: "pending" | "running" | "succeeded" | "failed" | "skipped";
  output?: string;
  error?: string;
}

export interface SandboxFixJobResponse {
  job_id: string;
  status: "pending" | "running" | "succeeded" | "failed";
  platform: string;
  reason: string;
  steps: SandboxFixJobStepStatus[];
  error?: string;
  docker_ready?: boolean;
  requires_restart?: boolean;
  current_step?: string | null;
  docker_cli_present?: boolean;
  docker_daemon_running?: boolean;
  image_present?: boolean | null;
  requires_admin?: boolean;
}

export function useSandboxFixPlan(enabled = true) {
  return useQuery<SandboxFixPlanResponse>({
    queryKey: ["system", "sandbox", "fix", "plan"] as const,
    queryFn: () => apiFetch<SandboxFixPlanResponse>("/system/sandbox/fix/plan"),
    ...defaultQueryOptions,
    enabled,
    staleTime: 15_000,
  });
}

export function useSandboxFix() {
  const qc = useQueryClient();
  return useMutation<SandboxFixJobResponse, ApiError, void>({
    mutationFn: () => apiFetch<SandboxFixJobResponse>("/system/sandbox/fix", { method: "POST", body: {} }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["system", "sandbox"] });
    },
  });
}

export function useSandboxFixStatus(jobId: string | null | undefined) {
  return useQuery<SandboxFixJobResponse>({
    queryKey: ["system", "sandbox", "fix", jobId ?? ""] as const,
    queryFn: () => apiFetch<SandboxFixJobResponse>(`/system/sandbox/fix/${encodeURIComponent(jobId as string)}`),
    ...defaultQueryOptions,
    enabled: !!jobId,
    refetchInterval: (query) => {
      const data = query.state.data as SandboxFixJobResponse | undefined;
      if (!data) return 2000;
      if (data.status === "running" || data.status === "pending") return 1500;
      return false;
    },
  });
}

/** Per-run sandbox summary (Sandbox tab). Polls only while the run is active. */
export function useRunSandbox(runId: string | null | undefined) {
  const qc = useQueryClient();
  return useQuery<RunSandboxResponse>({
    queryKey: queryKeys.runSandbox(runId ?? ""),
    queryFn: () => apiFetch<RunSandboxResponse>(`/runs/${encodeURIComponent(runId as string)}/sandbox`),
    ...defaultQueryOptions,
    enabled: !!runId,
    refetchInterval: () => {
      if (!runId) return false;
      const run = qc.getQueryData<RunDetail>(queryKeys.run(runId));
      if (!run || isActiveState(run.state)) return 30_000;
      return false;
    },
  });
}

/** Invalidate providers + models caches (after login/proxy changes). */
export function useInvalidateProviders() {
  const qc = useQueryClient();
  return useCallback(() => {
    qc.invalidateQueries({ queryKey: queryKeys.providers });
    qc.invalidateQueries({ queryKey: queryKeys.modelsLive });
    qc.invalidateQueries({ queryKey: queryKeys.models });
  }, [qc]);
}

export function useChatgptLogin() {
  const invalidate = useInvalidateProviders();
  return useMutation<ChatgptLoginResponse, ApiError, void>({
    mutationFn: () => apiFetch<ChatgptLoginResponse>("/providers/chatgpt/login", { method: "POST", body: {} }),
    onSettled: invalidate,
  });
}

export function useChatgptProxyStart() {
  const invalidate = useInvalidateProviders();
  return useMutation<ChatgptProxyResponse, ApiError, void>({
    mutationFn: () => apiFetch<ChatgptProxyResponse>("/providers/chatgpt/proxy/start", { method: "POST", body: {} }),
    onSettled: invalidate,
  });
}

export function useChatgptProxyStop() {
  const invalidate = useInvalidateProviders();
  return useMutation<ChatgptProxyResponse, ApiError, void>({
    mutationFn: () => apiFetch<ChatgptProxyResponse>("/providers/chatgpt/proxy/stop", { method: "POST", body: {} }),
    onSettled: invalidate,
  });
}

export function usePlugins() {
  return useQuery<{ plugins: PluginSummary[] }>({
    queryKey: queryKeys.plugins,
    queryFn: () => apiFetch<{ plugins: PluginSummary[] }>("/plugins"),
    ...defaultQueryOptions,
    staleTime: 60_000,
  });
}

export function useAttackModules() {
  return useQuery<AttackModulesResponse>({
    queryKey: ["attack", "modules"],
    queryFn: () => apiFetch<AttackModulesResponse>("/attack/modules"),
    ...defaultQueryOptions,
    staleTime: 60_000,
  });
}

export function useGoals() {
  return useQuery<GoalsResponse>({
    queryKey: queryKeys.goals,
    queryFn: () => apiFetch<GoalsResponse>("/goals"),
    ...defaultQueryOptions,
    staleTime: Infinity,
  });
}

export function useCreateGoal() {
  const qc = useQueryClient();
  return useMutation<CustomGoal, ApiError, { name: string; objective: string }>({
    mutationFn: (body) => apiFetch<CustomGoal>("/goals", { method: "POST", body }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: queryKeys.goals });
    },
  });
}

export function useUpdateGoal() {
  const qc = useQueryClient();
  return useMutation<CustomGoal, ApiError, { id: string; name: string; objective: string }>({
    mutationFn: ({ id, name, objective }) =>
      apiFetch<CustomGoal>(`/goals/${encodeURIComponent(id)}`, {
        method: "PATCH",
        body: { name, objective },
      }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: queryKeys.goals });
    },
  });
}

export function useDeleteGoal() {
  const qc = useQueryClient();
  return useMutation<{ deleted: boolean; id: string }, ApiError, string>({
    mutationFn: (id) => apiFetch<{ deleted: boolean; id: string }>(`/goals/${encodeURIComponent(id)}`, { method: "DELETE" }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: queryKeys.goals });
    },
  });
}

export function useSkills() {
  return useQuery<{ skills: SkillSummary[]; error?: string }>({
    queryKey: queryKeys.skills,
    queryFn: () => apiFetch<{ skills: SkillSummary[]; error?: string }>("/skills"),
    ...defaultQueryOptions,
    staleTime: 60_000,
  });
}

export function useSkillSearch(q: string, enabled = true) {
  const [debouncedQ, setDebouncedQ] = useState(q);
  useEffect(() => {
    const timer = setTimeout(() => setDebouncedQ(q), 250);
    return () => clearTimeout(timer);
  }, [q]);

  return useQuery<{ results: SkillSearchResult[] }>({
    queryKey: queryKeys.skillsSearch(debouncedQ),
    queryFn: () => apiFetch<{ results: SkillSearchResult[] }>(`/skills/search?q=${encodeURIComponent(debouncedQ)}`),
    ...defaultQueryOptions,
    enabled: enabled && debouncedQ.trim().length > 0,
    staleTime: 60_000,
  });
}

export function useSkillDetail(name: string | null) {
  return useQuery<SkillDetail>({
    queryKey: queryKeys.skill(name ?? ""),
    queryFn: () => apiFetch<SkillDetail>(`/skills/${encodeURIComponent(name as string)}`),
    ...defaultQueryOptions,
    enabled: !!name,
  });
}

export function useInstallSkill() {
  const qc = useQueryClient();
  return useMutation<SkillInstallResponse, ApiError, SkillInstallRequest>({
    mutationFn: (body) => apiFetch<SkillInstallResponse>("/skills", { method: "POST", body }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: queryKeys.skills });
    },
  });
}

export function useRemoveSkill() {
  const qc = useQueryClient();
  return useMutation<SkillRemoveResponse, ApiError, string>({
    mutationFn: (name) =>
      apiFetch<SkillRemoveResponse>(`/skills/${encodeURIComponent(name)}`, { method: "DELETE" }),
    onSuccess: (_data, name) => {
      void qc.invalidateQueries({ queryKey: queryKeys.skills });
      void qc.removeQueries({ queryKey: queryKeys.skill(name) });
    },
  });
}

export function useDiagnostics() {
  const useMut = useMutation<DiagnosticsResponse, ApiError, "doctor" | "self-test">;
  return useMut({
    mutationFn: (kind) =>
      apiFetch<DiagnosticsResponse>(`/diagnostics/${kind}`, { method: "POST", body: {} }),
  });
}

export function useResetSystem() {
  const qc = useQueryClient();
  return useMutation<
    { status: string; runs_deleted: number; removed: string[] },
    ApiError,
    void
  >({
    mutationFn: () => apiFetch<{ status: string; runs_deleted: number; removed: string[] }>(
      "/system/reset",
      { method: "POST", body: {} },
    ),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["runs"] });
      void qc.invalidateQueries({ queryKey: queryKeys.telemetry });
      void qc.invalidateQueries({ queryKey: queryKeys.memory });
    },
  });
}

export function useRuns(limit = 50, offset = 0, sort: string = "created_desc", q = "", state = "") {
  return useQuery<RunListResponse>({
    queryKey: queryKeys.runs(limit, offset, sort, q, state),
    queryFn: () => {
      const params = new URLSearchParams({ limit: String(limit), offset: String(offset), sort });
      if (q) params.set("q", q);
      if (state) params.set("state", state);
      return apiFetch<RunListResponse>(`/runs?${params.toString()}`);
    },
    ...defaultQueryOptions,
    // Poll fast only while at least one run is in an active state; when every
    // run is terminal, back off to a slow cadence so an idle dashboard is not
    // hammering the API every 5s forever.
    refetchInterval: (query) => {
      const rows: RunListRow[] | undefined = query.state.data?.runs;
      const hasActive = !!rows?.some((r) => isActiveState(r.state));
      return hasActive ? 5_000 : 60_000;
    },
    placeholderData: keepPreviousData,
  });
}

export function useRun(runId: string | null | undefined) {
  return useQuery<RunDetail>({
    queryKey: queryKeys.run(runId ?? ""),
    queryFn: () => apiFetch<RunDetail>(`/runs/${encodeURIComponent(runId as string)}`),
    ...defaultQueryOptions,
    enabled: !!runId,
    refetchInterval: (query) => {
      const data = query.state.data;
      if (!data) return 1_000;
      // ``preparing`` is the run-creation startup window — poll fast so the
      // wizard's startup panel reflects the transition promptly.
      if (data.state === "preparing") return 1_000;
      if (data.state === "running" || data.state === "queued" || data.state === "cancelling") {
        return 5_000;
      }
      return false;
    },
  });
}

export function useCreateRun() {
  const qc = useQueryClient();
  return useMutation<CreateRunResponse, ApiError, RunCreateRequest>({
    mutationFn: (body) => apiFetch<CreateRunResponse>("/runs", { method: "POST", body }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["runs"] });
    },
  });
}

export function useCancelRun() {
  const qc = useQueryClient();
  return useMutation<{ run_id: string; state: string }, ApiError, string>({
    mutationFn: (runId) =>
      apiFetch<{ run_id: string; state: string }>(`/runs/${encodeURIComponent(runId)}/cancel`, {
        method: "POST",
        body: {},
      }),
    onSuccess: (_data, runId) => {
      void qc.invalidateQueries({ queryKey: queryKeys.run(runId) });
      void qc.invalidateQueries({ queryKey: ["runs"] });
    },
  });
}

export function useResumeRun() {
  const qc = useQueryClient();
  return useMutation<ResumeRunResponse, ApiError, string>({
    mutationFn: (runId) =>
      apiFetch<ResumeRunResponse>(`/runs/${encodeURIComponent(runId)}/resume`, { method: "POST", body: {} }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["runs"] });
    },
  });
}

export function useDeleteRun() {
  const qc = useQueryClient();
  return useMutation<DeleteRunResponse, ApiError, { runId: string; purge?: boolean }>({
    mutationFn: ({ runId, purge }) =>
      apiFetch<DeleteRunResponse>(
        `/runs/${encodeURIComponent(runId)}?purge=${purge ? "true" : "false"}`,
        { method: "DELETE" },
      ),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["runs"] });
    },
  });
}

export function useRestoreDemo() {
  const qc = useQueryClient();
  return useMutation<{ run_id: string; restored: boolean }, ApiError, void>({
    mutationFn: () => apiFetch<{ run_id: string; restored: boolean }>("/runs/demo/restore", { method: "POST", body: {} }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["runs"] });
    },
  });
}

export function useRetitleRun() {
  const qc = useQueryClient();
  return useMutation<
    { run_id: string; title: string; regenerated: boolean },
    ApiError,
    { runId: string; title?: string; regen?: boolean }
  >({
    mutationFn: ({ runId, title, regen }) =>
      apiFetch<{ run_id: string; title: string; regenerated: boolean }>(
        `/runs/${encodeURIComponent(runId)}/title`,
        { method: "POST", body: { title: title ?? null, regen: !!regen } },
      ),
    onSuccess: (_data, vars) => {
      void qc.invalidateQueries({ queryKey: queryKeys.run(vars.runId) });
      void qc.invalidateQueries({ queryKey: ["runs"] });
    },
  });
}

export function useDecisions(runId: string | null | undefined) {
  return useQuery<{ decisions: DecisionListRow[] }>({
    queryKey: queryKeys.runDecisions(runId ?? ""),
    queryFn: () => apiFetch<{ decisions: DecisionListRow[] }>(`/runs/${encodeURIComponent(runId as string)}/decisions`),
    ...defaultQueryOptions,
    enabled: !!runId,
    refetchInterval: (query) => {
      const data = query.state.data;
      if (!data) return 10_000;
      const hasPending = data.decisions.some((d) => d.status === "pending");
      return hasPending ? 5_000 : false;
    },
  });
}

export function useDecision(runId: string | null, decisionId: string | null) {
  return useQuery<DecisionOut>({
    queryKey: queryKeys.decision(runId ?? "", decisionId ?? ""),
    queryFn: () =>
      apiFetch<DecisionOut>(
        `/runs/${encodeURIComponent(runId as string)}/decisions/${encodeURIComponent(decisionId as string)}`,
      ),
    ...defaultQueryOptions,
    enabled: !!runId && !!decisionId,
  });
}

export function useAnswerDecision(runId: string) {
  const qc = useQueryClient();
  return useMutation<DecisionAnswerResponse, ApiError, { decisionId: string; answer: string }>({
    mutationFn: ({ decisionId, answer }) =>
      apiFetch<DecisionAnswerResponse>(
        `/runs/${encodeURIComponent(runId)}/decisions/${encodeURIComponent(decisionId)}`,
        { method: "POST", body: { answer } },
      ),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: queryKeys.runDecisions(runId) });
      void qc.invalidateQueries({ queryKey: queryKeys.run(runId) });
      void qc.invalidateQueries({ queryKey: ["runs"] });
    },
  });
}

export function useRunTools(runId: string | null | undefined, enabled = true) {
  return useQuery<ToolsResponse>({
    queryKey: queryKeys.runTools(runId ?? ""),
    queryFn: () => apiFetch<ToolsResponse>(`/runs/${encodeURIComponent(runId as string)}/tools`),
    ...defaultQueryOptions,
    enabled: !!runId && enabled,
    staleTime: 15_000,
  });
}

export function useCallTool(runId: string) {
  return useMutation<ToolCallResponse, ApiError, { tool: string; arguments: Record<string, unknown> }>({
    mutationFn: ({ tool, arguments: args }) =>
      apiFetch<ToolCallResponse>(
        `/runs/${encodeURIComponent(runId)}/tools/${encodeURIComponent(tool)}/calls`,
        { method: "POST", body: { arguments: args } as ToolCallRequest },
      ),
  });
}

export function useArtifacts(runId: string | null | undefined) {
  const qc = useQueryClient();
  return useQuery<ArtifactListResponse>({
    queryKey: queryKeys.runArtifacts(runId ?? ""),
    queryFn: () => apiFetch<ArtifactListResponse>(`/runs/${encodeURIComponent(runId as string)}/artifacts`),
    ...defaultQueryOptions,
    enabled: !!runId,
    // Poll artifacts only while the run is active (artifacts appear as the run
    // progresses). Once the run reaches a terminal state the artifact set is
    // frozen, so stop polling. The run state is read from the run-detail query
    // cache so this hook needs no extra prop.
    refetchInterval: () => {
      if (!runId) return false;
      const run = qc.getQueryData<RunDetail>(queryKeys.run(runId));
      if (!run || isActiveState(run.state)) return 30_000;
      return false;
    },
  });
}

export function useAudit(runId: string | null | undefined, enabled = true) {
  return useQuery<AuditResponse>({
    queryKey: queryKeys.runAudit(runId ?? ""),
    queryFn: () => apiFetch<AuditResponse>(`/runs/${encodeURIComponent(runId as string)}/audit`),
    ...defaultQueryOptions,
    enabled: !!runId && enabled,
  });
}

export function useSwarmState(runId: string | null | undefined, enabled = true, refetchInterval: number | false = false) {
  return useQuery<SwarmStateResponse>({
    queryKey: queryKeys.runSwarm(runId ?? ""),
    queryFn: () => apiFetch<SwarmStateResponse>(`/runs/${encodeURIComponent(runId as string)}/swarm`),
    ...defaultQueryOptions,
    enabled: !!runId && enabled,
    refetchInterval,
    retry: (count, error) => {
      if (error instanceof ApiError && error.isNotFound) return false;
      return DEFAULT_RETRY(count, error);
    },
  });
}

export function useCampaignState(runId: string | null | undefined, enabled = true, refetchInterval: number | false = false) {
  return useQuery<CampaignStateResponse>({
    queryKey: queryKeys.runCampaign(runId ?? ""),
    queryFn: () => apiFetch<CampaignStateResponse>(`/runs/${encodeURIComponent(runId as string)}/campaign`),
    ...defaultQueryOptions,
    enabled: !!runId && enabled,
    refetchInterval,
    retry: (count, error) => {
      if (error instanceof ApiError && error.isNotFound) return false;
      return DEFAULT_RETRY(count, error);
    },
  });
}

export function useRunLog(
  runId: string | null,
  name: string,
  tail: number,
  attemptId: string,
  targetIp: string,
  enabled = true,
) {
  return useQuery<LogResponse>({
    queryKey: queryKeys.runLog(runId ?? "", name, tail, attemptId, targetIp),
    queryFn: () => {
      const params = new URLSearchParams({ tail: String(tail) });
      if (attemptId) params.set("attempt_id", attemptId);
      if (targetIp) params.set("target_ip", targetIp);
      return apiFetch<LogResponse>(
        `/runs/${encodeURIComponent(runId as string)}/logs/${encodeURIComponent(name)}?${params.toString()}`,
      );
    },
    ...defaultQueryOptions,
    enabled: !!runId && !!name && enabled,
  });
}

export function useCredentials(runId: string | null | undefined) {
  return useQuery<CredentialsResponse>({
    queryKey: queryKeys.runCredentials(runId ?? ""),
    queryFn: () => apiFetch<CredentialsResponse>(`/runs/${encodeURIComponent(runId as string)}/credentials`),
    ...defaultQueryOptions,
    enabled: !!runId,
  });
}

export function useRevealCredential(runId: string) {
  const qc = useQueryClient();
  return useMutation<CredentialRevealResponse, ApiError, number>({
    mutationFn: (index) =>
      apiFetch<CredentialRevealResponse>(
        `/runs/${encodeURIComponent(runId)}/credentials/${index}/reveal`,
        { method: "POST", body: {} },
      ),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: queryKeys.runCredentials(runId) });
    },
  });
}

export function useConfirmCredential(runId: string) {
  const qc = useQueryClient();
  return useMutation<unknown, ApiError, number>({
    mutationFn: (index) =>
      apiFetch<unknown>(
        `/runs/${encodeURIComponent(runId)}/credentials/${index}/confirm`,
        { method: "POST", body: {} },
      ),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: queryKeys.runCredentials(runId) });
    },
  });
}

export function useLoot(runId: string | null | undefined) {
  return useQuery<LootResponse>({
    queryKey: queryKeys.runLoot(runId ?? ""),
    queryFn: () => apiFetch<LootResponse>(`/runs/${encodeURIComponent(runId as string)}/loot`),
    ...defaultQueryOptions,
    enabled: !!runId,
  });
}

export function useWorkspace(runId: string | null | undefined) {
  return useQuery<WorkspaceListResponse>({
    queryKey: queryKeys.runWorkspace(runId ?? ""),
    queryFn: () => apiFetch<WorkspaceListResponse>(`/runs/${encodeURIComponent(runId as string)}/workspace`),
    ...defaultQueryOptions,
    enabled: !!runId,
  });
}

// ponytail: no bare href builders (never ?token=) — use the Bearer blob fetchers below.
export function useFetchWorkspaceFile(runId: string) {
  return useMutation<Blob, ApiError, string>({
    mutationFn: (path) =>
      apiFetch<Blob>(
        `/runs/${encodeURIComponent(runId)}/workspace/${path.split("/").map(encodeURIComponent).join("/")}`,
        { raw: true },
      ),
  });
}

export function useFetchArtifactBlob(runId: string) {
  return useMutation<Blob, ApiError, string>({
    mutationFn: (name) =>
      apiFetch<Blob>(
        `/runs/${encodeURIComponent(runId)}/artifacts/${name.split("/").map(encodeURIComponent).join("/")}`,
        { raw: true },
      ),
  });
}

export function useRunGraph(runId: string | null | undefined, enabled = true) {
  return useQuery<RunGraphResponse>({
    queryKey: queryKeys.runGraph(runId ?? ""),
    queryFn: () => apiFetch<RunGraphResponse>(`/runs/${encodeURIComponent(runId as string)}/graph`),
    ...defaultQueryOptions,
    enabled: !!runId && enabled,
    retry: (count, error) => {
      // 404 = route disabled (api.graph_route=false) or run has no graph yet;
      // don't retry — just render the empty state.
      if (error instanceof ApiError && error.isNotFound) return false;
      return DEFAULT_RETRY(count, error);
    },
  });
}

export function useWitness(runId: string | null | undefined, enabled = true) {
  return useQuery<WitnessResponse>({
    queryKey: queryKeys.runWitness(runId ?? ""),
    queryFn: () => apiFetch<WitnessResponse>(`/runs/${encodeURIComponent(runId as string)}/witness`),
    ...defaultQueryOptions,
    enabled: !!runId && enabled,
    retry: (count, error) => {
      // 404 = witness feature off / no witness.jsonl yet; don't retry.
      if (error instanceof ApiError && error.isNotFound) return false;
      return DEFAULT_RETRY(count, error);
    },
  });
}

/** HITL evidence loop: findings awaiting human review (Evidence tab).
 * Polls while the run is active (new proposals arrive mid-run); the decide
 * mutation invalidates immediately so Approve/Reject feels live. */
export function useProposed(runId: string | null | undefined, enabled = true) {
  const qc = useQueryClient();
  return useQuery<ProposedResponse>({
    queryKey: queryKeys.runProposed(runId ?? ""),
    queryFn: () => apiFetch<ProposedResponse>(`/runs/${encodeURIComponent(runId as string)}/proposed`),
    ...defaultQueryOptions,
    enabled: !!runId && enabled,
    refetchInterval: () => {
      if (!runId) return false;
      const run = qc.getQueryData<RunDetail>(queryKeys.run(runId));
      if (!run || isActiveState(run.state)) return 10_000;
      return false;
    },
  });
}

export function useDecideFinding(runId: string) {
  const qc = useQueryClient();
  return useMutation<DecideFindingResponse, ApiError, { findingId: string; decision: string; note?: string }>({
    mutationFn: ({ findingId, decision, note }) =>
      apiFetch<DecideFindingResponse>(`/runs/${encodeURIComponent(runId)}/decide`, {
        method: "POST",
        body: { finding_id: findingId, decision, note: note ?? "" },
      }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: queryKeys.runProposed(runId) });
      void qc.invalidateQueries({ queryKey: queryKeys.run(runId) });
    },
  });
}

// ── Connections (operator access channels) ─────────────────────────────────
// Backed by ConnectionManager (tools/operator_connection/manager.py).
// The manager is the single source of truth; the WebUI never parses JSON directly.

export function useConnections(params?: { status?: string; target?: string }) {
  return useQuery<ConnectionsListResponse>({
    queryKey: params?.status || params?.target ? ["connections", params] as const : queryKeys.connections,
    queryFn: () => {
      const q = new URLSearchParams();
      if (params?.status) q.set("status", params.status);
      if (params?.target) q.set("target", params.target);
      const suffix = q.toString() ? `?${q.toString()}` : "";
      return apiFetch<ConnectionsListResponse>(`/connections${suffix}`);
    },
    ...defaultQueryOptions,
    staleTime: 8_000,
    refetchInterval: (query) => {
      const data = query.state.data as ConnectionsListResponse | undefined;
      if (!data) return 12_000;
      const hasActive = data.connections.some((c) => c.status === "active");
      const hasStale = data.connections.some((c) => c.status === "stale");
      if (hasActive) return 12_000;
      if (hasStale) return 15_000;
      // No active/stale — slow poll for sidebar badge updates
      return 30_000;
    },
    refetchOnWindowFocus: false,
  });
}

export function useConnection(connectionId: string | null | undefined, enabled = true) {
  return useQuery<OperatorConnection>({
    queryKey: queryKeys.connection(connectionId ?? ""),
    queryFn: () => apiFetch<OperatorConnection>(`/connections/${encodeURIComponent(connectionId as string)}`),
    ...defaultQueryOptions,
    enabled: !!connectionId && enabled,
    refetchInterval: (query) => {
      const data = query.state.data as OperatorConnection | undefined;
      if (!data) return 10_000;
      if (data.status === "removed") return false;
      if (data.status === "active" || data.status === "stale") return 10_000;
      return 30_000;
    },
  });
}

export function useConnectionListener(connectionId: string | null | undefined, enabled = true) {
  return useQuery<ConnectionListenerResponse>({
    queryKey: queryKeys.connectionListener(connectionId ?? ""),
    queryFn: () =>
      apiFetch<ConnectionListenerResponse>(`/connections/${encodeURIComponent(connectionId as string)}/listener`),
    ...defaultQueryOptions,
    enabled: !!connectionId && enabled,
    staleTime: 2_000,
    refetchInterval: enabled ? 3_000 : false,
    retry: (count, error) => {
      if (error instanceof ApiError && error.isNotFound) return false;
      return DEFAULT_RETRY(count, error);
    },
  });
}

export function useCheckConnection() {
  const qc = useQueryClient();
  return useMutation<OperatorConnection, ApiError, string>({
    mutationFn: (connectionId) =>
      apiFetch<OperatorConnection>(`/connections/${encodeURIComponent(connectionId)}/check`, {
        method: "POST",
        body: {},
      }),
    onSuccess: (data) => {
      qc.setQueryData(queryKeys.connection(data.connection_id), data);
      void qc.invalidateQueries({ queryKey: queryKeys.connections });
      void qc.invalidateQueries({ queryKey: queryKeys.connection(data.connection_id) });
      void qc.invalidateQueries({ queryKey: queryKeys.connectionListener(data.connection_id) });
    },
  });
}

export function useRemoveConnection() {
  const qc = useQueryClient();
  return useMutation<RemoveConnectionResponse, ApiError, string>({
    mutationFn: (connectionId) =>
      apiFetch<RemoveConnectionResponse>(`/connections/${encodeURIComponent(connectionId)}/remove`, {
        method: "POST",
        body: {},
      }),
    onSuccess: (data) => {
      qc.setQueryData(queryKeys.connection(data.connection.connection_id), data.connection);
      void qc.invalidateQueries({ queryKey: queryKeys.connections });
      void qc.invalidateQueries({ queryKey: queryKeys.connection(data.connection.connection_id) });
    },
  });
}
