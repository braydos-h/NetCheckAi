// BreachPilot by @braydos-h — https://github.com/braydos-h/BreachPilot
// Types for the benchmark suite API (/api/v1/benchmarks/*).

export type TrialStatus =
  | "VERIFIED"
  | "FAILED"
  | "FALSE_POSITIVE"
  | "TIMEOUT"
  | "INFRASTRUCTURE_ERROR"
  | "SKIPPED";

export type FailureCategory =
  | "TARGET_PROVISION_FAILED"
  | "SANDBOX_FAILED"
  | "MODEL_FAILED"
  | "TIMEOUT"
  | "PLANNER_FAILURE"
  | "TOOL_FAILURE"
  | "VERIFICATION_FAILURE"
  | "FALSE_POSITIVE"
  | "NO_EXPLOIT_PATH"
  | "AGENT_ABORTED"
  | "TARGET_RESET_FAILED"
  | "UNKNOWN";

export interface SuiteInfo {
  suite_id: string;
  scenarios: number;
  invalid_manifests?: number;
  manifest_dir?: string;
  tags?: Record<string, number>;
}

export interface ScenarioInfo {
  suite: string;
  scenario_id: string;
  benchmark_id: string;
  name: string;
  description: string;
  target_type: string;
  target_image: string;
  target_host: string;
  target_ports: number[];
  goal: string;
  tags: string[];
  difficulty: string;
  reset_strategy: string;
  timeout_seconds: number;
  expected_flags: string[];
  oracle_flag_count: number;
  source_manifest: string;
}

export interface SandboxSnapshot {
  enabled: boolean;
  required: boolean;
  image: string;
  image_digest: string;
  container_id: string;
  network_policy_fingerprint: string;
  authorized_destinations: string[];
  blocked_events: number;
  failures: number;
  last_error: string;
}

export interface TargetSnapshot {
  host: string;
  ports: number[];
  image: string;
  image_digest: string;
  container_id: string;
  snapshot_id: string;
  reset_strategy: string;
}

export interface FlagCheckResult {
  flag_id: string;
  passed: boolean;
  detail: string;
  check: Record<string, unknown>;
}

export interface TrialTelemetry {
  model_calls: number;
  total_tokens: number;
  prompt_tokens: number;
  completion_tokens: number;
  estimated_cost: number | null;
  tool_calls: number;
  tool_errors: number;
  sandbox_blocked_actions: number;
}

export interface Trial {
  run_id: string;
  suite: string;
  scenario_id: string;
  trial_index: number;
  trial_id: string;
  status: TrialStatus;
  agent_claimed_success: boolean;
  oracle_verified_success: boolean;
  false_positive: boolean;
  false_negative: boolean;
  failure_category: FailureCategory;
  failure_detail: string;
  started_at: string;
  ended_at: string;
  duration_seconds: number;
  model_calls: number;
  tool_calls: number;
  total_tokens: number;
  estimated_cost: number | null;
  claimed_summary: string;
  flags: FlagCheckResult[];
  flags_captured: number;
  flags_total: number;
  evidence_refs: string[];
  audit_path: string;
  workspace: string;
  errors: string[];
  sandbox: SandboxSnapshot;
  target: TargetSnapshot;
  telemetry: TrialTelemetry;
}

export interface RunEnvironment {
  breachpilot_version: string;
  git_sha: string;
  git_dirty: boolean | null;
  git_branch: string;
  model_provider: string;
  model_alias: string;
  model_id: string;
  model_version: string;
  reasoning_config: Record<string, unknown>;
  temperature: number | null;
  config_hash: string;
  benchmark_config_hash: string;
  sandbox_image: string;
  sandbox_image_digest: string;
  sandbox_enabled: boolean;
  sandbox_required: boolean;
  target_images: Record<string, string>;
  platform: string;
  python_version: string;
}

export interface ScenarioSummary {
  scenario_id: string;
  name: string;
  difficulty: string;
  tags: string[];
  trials: number;
  verified: number;
  claimed: number;
  false_positives: number;
  false_negatives: number;
  timeouts: number;
  infra_errors: number;
  success_probability: number;
  success_variance: number;
  success_stddev: number;
  ci95_low: number | null;
  ci95_high: number | null;
  median_duration: number | null;
  mean_duration: number | null;
  median_actions: number | null;
  mean_actions: number | null;
  median_model_calls: number | null;
  total_tokens: number;
  estimated_cost: number | null;
  failure_categories: Record<string, number>;
}

export interface RunSummary {
  run_id: string;
  suite: string;
  timestamp: string;
  trials_total: number;
  trials_completed: number;
  verified_success_rate: number;
  solved: number;
  false_positive_rate: number;
  false_negative_rate: number;
  median_solve_time: number | null;
  mean_solve_time: number | null;
  median_tool_actions: number | null;
  mean_tool_actions: number | null;
  median_model_calls: number | null;
  total_tokens: number;
  estimated_cost: number | null;
  time_to_first_verified_success: number | null;
  sandbox_blocked_actions: number;
  infra_error_count: number;
  timeout_count: number;
  failure_categories: Record<string, number>;
  scenarios: ScenarioSummary[];
}

export interface RunConfig {
  suite: string;
  scenario_ids: string[];
  tags: string[];
  trials: number;
  timeout_seconds: number;
  model_alias: string;
  reasoning_profile: string;
  sandbox_required: boolean;
  save_baseline: boolean;
  check_regression: boolean;
  output_dir: string;
}

export interface ReplayManifest {
  run_id: string;
  suite: string;
  breachpilot_version: string;
  git_sha: string;
  git_dirty: boolean | null;
  git_branch: string;
  model_provider: string;
  model_alias: string;
  model_id: string;
  model_version: string;
  reasoning_config: Record<string, unknown>;
  temperature: number | null;
  config_hash: string;
  benchmark_config_hash: string;
  sandbox_image: string;
  sandbox_image_digest: string;
  sandbox_enabled: boolean;
  target_images: Record<string, string>;
  trials: number;
  replay_command: string;
}

export interface RunIndexRow {
  run_id: string;
  suite: string;
  status: string;
  timestamp: string;
  trials_total: number;
  solved: number;
  verified_success_rate: number;
  false_positive_rate: number;
  median_solve_time: number | null;
  estimated_cost: number | null;
  total_tokens: number;
}

export interface RunDetail {
  run_id: string;
  suite: string;
  status: string;
  config: RunConfig;
  environment: RunEnvironment;
  scenario_ids: string[];
  trials: Trial[];
  replay_manifest?: ReplayManifest;
  summary: RunSummary | null;
}

export interface BenchmarkEvent {
  sequence: number;
  timestamp: string;
  elapsed_seconds: number;
  run_id: string;
  type: string;
  level: string;
  trial_id: string;
  scenario_id: string;
  agent: string;
  tool: string;
  target: string;
  payload: Record<string, unknown>;
}

export interface BenchmarkRunRequest {
  suite: string;
  scenarios?: string[];
  tags?: string[];
  trials?: number;
  model?: string;
  reasoning?: string;
  sandbox_required?: boolean;
  timeout_seconds?: number;
  save_baseline?: boolean;
  check_regression?: boolean;
}

export interface ReadinessTarget {
  scenario_id: string;
  target_type: string;
  target_host: string;
  target_ports: number[];
  reachable: boolean;
  self_provisioned: boolean;
  detail: string;
}

export interface SuiteReadiness {
  suite: string;
  ready: boolean;
  lab_command: string;
  targets: ReadinessTarget[];
}

export interface ActiveRunStatus {
  run_id: string | null;
  state: string;
  error: string;
}

export interface BaselineMeta {
  exists: boolean;
  path: string;
  run_id?: string;
  suite?: string;
  timestamp?: string;
  trials_total?: number;
  verified_success_rate?: number;
  false_positive_rate?: number;
  median_solve_time?: number | null;
  estimated_cost?: number | null;
  scenarios?: Record<string, { success_probability: number; verified: number; trials: number }>;
}

export interface CompareMetricRow {
  metric: string;
  baseline: number | null;
  current: number | null;
  delta: number | null;
  direction: "improved" | "regressed" | "unchanged";
}

export interface CompareScenarioRow {
  scenario_id: string;
  baseline: number;
  current: number;
  delta: number;
  category: "newly_solved" | "regressed" | "still_solved" | "still_failing";
}

export interface RunComparison {
  run_a: { run_id: string; suite: string; summary: RunSummary };
  run_b: { run_id: string; suite: string; summary: RunSummary };
  comparison: {
    metrics: CompareMetricRow[];
    scenarios: CompareScenarioRow[];
    categories: Record<string, string[]>;
  };
}
