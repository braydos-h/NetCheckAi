// @vitest-environment jsdom
// BreachPilot by @braydos-h — https://github.com/braydos-h/BreachPilot
// Repaired-behaviour tests for the benchmark run detail page: interrupted
// (orphaned) runs are detected instead of polling "live" forever, and live
// per-trial progress is merged from the scenarios endpoint.
import { describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BenchmarkRunPage } from "@/routes/BenchmarkRunPage";
import type { RunDetail, Trial } from "@/features/benchmarks/types";

vi.mock("@/api/hooks", () => ({
  useModels: () => ({ data: { default_alias: "glm" } }),
}));

vi.mock("@/hooks/use-toast", () => ({
  toast: vi.fn(),
}));

const fetchRun = vi.fn();
const fetchOverview = vi.fn();
const fetchRunEvents = vi.fn();
const fetchRunScenarios = vi.fn();
const cancelBenchmarkRun = vi.fn();
const saveBaseline = vi.fn();

vi.mock("@/features/benchmarks/api", () => ({
  fetchRun: (...args: unknown[]) => fetchRun(...args),
  fetchOverview: (...args: unknown[]) => fetchOverview(...args),
  fetchRunEvents: (...args: unknown[]) => fetchRunEvents(...args),
  fetchRunScenarios: (...args: unknown[]) => fetchRunScenarios(...args),
  cancelBenchmarkRun: (...args: unknown[]) => cancelBenchmarkRun(...args),
  saveBaseline: (...args: unknown[]) => saveBaseline(...args),
}));

function makeTrial(overrides: Partial<Trial>): Trial {
  return {
    run_id: "r1",
    suite: "xben",
    scenario_id: "xben-dvwa",
    trial_index: 0,
    trial_id: "xben-dvwa#t1",
    status: "VERIFIED",
    agent_claimed_success: true,
    oracle_verified_success: true,
    false_positive: false,
    false_negative: false,
    failure_category: "UNKNOWN",
    failure_detail: "",
    started_at: "2026-08-30T00:00:00Z",
    ended_at: "2026-08-30T00:10:00Z",
    duration_seconds: 600,
    model_calls: 5,
    tool_calls: 4,
    total_tokens: 100,
    estimated_cost: null,
    claimed_summary: "",
    flags: [],
    flags_captured: 1,
    flags_total: 1,
    evidence_refs: [],
    audit_path: "",
    workspace: "",
    errors: [],
    sandbox: {
      enabled: true,
      required: true,
      image: "breachpilot-sandbox:latest",
      image_digest: "unknown",
      container_id: "c1",
      network_policy_fingerprint: "",
      authorized_destinations: [],
      blocked_events: 0,
      failures: 0,
      last_error: "",
    },
    target: {
      host: "127.0.0.1",
      ports: [8080],
      image: "unknown",
      image_digest: "unknown",
      container_id: "t1",
      snapshot_id: "",
      reset_strategy: "recreate",
    },
    telemetry: {
      model_calls: 5,
      total_tokens: 100,
      prompt_tokens: 60,
      completion_tokens: 40,
      estimated_cost: null,
      tool_calls: 4,
      tool_errors: 0,
      sandbox_blocked_actions: 0,
    },
    ...overrides,
  } as Trial;
}

const BASE_RUN: RunDetail = {
  run_id: "r1",
  suite: "xben",
  status: "running",
  config: {
    suite: "xben",
    scenario_ids: ["xben-dvwa", "xben-juice-shop"],
    tags: [],
    trials: 1,
    timeout_seconds: 1800,
    model_alias: "",
    reasoning_profile: "",
    sandbox_required: true,
    save_baseline: false,
    check_regression: false,
    output_dir: "",
  },
  environment: {
    breachpilot_version: "0.49.12",
    git_sha: "abc",
    git_dirty: false,
    git_branch: "main",
    model_provider: "ollama",
    model_alias: "glm",
    model_id: "glm",
    model_version: "v1",
    reasoning_config: {},
    temperature: null,
    config_hash: "h1",
    benchmark_config_hash: "h2",
    sandbox_image: "breachpilot-sandbox:latest",
    sandbox_image_digest: "unknown",
    sandbox_enabled: true,
    sandbox_required: true,
    target_images: {},
    platform: "test",
    python_version: "3.11",
  },
  scenario_ids: ["xben-dvwa", "xben-juice-shop"],
  trials: [],
  summary: null,
};

function renderRunPage() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={["/benchmarks/r1"]}>
        <Routes>
          <Route path="/benchmarks/:runId" element={<BenchmarkRunPage />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("BenchmarkRunPage", () => {
  it("detects an interrupted (orphaned) run instead of polling live forever", async () => {
    fetchRun.mockResolvedValue(BASE_RUN);
    fetchOverview.mockResolvedValue({
      suites: [],
      runs: [],
      active: { run_id: null, state: "idle", error: "" },
      baseline: { exists: false, path: "reports/benchmarks/baseline.json" },
    });
    fetchRunEvents.mockResolvedValue({ run_id: "r1", events: [], latest_sequence: 0 });
    fetchRunScenarios.mockResolvedValue({ run_id: "r1", scenarios: [makeTrial({})] });

    renderRunPage();

    await waitFor(() => {
      expect(screen.getByTestId("benchmark-interrupted-banner")).toBeInTheDocument();
    });
    expect(screen.getByText("Interrupted")).toBeInTheDocument();
    // The live pill (present only on genuinely active runs) must not render.
    expect(screen.queryByText(/live ·/)).not.toBeInTheDocument();
    // Progress merges the live trial from the scenarios endpoint: 1 of 2 done.
    await waitFor(() => {
      expect(screen.getByText("1/2")).toBeInTheDocument();
    });
  });
  it("renders a completed run with its summary and no interruption banner", async () => {    fetchRun.mockResolvedValue({
      ...BASE_RUN,
      status: "completed",
      trials: [makeTrial({})],
      summary: {
        run_id: "r1",
        suite: "xben",
        timestamp: "2026-08-30T01:00:00Z",
        trials_total: 2,
        trials_completed: 2,
        verified_success_rate: 0.5,
        solved: 1,
        false_positive_rate: 0,
        false_negative_rate: 0,
        median_solve_time: 600,
        mean_solve_time: 600,
        median_tool_actions: 4,
        mean_tool_actions: 4,
        median_model_calls: 5,
        total_tokens: 100,
        estimated_cost: null,
        time_to_first_verified_success: 600,
        sandbox_blocked_actions: 0,
        infra_error_count: 0,
        timeout_count: 0,
        failure_categories: {},
        scenarios: [],
      },
    });
    fetchOverview.mockResolvedValue({
      suites: [],
      runs: [],
      active: { run_id: null, state: "idle", error: "" },
      baseline: { exists: false, path: "reports/benchmarks/baseline.json" },
    });
    fetchRunEvents.mockResolvedValue({ run_id: "r1", events: [], latest_sequence: 0 });

    renderRunPage();

    await waitFor(() => {
      expect(screen.getByTestId("benchmark-metric-cards")).toBeInTheDocument();
    });
    expect(screen.getAllByText("50.0%").length).toBeGreaterThan(0);
    expect(screen.queryByTestId("benchmark-interrupted-banner")).not.toBeInTheDocument();
  });
  it("surfaces an unreachable-lab banner on instant-finish provision failures", async () => {
    const provisionTrial = makeTrial({
      status: "INFRASTRUCTURE_ERROR",
      agent_claimed_success: false,
      oracle_verified_success: false,
      failure_category: "TARGET_PROVISION_FAILED",
      failure_detail: "target 127.0.0.1 refused all declared ports [8080] -- is the lab suite up?",
    });
    fetchRun.mockResolvedValue({
      ...BASE_RUN,
      status: "completed",
      trials: [provisionTrial, { ...provisionTrial, trial_id: "xben-juice-shop#t1", scenario_id: "xben-juice-shop" }],
      summary: {
        run_id: "r1",
        suite: "xben",
        timestamp: "2026-08-30T01:00:00Z",
        trials_total: 2,
        trials_completed: 0,
        verified_success_rate: 0,
        solved: 0,
        false_positive_rate: 0,
        false_negative_rate: 0,
        median_solve_time: null,
        mean_solve_time: null,
        median_tool_actions: null,
        mean_tool_actions: null,
        median_model_calls: null,
        total_tokens: 0,
        estimated_cost: null,
        time_to_first_verified_success: null,
        sandbox_blocked_actions: 0,
        infra_error_count: 2,
        timeout_count: 0,
        failure_categories: { TARGET_PROVISION_FAILED: 2 },
        scenarios: [],
      },
    });
    fetchOverview.mockResolvedValue({
      suites: [],
      runs: [],
      active: { run_id: null, state: "idle", error: "" },
      baseline: { exists: false, path: "reports/benchmarks/baseline.json" },
    });
    fetchRunEvents.mockResolvedValue({ run_id: "r1", events: [], latest_sequence: 0 });

    renderRunPage();

    await waitFor(() => {
      expect(screen.getByTestId("benchmark-infra-banner")).toBeInTheDocument();
    });
    expect(screen.getByText("Lab targets were unreachable")).toBeInTheDocument();
    expect(screen.getByText(/docker compose -f eval_targets\/docker-compose\.yml up -d/)).toBeInTheDocument();
    expect(screen.queryByTestId("benchmark-interrupted-banner")).not.toBeInTheDocument();
  });
});
