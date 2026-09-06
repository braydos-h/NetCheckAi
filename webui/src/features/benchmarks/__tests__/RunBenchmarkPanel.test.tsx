// @vitest-environment jsdom
// BreachPilot by @braydos-h — https://github.com/braydos-h/BreachPilot
// Repaired-behaviour tests for the run-benchmark panel: scenario auto-load,
// exact selection semantics (empty selection = whole suite) and surfaced
// scenario-load failures.
import { describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { RunBenchmarkPanel } from "@/features/benchmarks/RunBenchmarkPanel";
import type { ScenarioInfo } from "@/features/benchmarks/types";

const fetchSuiteScenarios = vi.fn();
const startBenchmarkRun = vi.fn();

vi.mock("@/features/benchmarks/api", () => ({
  fetchSuiteScenarios: (...args: unknown[]) => fetchSuiteScenarios(...args),
  startBenchmarkRun: (...args: unknown[]) => startBenchmarkRun(...args),
}));

vi.mock("@/components/ProviderSetup", () => ({
  useDefaultModel: () => "glm",
  useModelOptions: () => ["glm", "glm-mini"],
}));

const SCENARIOS: ScenarioInfo[] = [
  {
    suite: "xben",
    scenario_id: "xben-dvwa",
    benchmark_id: "xben/xben-dvwa",
    name: "DVWA",
    description: "",
    target_type: "docker",
    target_image: "dvwa:latest",
    target_host: "127.0.0.1",
    target_ports: [8080],
    goal: "initial_access",
    tags: ["web"],
    difficulty: "easy",
    reset_strategy: "recreate",
    timeout_seconds: 1800,
    expected_flags: [],
    oracle_flag_count: 1,
    source_manifest: "",
  },
  {
    ...{} as ScenarioInfo,
    suite: "xben",
    scenario_id: "xben-juice-shop",
    benchmark_id: "xben/xben-juice-shop",
    name: "Juice Shop",
    description: "",
    target_type: "docker",
    target_image: "juice-shop:latest",
    target_host: "127.0.0.1",
    target_ports: [3000],
    goal: "initial_access",
    tags: ["web", "owasp"],
    difficulty: "medium",
    reset_strategy: "recreate",
    timeout_seconds: 1800,
    expected_flags: [],
    oracle_flag_count: 1,
    source_manifest: "",
  },
];

function renderPanel() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <RunBenchmarkPanel
          suites={[{ suite_id: "xben", scenarios: 2 }]}
          active={{ run_id: null, state: "idle", error: "" }}
          defaultModel="glm"
        />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("RunBenchmarkPanel", () => {
  it("auto-loads the scenarios of the initially selected suite", async () => {
    fetchSuiteScenarios.mockResolvedValue({ suite: "xben", scenarios: SCENARIOS });
    renderPanel();
    await waitFor(() => {
      expect(screen.getByText("xben-dvwa")).toBeInTheDocument();
    });
    expect(fetchSuiteScenarios).toHaveBeenCalledWith("xben");
    expect(screen.getByText("xben-juice-shop")).toBeInTheDocument();
  });

  it("sends exactly the checked scenario ids and no tags when starting a run", async () => {
    const user = userEvent.setup();
    fetchSuiteScenarios.mockResolvedValue({ suite: "xben", scenarios: SCENARIOS });
    startBenchmarkRun.mockResolvedValue({ run_id: "r9", state: "running" });
    renderPanel();
    await waitFor(() => {
      expect(screen.getByText("xben-dvwa")).toBeInTheDocument();
    });
    await user.click(screen.getByLabelText(/xben-dvwa/));
    await user.click(screen.getByTestId("run-benchmark-button"));
    await waitFor(() => {
      expect(startBenchmarkRun).toHaveBeenCalledTimes(1);
    });
    const body = startBenchmarkRun.mock.calls[0]![0] as Record<string, unknown>;
    expect(body).toEqual(expect.objectContaining({ suite: "xben", scenarios: ["xben-dvwa"], trials: 1 }));
    // Tag chips are view filters only — they must never leak into the request.
    expect("tags" in body).toBe(false);
  });

  it("surfaces scenario-load failures and recovers via Retry", async () => {
    const user = userEvent.setup();
    fetchSuiteScenarios.mockRejectedValueOnce(new Error("boom"));
    fetchSuiteScenarios.mockResolvedValue({ suite: "xben", scenarios: SCENARIOS });
    renderPanel();
    await waitFor(() => {
      expect(screen.getByText(/Failed to load scenarios/)).toBeInTheDocument();
    });
    expect(screen.getByText(/boom/)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: /Retry/ }));
    await waitFor(() => {
      expect(screen.getByText("xben-dvwa")).toBeInTheDocument();
    });
    expect(screen.queryByText(/Failed to load scenarios/)).not.toBeInTheDocument();
  });
});
