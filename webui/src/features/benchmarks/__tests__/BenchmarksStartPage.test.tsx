// @vitest-environment jsdom
// BreachPilot by @braydos-h — https://github.com/braydos-h/BreachPilot
import { describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BenchmarksStartPage } from "@/routes/BenchmarksStartPage";

vi.mock("@/api/hooks", () => ({
  useModels: () => ({ data: { default_alias: "glm" } }),
}));

vi.mock("@/components/ProviderSetup", () => ({
  useDefaultModel: () => "glm",
  useModelOptions: () => ["glm"],
}));

const fetchOverview = vi.fn();
vi.mock("@/features/benchmarks/api", () => ({
  fetchOverview: (...args: unknown[]) => fetchOverview(...args),
  fetchSuiteScenarios: vi.fn().mockResolvedValue({ suite: "xben", scenarios: [] }),
  startBenchmarkRun: vi.fn(),
}));

function renderPage() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={["/benchmarks/new"]}>
        <BenchmarksStartPage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

const OVERVIEW = {
  suites: [{ suite_id: "xben", scenarios: 4, tags: { web: 2 } }],
  runs: [],
  active: { run_id: null, state: "idle", error: "" },
  baseline: { exists: false, path: "reports/benchmarks/baseline.json" },
};

describe("BenchmarksStartPage", () => {
  it("renders the run panel with an idle baseline note", async () => {
    fetchOverview.mockResolvedValue(OVERVIEW);
    renderPage();
    await waitFor(() => {
      expect(screen.getByTestId("run-benchmark-panel")).toBeInTheDocument();
    });
    expect(screen.getByLabelText(/Benchmark suite/)).toBeInTheDocument();
    expect(screen.getByTestId("start-baseline-card")).toBeInTheDocument();
    expect(screen.getByText(/No baseline saved yet/)).toBeInTheDocument();
  });

  it("shows the baseline the regression check compares against", async () => {
    fetchOverview.mockResolvedValue({
      ...OVERVIEW,
      baseline: { exists: true, path: "reports/benchmarks/baseline.json", run_id: "run-0", verified_success_rate: 0.5, false_positive_rate: 0 },
    });
    renderPage();
    await waitFor(() => {
      expect(screen.getByRole("link", { name: "run-0" })).toBeInTheDocument();
    });
    expect(screen.getByText("50.0%")).toBeInTheDocument();
  });
});
