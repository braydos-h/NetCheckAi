// @vitest-environment jsdom
import { describe, expect, it, vi, beforeEach } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { Layout } from "@/components/Layout";

// ── module mocks ────────────────────────────────────────────────────────────

vi.mock("@/api/hooks", () => ({
  useRuns: vi.fn(),
  useConnections: vi.fn(),
  useModels: vi.fn(),
  useHostPlatform: vi.fn(),
}));

vi.mock("@/components/ProviderSetup", async () => {
  const actual = await vi.importActual<typeof import("@/components/ProviderSetup")>("@/components/ProviderSetup");
  return {
    ...actual,
    useProviderStatus: vi.fn(),
  };
});

vi.mock("@/lib/sessionTokens", async () => {
  const actual = await vi.importActual<typeof import("@/lib/sessionTokens")>("@/lib/sessionTokens");
  return {
    ...actual,
    useSessionTokens: vi.fn(),
  };
});

import { useConnections, useHostPlatform, useModels, useRuns } from "@/api/hooks";
import { useProviderStatus } from "@/components/ProviderSetup";
import { useSessionTokens } from "@/lib/sessionTokens";

const runsMock = vi.mocked(useRuns);
const connectionsMock = vi.mocked(useConnections);
const modelsMock = vi.mocked(useModels);
const hostPlatformMock = vi.mocked(useHostPlatform);
const providerStatusMock = vi.mocked(useProviderStatus);
const sessionTokensMock = vi.mocked(useSessionTokens);

function setup({ activeRuns = [] as Array<{ id: string; state: string; target: string | null }> } = {}) {
  runsMock.mockReturnValue({
    data: { runs: activeRuns, total: activeRuns.length },
    isLoading: false,
    error: null,
  } as never);
  connectionsMock.mockReturnValue({
    data: { active: 2, connections: [], total: 0, stale: 0, removed: 0, error: 0 },
    isLoading: false,
    error: null,
  } as never);
  modelsMock.mockReturnValue({
    data: { provider: "ollama", default_alias: "glm" },
    isLoading: false,
    error: null,
  } as never);
  hostPlatformMock.mockReturnValue({
    data: { platform: "linux" },
    isLoading: false,
    isError: false,
  } as never);
  providerStatusMock.mockReturnValue({
    provider: "ollama",
    label: "Ollama",
    online: true,
    source: "ollama",
    liveCount: 2,
    error: undefined,
    status: "online",
    statusText: "Online",
    isChecking: false,
  } as never);
  sessionTokensMock.mockReturnValue({
    sessionTokens: 8421,
    totalTokens: 8421,
    baseline: 0,
    isLoading: false,
    error: null,
  } as never);

  render(
    <MemoryRouter initialEntries={["/"]}>
      <Layout />
    </MemoryRouter>,
  );
}

beforeEach(() => {
  vi.clearAllMocks();
  sessionStorage.clear();
  // Vite injects __APP_VERSION__ at build time; provide it for the test env.
  vi.stubGlobal("__APP_VERSION__", "0.0.0-test");
});

describe("Layout mobile navigation", () => {
  it("renders the hamburger in the mobile header (desktop aside still present)", () => {
    setup();
    expect(screen.getByRole("button", { name: "Open navigation" })).toBeInTheDocument();
    // Desktop nav is in the DOM (hidden by CSS, not by JS).
    expect(screen.getByRole("navigation", { name: "Primary" })).toBeInTheDocument();
  });

  it("opens a drawer containing every nav item and the footer controls", async () => {
    const user = userEvent.setup();
    setup();
    await user.click(screen.getByRole("button", { name: "Open navigation" }));

    const drawer = screen.getByRole("dialog");
    for (const label of [
      "Home",
      "Sessions",
      "Connections",
      "Modules",
      "Goals",
      "Attack Graph",
      "Stats",
      "Skills",
      "Memory",
      "Settings",
      "Help",
    ]) {
      expect(within(drawer).getByRole("link", { name: new RegExp(`^${label}`) })).toBeInTheDocument();
    }
    // Footer controls live in the drawer too.
    expect(within(drawer).getByRole("button", { name: "Clear token" })).toBeInTheDocument();
  });

  it("clicking a nav link closes the drawer", async () => {
    const user = userEvent.setup();
    setup();
    await user.click(screen.getByRole("button", { name: "Open navigation" }));
    const drawer = screen.getByRole("dialog");
    await user.click(within(drawer).getByRole("link", { name: /^Sessions/ }));
    // Route change closes the drawer; Radix unmounts after the exit transition.
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
  });

  it("shows active-run rows in the drawer nav", async () => {
    const user = userEvent.setup();
    setup({
      activeRuns: [{ id: "run-abc123", state: "running", target: "10.0.0.50" }],
    });
    await user.click(screen.getByRole("button", { name: "Open navigation" }));
    const drawer = screen.getByRole("dialog");
    const runLink = within(drawer).getByRole("link", { name: /10\.0\.0\.50/ });
    expect(runLink).toHaveAttribute("href", "/runs/run-abc123");
  });
});

describe("Layout provider status (provider-aware)", () => {
  it("shows Ollama and does not mention another provider when ollama is active", () => {
    setup();
    // Provider name primary text
    expect(screen.getByText("Ollama")).toBeInTheDocument();
    expect(screen.getByText(/Online/)).toBeInTheDocument();
    // Must not mention OpenCode Go or ChatGPT when ollama active
    expect(screen.queryByText("OpenCode Go")).not.toBeInTheDocument();
    expect(screen.queryByText("ChatGPT")).not.toBeInTheDocument();
    // Old hardcoded string must be gone entirely
    expect(screen.queryByText("Ollama configured")).not.toBeInTheDocument();
  });

  it("shows OpenCode Go and MUST NOT say 'Ollama configured' when opencode_go is active", () => {
    providerStatusMock.mockReturnValue({
      provider: "opencode_go",
      label: "OpenCode Go",
      online: true,
      source: "opencode_go",
      liveCount: 1,
      error: undefined,
      status: "online",
      statusText: "Online",
      isChecking: false,
    } as never);
    sessionTokensMock.mockReturnValue({
      sessionTokens: 12400,
      totalTokens: 12400,
      baseline: 0,
      isLoading: false,
      error: null,
    } as never);
    // Need to re-mock runs/connections as setup does
    runsMock.mockReturnValue({ data: { runs: [], total: 0 }, isLoading: false, error: null } as never);
    connectionsMock.mockReturnValue({ data: { active: 0, connections: [], total: 0, stale: 0, removed: 0, error: 0 }, isLoading: false, error: null } as never);
    modelsMock.mockReturnValue({ data: { provider: "opencode_go" }, isLoading: false, error: null } as never);
    render(
      <MemoryRouter initialEntries={["/"]}>
        <Layout />
      </MemoryRouter>,
    );
    expect(screen.getByText("OpenCode Go")).toBeInTheDocument();
    expect(screen.queryByText("Ollama configured")).not.toBeInTheDocument();
    expect(screen.queryByText("Ollama")).not.toBeInTheDocument();
    expect(screen.getByText(/Online/)).toBeInTheDocument();
    // token formatted 12.4K
    expect(screen.getByText(/12\.4K tokens this session/)).toBeInTheDocument();
  });

  it("shows ChatGPT when chatgpt is active", () => {
    providerStatusMock.mockReturnValue({
      provider: "chatgpt",
      label: "ChatGPT",
      online: true,
      source: "chatgpt",
      liveCount: 3,
      error: undefined,
      status: "online",
      statusText: "Online",
      isChecking: false,
    } as never);
    sessionTokensMock.mockReturnValue({ sessionTokens: 31700, totalTokens: 31700, baseline: 0, isLoading: false, error: null } as never);
    runsMock.mockReturnValue({ data: { runs: [], total: 0 }, isLoading: false, error: null } as never);
    connectionsMock.mockReturnValue({ data: { active: 0, connections: [], total: 0, stale: 0, removed: 0, error: 0 }, isLoading: false, error: null } as never);
    modelsMock.mockReturnValue({ data: { provider: "chatgpt" }, isLoading: false, error: null } as never);
    render(
      <MemoryRouter initialEntries={["/"]}>
        <Layout />
      </MemoryRouter>,
    );
    expect(screen.getByText("ChatGPT")).toBeInTheDocument();
    expect(screen.getByText(/31\.7K tokens this session/)).toBeInTheDocument();
  });

  it("uses provider registry display name for generic registered provider", () => {
    providerStatusMock.mockReturnValue({
      provider: "my_provider",
      label: "My Custom Provider",
      online: true,
      source: "my_provider",
      liveCount: 1,
      error: undefined,
      status: "online",
      statusText: "Online",
      isChecking: false,
    } as never);
    sessionTokensMock.mockReturnValue({ sessionTokens: 500, totalTokens: 500, baseline: 0, isLoading: false, error: null } as never);
    runsMock.mockReturnValue({ data: { runs: [], total: 0 }, isLoading: false, error: null } as never);
    connectionsMock.mockReturnValue({ data: { active: 0, connections: [], total: 0, stale: 0, removed: 0, error: 0 }, isLoading: false, error: null } as never);
    modelsMock.mockReturnValue({ data: { provider: "my_provider" }, isLoading: false, error: null } as never);
    render(
      <MemoryRouter initialEntries={["/"]}>
        <Layout />
      </MemoryRouter>,
    );
    expect(screen.getByText("My Custom Provider")).toBeInTheDocument();
    expect(screen.queryByText("My Provider")).not.toBeInTheDocument();
  });

  it("displays Online when provider is reachable", () => {
    setup();
    expect(screen.getByText(/Online/)).toBeInTheDocument();
    // dot + text, not just color
    expect(screen.getByText(/Online ·/)).toBeInTheDocument();
  });

  it("displays Offline/Unreachable when provider fails", () => {
    providerStatusMock.mockReturnValue({
      provider: "ollama",
      label: "Ollama",
      online: false,
      source: "ollama",
      liveCount: 0,
      error: "unreachable",
      status: "unreachable",
      statusText: "Unreachable",
      isChecking: false,
    } as never);
    sessionTokensMock.mockReturnValue({ sessionTokens: 4302, totalTokens: 4302, baseline: 0, isLoading: false, error: null } as never);
    runsMock.mockReturnValue({ data: { runs: [], total: 0 }, isLoading: false, error: null } as never);
    connectionsMock.mockReturnValue({ data: { active: 0, connections: [], total: 0, stale: 0, removed: 0, error: 0 }, isLoading: false, error: null } as never);
    modelsMock.mockReturnValue({ data: { provider: "ollama" }, isLoading: false, error: null } as never);
    render(
      <MemoryRouter initialEntries={["/"]}>
        <Layout />
      </MemoryRouter>,
    );
    // Should show Unreachable (or Offline) — spec allows either
    const hasFailure = screen.queryByText(/Unreachable/) ?? screen.queryByText(/Offline/);
    expect(hasFailure).toBeInTheDocument();
  });

  it("shows checking state rather than claiming configured", () => {
    providerStatusMock.mockReturnValue({
      provider: "opencode_go",
      label: "OpenCode Go",
      online: false,
      source: "—",
      liveCount: 0,
      error: undefined,
      status: "checking",
      statusText: "Checking…",
      isChecking: true,
    } as never);
    sessionTokensMock.mockReturnValue({ sessionTokens: 0, totalTokens: null, baseline: null, isLoading: true, error: null } as never);
    runsMock.mockReturnValue({ data: { runs: [], total: 0 }, isLoading: false, error: null } as never);
    connectionsMock.mockReturnValue({ data: { active: 0, connections: [], total: 0, stale: 0, removed: 0, error: 0 }, isLoading: false, error: null } as never);
    modelsMock.mockReturnValue({ data: undefined, isLoading: true, error: null } as never);
    render(
      <MemoryRouter initialEntries={["/"]}>
        <Layout />
      </MemoryRouter>,
    );
    expect(screen.getByText(/Checking…/)).toBeInTheDocument();
    expect(screen.queryByText(/configured/)).not.toBeInTheDocument();
  });

  it("shows 0 tokens initially after baseline establishment", () => {
    providerStatusMock.mockReturnValue({
      provider: "ollama",
      label: "Ollama",
      online: true,
      source: "ollama",
      liveCount: 1,
      error: undefined,
      status: "online",
      statusText: "Online",
      isChecking: false,
    } as never);
    sessionTokensMock.mockReturnValue({ sessionTokens: 0, totalTokens: 100000, baseline: 100000, isLoading: false, error: null } as never);
    runsMock.mockReturnValue({ data: { runs: [], total: 0 }, isLoading: false, error: null } as never);
    connectionsMock.mockReturnValue({ data: { active: 0, connections: [], total: 0, stale: 0, removed: 0, error: 0 }, isLoading: false, error: null } as never);
    modelsMock.mockReturnValue({ data: { provider: "ollama" }, isLoading: false, error: null } as never);
    render(
      <MemoryRouter initialEntries={["/"]}>
        <Layout />
      </MemoryRouter>,
    );
    expect(screen.getByText(/0 tokens this session/)).toBeInTheDocument();
  });

  it("shows 3,250 session tokens when total goes from 100,000 to 103,250", () => {
    providerStatusMock.mockReturnValue({
      provider: "ollama",
      label: "Ollama",
      online: true,
      source: "ollama",
      liveCount: 1,
      error: undefined,
      status: "online",
      statusText: "Online",
      isChecking: false,
    } as never);
    sessionTokensMock.mockReturnValue({ sessionTokens: 3250, totalTokens: 103250, baseline: 100000, isLoading: false, error: null } as never);
    runsMock.mockReturnValue({ data: { runs: [], total: 0 }, isLoading: false, error: null } as never);
    connectionsMock.mockReturnValue({ data: { active: 0, connections: [], total: 0, stale: 0, removed: 0, error: 0 }, isLoading: false, error: null } as never);
    modelsMock.mockReturnValue({ data: { provider: "ollama" }, isLoading: false, error: null } as never);
    render(
      <MemoryRouter initialEntries={["/"]}>
        <Layout />
      </MemoryRouter>,
    );
    // 3250 formatted as 3.3K by capital K formatter
    expect(screen.getByText(/3\.3K tokens this session/)).toBeInTheDocument();
  });

  it("switching from Ollama to OpenCode Go updates UI without refresh", async () => {
    // initial ollama
    providerStatusMock.mockReturnValue({
      provider: "ollama",
      label: "Ollama",
      online: true,
      source: "ollama",
      liveCount: 1,
      error: undefined,
      status: "online",
      statusText: "Online",
      isChecking: false,
    } as never);
    sessionTokensMock.mockReturnValue({ sessionTokens: 100, totalTokens: 100, baseline: 0, isLoading: false, error: null } as never);
    runsMock.mockReturnValue({ data: { runs: [], total: 0 }, isLoading: false, error: null } as never);
    connectionsMock.mockReturnValue({ data: { active: 0, connections: [], total: 0, stale: 0, removed: 0, error: 0 }, isLoading: false, error: null } as never);
    modelsMock.mockReturnValue({ data: { provider: "ollama" }, isLoading: false, error: null } as never);
    const { rerender } = render(
      <MemoryRouter initialEntries={["/"]}>
        <Layout />
      </MemoryRouter>,
    );
    expect(screen.getByText("Ollama")).toBeInTheDocument();

    // switch to opencode_go — simulate React Query invalidation by updating mock
    providerStatusMock.mockReturnValue({
      provider: "opencode_go",
      label: "OpenCode Go",
      online: true,
      source: "opencode_go",
      liveCount: 2,
      error: undefined,
      status: "online",
      statusText: "Online",
      isChecking: false,
    } as never);
    rerender(
      <MemoryRouter initialEntries={["/"]}>
        <Layout />
      </MemoryRouter>,
    );
    expect(screen.getByText("OpenCode Go")).toBeInTheDocument();
    expect(screen.queryByText("Ollama")).not.toBeInTheDocument();
  });

  it("provider block is a link to Settings and shows provider error inline when unreachable", async () => {
    providerStatusMock.mockReturnValue({
      provider: "ollama",
      label: "Ollama",
      online: false,
      source: "ollama",
      liveCount: 0,
      error: "Ollama daemon not reachable at http://127.0.0.1:11434",
      status: "unreachable",
      statusText: "Unreachable",
      isChecking: false,
    } as never);
    sessionTokensMock.mockReturnValue({ sessionTokens: 0, totalTokens: 0, baseline: 0, isLoading: false, error: null } as never);
    runsMock.mockReturnValue({ data: { runs: [], total: 0 }, isLoading: false, error: null } as never);
    connectionsMock.mockReturnValue({ data: { active: 0, connections: [], total: 0, stale: 0, removed: 0, error: 0 }, isLoading: false, error: null } as never);
    modelsMock.mockReturnValue({ data: { provider: "ollama" }, isLoading: false, error: null } as never);
    render(
      <MemoryRouter initialEntries={["/"]}>
        <Layout />
      </MemoryRouter>,
    );
    const link = screen.getByRole("link", { name: /Provider: Ollama.*Unreachable/ });
    expect(link).toHaveAttribute("href", "/system");
    expect(link).toHaveAttribute("title", expect.stringContaining("Ollama daemon not reachable"));
    // Inline error text should be visible beneath the status line
    expect(screen.getByText("Ollama daemon not reachable at http://127.0.0.1:11434")).toBeInTheDocument();
  });

  it("clicking the provider block navigates to Settings", async () => {
    const user = userEvent.setup();
    setup();
    const link = screen.getByRole("link", { name: /Provider:/ });
    expect(link).toHaveAttribute("href", "/system");
    await user.click(link);
    // Navigation updates the active nav item
    expect(screen.getByRole("link", { name: /^Settings/ })).toHaveAttribute("aria-current", "page");
  });
});