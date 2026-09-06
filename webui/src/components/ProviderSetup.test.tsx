// @vitest-environment jsdom
import { describe, expect, it, vi, beforeEach } from "vitest";
import { renderHook } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import React from "react";

vi.mock("@/api/client", async () => {
  const actual = await vi.importActual<typeof import("@/api/client")>("@/api/client");
  return { ...actual, apiFetch: vi.fn() };
});

import { apiFetch } from "@/api/client";

const apiFetchMock = vi.mocked(apiFetch);

// Import after mock so hooks use mocked apiFetch
import { providerLabel, useDefaultModel, useModelOptions, useProviderStatus } from "@/components/ProviderSetup";

function createWrapper() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return ({ children }: { children: React.ReactNode }) => React.createElement(QueryClientProvider, { client: qc }, children);
}

beforeEach(() => {
  vi.clearAllMocks();
  sessionStorage.clear();
});

describe("providerLabel", () => {
  it("maps built-ins correctly", () => {
    expect(providerLabel("ollama")).toBe("Ollama");
    expect(providerLabel("chatgpt")).toBe("ChatGPT");
    expect(providerLabel("opencode_go")).toBe("OpenCode Go");
  });

  it("prefers registry display name when provided", () => {
    expect(providerLabel("my_provider", "My Custom Provider")).toBe("My Custom Provider");
    expect(providerLabel("ollama", "OVERRIDE")).toBe("OVERRIDE");
  });

  it("falls back to title-casing for unknown provider id", () => {
    expect(providerLabel("my_provider")).toBe("My Provider");
    expect(providerLabel("some_long_provider_id")).toBe("Some Long Provider Id");
  });
});

describe("useProviderStatus", () => {
  it("uses registry display name for generic provider", async () => {
    apiFetchMock.mockImplementation(async (path: string) => {
      if (path === "/models") return { provider: "my_provider", default_alias: "x", registry: {} } as never;
      if (path === "/models/live") return { models: ["a"], source: "my_provider" } as never;
      if (path === "/providers")
        return {
          provider: "my_provider",
          providers: [{ id: "my_provider", name: "My Custom Provider", capabilities: { chat: true, streaming: true, tool_calls: true, reasoning: true, embeddings: false, model_discovery: true } }],
        } as never;
      throw new Error(`unexpected ${path}`);
    });

    const { result } = renderHook(() => useProviderStatus(), { wrapper: createWrapper() });
    // Wait a tick for queries to resolve
    await new Promise((r) => setTimeout(r, 50));
    expect(result.current.provider).toBe("my_provider");
    expect(result.current.label).toBe("My Custom Provider");
    expect(result.current.online).toBe(true);
    expect(result.current.status).toBe("online");
    expect(result.current.statusText).toBe("Online");
  });

  it("reports ollama correctly", async () => {
    apiFetchMock.mockImplementation(async (path: string) => {
      if (path === "/models") return { provider: "ollama", default_alias: "glm", registry: {} } as never;
      if (path === "/models/live") return { models: ["glm"], source: "ollama" } as never;
      if (path === "/providers")
        return {
          provider: "ollama",
          providers: [
            { id: "ollama", name: "Ollama", capabilities: { chat: true, streaming: false, tool_calls: false, reasoning: false, embeddings: true, model_discovery: true } },
            { id: "chatgpt", name: "ChatGPT", capabilities: { chat: true, streaming: true, tool_calls: true, reasoning: true, embeddings: false, model_discovery: true } },
          ],
        } as never;
      throw new Error(`unexpected ${path}`);
    });
    const { result } = renderHook(() => useProviderStatus(), { wrapper: createWrapper() });
    await new Promise((r) => setTimeout(r, 50));
    expect(result.current.label).toBe("Ollama");
    expect(result.current.online).toBe(true);
  });

  it("reports opencode_go correctly", async () => {
    apiFetchMock.mockImplementation(async (path: string) => {
      if (path === "/models") return { provider: "opencode_go", default_alias: "glm", registry: {} } as never;
      if (path === "/models/live") return { models: ["muse-spark-1.2-contributor"], source: "opencode_go" } as never;
      if (path === "/providers")
        return {
          provider: "opencode_go",
          providers: [{ id: "opencode_go", name: "OpenCode Go", capabilities: { chat: true, streaming: true, tool_calls: true, reasoning: true, embeddings: false, model_discovery: true } }],
        } as never;
      throw new Error(`unexpected ${path}`);
    });
    const { result } = renderHook(() => useProviderStatus(), { wrapper: createWrapper() });
    await new Promise((r) => setTimeout(r, 50));
    expect(result.current.label).toBe("OpenCode Go");
    expect(result.current.online).toBe(true);
  });

  it("reports offline when no live models and no error", async () => {
    apiFetchMock.mockImplementation(async (path: string) => {
      if (path === "/models") return { provider: "ollama", default_alias: "glm", registry: {} } as never;
      if (path === "/models/live") return { models: [], source: "ollama" } as never;
      if (path === "/providers") return { provider: "ollama", providers: [] } as never;
      throw new Error(`unexpected ${path}`);
    });
    const { result } = renderHook(() => useProviderStatus(), { wrapper: createWrapper() });
    await new Promise((r) => setTimeout(r, 50));
    expect(result.current.online).toBe(false);
    expect(result.current.status).toBe("offline");
    expect(result.current.statusText).toBe("Offline");
  });

  it("reports unreachable when live returns error", async () => {
    apiFetchMock.mockImplementation(async (path: string) => {
      if (path === "/models") return { provider: "chatgpt", default_alias: "gpt-5.2", registry: {} } as never;
      if (path === "/models/live") return { models: [], source: "chatgpt", error: "unreachable" } as never;
      if (path === "/providers") return { provider: "chatgpt", providers: [] } as never;
      throw new Error(`unexpected ${path}`);
    });
    const { result } = renderHook(() => useProviderStatus(), { wrapper: createWrapper() });
    await new Promise((r) => setTimeout(r, 50));
    expect(result.current.online).toBe(false);
    expect(result.current.status).toBe("unreachable");
    expect(result.current.statusText).toBe("Unreachable");
    expect(result.current.error).toBe("unreachable");
  });

  it("keeps degraded registry-source fallback models for the active provider", async () => {
    // Backend contract: a 503 {source: "registry"} payload carries the active
    // provider's fallback only — useModelOptions must include it, not drop it.
    apiFetchMock.mockImplementation(async (path: string) => {
      if (path === "/models")
        return {
          provider: "chatgpt",
          default_alias: "glm",
          registry: { glm: "glm-5.2:cloud" },
          chatgpt: { default_model: "gpt-5.2", configured_models: [] },
        } as never;
      if (path === "/models/live") return { models: ["gpt-5.2"], source: "registry" } as never;
      if (path === "/providers") return { provider: "chatgpt", providers: [] } as never;
      throw new Error(`unexpected ${path}`);
    });
    const { result } = renderHook(() => useModelOptions(), { wrapper: createWrapper() });
    await new Promise((r) => setTimeout(r, 50));
    expect(result.current).toContain("gpt-5.2");
    expect(result.current).not.toContain("glm-5.2:cloud");
  });

  it("resolves generic provider options from the active_provider block", async () => {
    apiFetchMock.mockImplementation(async (path: string) => {
      if (path === "/models")
        return {
          provider: "fourth",
          default_alias: "glm",
          registry: { glm: "glm-5.2:cloud" },
          active_provider: { id: "fourth", default_model: "fourth-1", configured_models: ["fourth-1", "fourth-2"] },
        } as never;
      if (path === "/models/live") return { models: ["fourth-1", "fourth-2"], source: "fourth" } as never;
      if (path === "/providers")
        return {
          provider: "fourth",
          providers: [{ id: "fourth", name: "Fourth", capabilities: { chat: true, streaming: false, tool_calls: false, reasoning: false, embeddings: false, model_discovery: true } }],
        } as never;
      throw new Error(`unexpected ${path}`);
    });
    const { result: options } = renderHook(() => useModelOptions(), { wrapper: createWrapper() });
    const { result: def } = renderHook(() => useDefaultModel(), { wrapper: createWrapper() });
    await new Promise((r) => setTimeout(r, 50));
    expect(options.current).toContain("fourth-1");
    expect(options.current).toContain("fourth-2");
    expect(def.current).toBe("fourth-1");
  });

  it("does not hardcode ollama fallback for generic provider", async () => {
    // Ensure that generic provider label is not Ollama
    apiFetchMock.mockImplementation(async (path: string) => {
      if (path === "/models") return { provider: "opencode_go", default_alias: "muse", registry: {} } as never;
      if (path === "/models/live") return { models: ["m"], source: "opencode_go" } as never;
      if (path === "/providers")
        return {
          provider: "opencode_go",
          providers: [{ id: "opencode_go", name: "OpenCode Go", capabilities: { chat: true, streaming: true, tool_calls: true, reasoning: true, embeddings: false, model_discovery: true } }],
        } as never;
      throw new Error(`unexpected ${path}`);
    });
    const { result } = renderHook(() => useProviderStatus(), { wrapper: createWrapper() });
    await new Promise((r) => setTimeout(r, 50));
    expect(result.current.label).not.toBe("Ollama");
    expect(result.current.label).toBe("OpenCode Go");
  });
});
