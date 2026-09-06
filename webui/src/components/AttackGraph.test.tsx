// @vitest-environment jsdom
import { describe, expect, it, vi, beforeEach } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";
import { AttackGraph } from "@/components/AttackGraph";
import type { ToolCallResponse } from "@/api/types";

// ── module mocks ────────────────────────────────────────────────────────────

vi.mock("@/api/hooks", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/api/hooks")>()),
  useFetchArtifactBlob: vi.fn(),
  useCallTool: vi.fn(),
}));

import { useCallTool, useFetchArtifactBlob } from "@/api/hooks";
import { ApiError } from "@/api/client";

const fetchMock = vi.mocked(useFetchArtifactBlob);
const callToolMock = vi.mocked(useCallTool);

// ── fixtures ────────────────────────────────────────────────────────────────

function reportFixture() {
  return {
    report_metadata: { generated_at: "2026-01-01T00:10:00Z" },
    exploitation_chains: [
      {
        chain_id: "chain-1",
        target: "10.0.0.50",
        entries: [
          { module: "quick_scan", result: "success" },
          { module: "ms17_010", result: "success" },
        ],
        successful: true,
        final_privilege: "user",
      },
    ],
    technical_findings: [
      {
        finding_id: "F-1",
        title: "SMBv1 enabled",
        affected_asset: "10.0.0.50",
        vuln_class: "configuration",
        severity: "high",
        cvss: { base_score: 8.1, severity: "High" },
        confidence: 0.9,
        summary: "SMBv1 enabled.",
      },
    ],
    // Deliberately out of order — the UI must sort ascending by timestamp.
    attack_timeline: [
      { timestamp: "2026-01-01T00:03:00Z", event_type: "exploit", description: "EternalBlue landed", target: "10.0.0.50", module: "ms17_010", result: "success" },
      { timestamp: "2026-01-01T00:01:00Z", event_type: "recon", description: "Port sweep", target: "10.0.0.50", module: "quick_scan", result: "" },
      { timestamp: "2026-01-01T00:02:00Z", event_type: "exploit", description: "Payload rejected", target: "10.0.0.50", module: "ms17_010", result: "fail" },
    ],
    failure_analysis: [
      {
        operation: "smb_bruteforce",
        failure_count: 3,
        primary_error: "connection refused",
        error_breakdown: { "connection refused": 2, timeout: 1 },
        mitigation_suggestion: "Slow down pacing.",
      },
      {
        operation: "web_scan",
        failure_count: 7,
        primary_error: "404 enumeration base",
      },
    ],
  };
}

// ── harness ─────────────────────────────────────────────────────────────────

function setup(blobText: string | null, opts: { ready?: boolean; fails?: boolean } = {}) {
  const mutate = vi.fn((_name: string, handlers?: { onSuccess?: (b: Blob) => void; onError?: (e: unknown) => void }) => {
    if (opts.fails) {
      handlers?.onError?.(Object.assign(new Error("boom"), { isNotFound: false }));
    } else {
      handlers?.onSuccess?.(new Blob([blobText ?? "{}"], { type: "application/json" }));
    }
  });
  fetchMock.mockReturnValue({ mutate } as never);
  callToolMock.mockReturnValue({ mutate: vi.fn(), isPending: false } as never);
  render(<AttackGraph runId="run-1" ready={opts.ready ?? true} />);
  return mutate;
}

beforeEach(() => {
  vi.clearAllMocks();
});

// ── tests ───────────────────────────────────────────────────────────────────

describe("AttackGraph timeline + failure analysis", () => {
  it("renders timeline events sorted ascending", async () => {
    setup(JSON.stringify(reportFixture()));
    expect(await screen.findByText("Attack Timeline")).toBeInTheDocument();
    const list = screen.getByRole("list");
    const stamps = [...list.querySelectorAll("span")].filter((el) =>
      /^2026-01-01T/.test(el.textContent ?? ""),
    );
    expect(stamps.map((el) => el.textContent)).toEqual([
      "2026-01-01T00:01:00Z",
      "2026-01-01T00:02:00Z",
      "2026-01-01T00:03:00Z",
    ]);
  });

  it("sorts failure groups by failure_count descending", async () => {
    setup(JSON.stringify(reportFixture()));
    await screen.findByText("Failure Analysis");
    const groups = screen.getAllByText(/failure(s)?$/);
    expect(groups.map((g) => g.textContent)).toEqual(["7 failures", "3 failures"]);
  });

  it("shows error-breakdown chips and the mitigation line", async () => {
    setup(JSON.stringify(reportFixture()));
    expect(await screen.findByText("×2")).toBeInTheDocument();
    expect(screen.getByText("×1")).toBeInTheDocument();
    expect(screen.getByText(/Mitigation:/)).toBeInTheDocument();
  });

  it("keeps count badges consistent with the new sections", async () => {
    setup(JSON.stringify(reportFixture()));
    expect(await screen.findByText("3 timeline events")).toBeInTheDocument();
    expect(screen.getByText("2 failure groups")).toBeInTheDocument();
    expect(screen.getByText("1 chains")).toBeInTheDocument();
    expect(screen.getByText("1 findings")).toBeInTheDocument();
  });

  it("renders a timeline-only report instead of the empty state", async () => {
    const report = reportFixture();
    delete (report as Record<string, unknown>).exploitation_chains;
    delete (report as Record<string, unknown>).technical_findings;
    setup(JSON.stringify(report));
    expect(await screen.findByText("Attack Timeline")).toBeInTheDocument();
    expect(screen.queryByText(/No exploitation chains or findings/)).not.toBeInTheDocument();
  });

  it("still shows the empty state when every section is absent", async () => {
    setup(JSON.stringify({ report_metadata: {} }));
    expect(await screen.findByText(/No exploitation chains or findings/)).toBeInTheDocument();
  });

  it("shows the not-found branch when the artifact is missing", async () => {
    const mutate = vi.fn((_name: string, handlers?: { onError?: (e: unknown) => void }) => {
      handlers?.onError?.(
        new ApiError({ status: 404, message: "Not found", code: "not_found", details: {}, requestId: "r1", raw: null }),
      );
    });
    fetchMock.mockReturnValue({ mutate } as never);
    render(<AttackGraph runId="run-1" />);
    expect(await screen.findByText("No enhanced report yet for this run.")).toBeInTheDocument();
  });

  it("does not fetch while the artifact isn't ready", async () => {
    setup(JSON.stringify(reportFixture()), { ready: false });
    expect(screen.getByText(/Attack path report is generated when the run completes/)).toBeInTheDocument();
    expect(fetchMock.mock.results.length).toBeGreaterThan(0);
    // mutate never fired — the component skipped the artifact fetch entirely.
    expect(vi.mocked(fetchMock.mock.results[0]!.value as { mutate: () => void }).mutate).not.toHaveBeenCalled();
  });

  it("shows the generic error branch for non-404 failures", async () => {
    setup(null, { fails: true });
    expect(await screen.findByText("Failed to load enhanced report.")).toBeInTheDocument();
  });

  it("paints neutral events with the pending icon even when the backend marks result 'failure'", async () => {
    // enhanced_reporting derives result="failure" for every non-success event;
    // the icon must key off event_type (like the markdown report), so a plain
    // recon event stays ⏳ rather than turning red.
    setup(JSON.stringify(reportFixture()));
    const row = (await screen.findByText("Port sweep")).closest("li")!;
    expect(row.querySelector("svg.lucide-clock")).not.toBeNull();
    expect(row.querySelector("svg.lucide-x-circle")).toBeNull();
  });
});

describe("AttackGraph closed-loop retest", () => {
  function setupWithRetest(resultText: string) {
    const mutate = vi.fn(
      (
        _vars: unknown,
        handlers?: { onSuccess?: (data: ToolCallResponse) => void; onError?: (e: unknown) => void },
      ) => {
        handlers?.onSuccess?.({ tool: "retest_finding", result: resultText });
      },
    );
    const fetchMutate = vi.fn(
      (_name: string, handlers?: { onSuccess?: (b: Blob) => void; onError?: (e: unknown) => void }) => {
        handlers?.onSuccess?.(
          new Blob([JSON.stringify(reportFixture())], { type: "application/json" }),
        );
      },
    );
    fetchMock.mockReturnValue({ mutate: fetchMutate } as never);
    callToolMock.mockReturnValue({ mutate, isPending: false } as never);
    render(<AttackGraph runId="run-1" />);
    return mutate;
  }

  it("renders one Retest button per finding calling retest_finding", async () => {
    const mutate = setupWithRetest("RETEST_VERDICT:\nVERDICT: FIXED");
    const btn = await screen.findByRole("button", { name: "Retest F-1" });
    fireEvent.click(btn);
    expect(mutate).toHaveBeenCalledWith(
      { tool: "retest_finding", arguments: { target_ip: "10.0.0.50", finding_id: "F-1" } },
      expect.anything(),
    );
  });

  it("displays the returned verdict inline", async () => {
    setupWithRetest("RETEST_VERDICT:\nFINDING: F-1\nVERDICT: FIXED\nEVIDENCE: x");
    fireEvent.click(await screen.findByRole("button", { name: "Retest F-1" }));
    expect(await screen.findByText("FIXED")).toBeInTheDocument();
  });

  it("shows the stored retest_status from the report without clicking", async () => {
    const report = reportFixture();
    (report.technical_findings[0] as Record<string, unknown>).retest_status = "STILL_OPEN";
    const fetchMutate = vi.fn(
      (_name: string, handlers?: { onSuccess?: (b: Blob) => void }) => {
        handlers?.onSuccess?.(new Blob([JSON.stringify(report)], { type: "application/json" }));
      },
    );
    fetchMock.mockReturnValue({ mutate: fetchMutate } as never);
    callToolMock.mockReturnValue({ mutate: vi.fn(), isPending: false } as never);
    render(<AttackGraph runId="run-1" />);
    expect(await screen.findByText("STILL_OPEN")).toBeInTheDocument();
  });
});