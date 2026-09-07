// @vitest-environment jsdom
// BreachPilot by @braydos-h — https://github.com/braydos-h/BreachPilot
import { describe, expect, it } from "vitest";
import { formatCost, formatDuration, formatPct, isActiveState, isOrphanedRun, runStatusToBadge } from "@/features/benchmarks/format";

describe("benchmark formatters", () => {
  it("formats durations", () => {
    expect(formatDuration(862)).toBe("14m 22s");
    expect(formatDuration(0)).toBe("0m 00s");
    expect(formatDuration(null)).toBe("n/a");
    expect(formatDuration(undefined)).toBe("n/a");
    expect(formatDuration(Number.NaN)).toBe("n/a");
  });

  it("formats costs with sub-cent precision for tiny estimates", () => {
    expect(formatCost(0.42)).toBe("$0.42");
    expect(formatCost(0.0031)).toBe("$0.0031");
    expect(formatCost(0)).toBe("$0.00");
    expect(formatCost(null)).toBe("n/a");
  });

  it("formats percentages", () => {
    expect(formatPct(0.962)).toBe("96.2%");
    expect(formatPct(null)).toBe("n/a");
  });
});

describe("isActiveState", () => {
  it("treats running/starting/cancelling as active", () => {
    expect(isActiveState("running")).toBe(true);
    expect(isActiveState("starting")).toBe(true);
    expect(isActiveState("cancelling")).toBe(true);
    expect(isActiveState("idle")).toBe(false);
    expect(isActiveState("completed")).toBe(false);
    expect(isActiveState("error")).toBe(false);
  });
});

describe("runStatusToBadge", () => {
  it("maps backend run statuses to badge keys", () => {
    // "completed" is runner-finished, not oracle-verified — it must not map
    // to VERIFIED (a completed run can have zero solved trials).
    expect(runStatusToBadge("completed")).toBe("COMPLETED");
    expect(runStatusToBadge("cancelled")).toBe("CANCELLED");
    expect(runStatusToBadge("running")).toBe("RUNNING");
    expect(runStatusToBadge("failed")).toBe("FAILED");
    expect(runStatusToBadge("")).toBe("FAILED");
  });
});

describe("isOrphanedRun", () => {
  it("flags a still-running run that no runner owns", () => {
    expect(
      isOrphanedRun("running", { active: { run_id: null, state: "idle" } }, "r1"),
    ).toBe(true);
    expect(
      isOrphanedRun("running", { active: { run_id: "other", state: "running" } }, "r1"),
    ).toBe(true);
  });

  it("keeps a genuinely active run live", () => {
    expect(
      isOrphanedRun("running", { active: { run_id: "r1", state: "running" } }, "r1"),
    ).toBe(false);
  });

  it("ignores terminal runs and an unknown overview", () => {
    expect(isOrphanedRun("completed", { active: { run_id: null, state: "idle" } }, "r1")).toBe(false);
    expect(isOrphanedRun("running", undefined, "r1")).toBe(false);
  });
});
