import { useCallback, useEffect, useState } from "react";
import type { DecisionListRow } from "@/api/types";

export type PermissionMode = "read_only" | "approve" | "full_access";

const STORAGE_KEY = "breachpilot.permissionMode.v1";
const DEFAULT_MODE: PermissionMode = "read_only";

/** When "1", the Full Access confirmation dialog is skipped and the mode is applied directly. */
export const SUPPRESS_FULL_ACCESS_KEY = "breachpilot.permissionMode.suppressFullAccessConfirm.v1";

export function shouldSuppressFullAccessConfirm(): boolean {
  try {
    return sessionStorage.getItem(SUPPRESS_FULL_ACCESS_KEY) === "1";
  } catch {
    return false;
  }
}

export function setSuppressFullAccessConfirm(suppress: boolean): void {
  try {
    if (suppress) sessionStorage.setItem(SUPPRESS_FULL_ACCESS_KEY, "1");
    else sessionStorage.removeItem(SUPPRESS_FULL_ACCESS_KEY);
  } catch {
    // ignore
  }
}

function readStored(): PermissionMode {
  try {
    const v = sessionStorage.getItem(STORAGE_KEY);
    if (v === "approve" || v === "full_access") return v;
  } catch {
    // ignore
  }
  return DEFAULT_MODE;
}

function writeStored(mode: PermissionMode): void {
  try {
    sessionStorage.setItem(STORAGE_KEY, mode);
  } catch {
    // ignore
  }
}

export function usePermissionMode() {
  const [mode, setMode] = useState<PermissionMode>(readStored);

  useEffect(() => {
    writeStored(mode);
  }, [mode]);

  const change = useCallback((m: PermissionMode) => setMode(m), []);
  return { mode, setMode: change };
}

/**
 * Return the answer string to auto-submit for `decision` under `mode`,
 * or `null` when the mode does not cover this decision (operator must answer).
 *
 * - read_only: never auto-answers (operator must confirm everything).
 * - approve: non-destructive start_confirm / tool_approval only (sends "yes").
 *   Destructive decisions (those carrying required_text) are always left to
 *   the operator regardless of mode.
 * - full_access: auto-answers every start_confirm / tool_approval. Non-
 *   destructive decisions send "yes"; destructive decisions send the exact
 *   `required_text` string the server validates against
 *   (run_manager.confirm_and_start). goal_select is still left to the operator.
 *
 * goal_select is never auto-answered — the operator must pick a
 * goal from the AI-ranked suggestions themselves.
 */
export function autoAnswerFor(decision: DecisionListRow, mode: PermissionMode): string | null {
  if (mode === "read_only") return null;
  if (decision.status !== "pending") return null;

  const requiredText = decision.required_text ?? "";
  const destructive = !!requiredText;
  const kind = decision.kind;

  if (kind === "goal_select") return null;

  // Mid-run operator checkpoints are NEVER auto-answered regardless of
  // permission mode. The operator must explicitly choose whether to continue,
  // change objective, finish, or cancel — a full_access posture must not
  // silently auto-escalate or auto-pivot at the verified-access milestone.
  if (kind === "campaign_next_step") return null;

  if (mode === "approve") {
    if (destructive) return null;
    // start_confirm / tool_approval, non-destructive
    return "yes";
  }

  // full_access: auto-answer everything the operator could answer.
  // Destructive confirmations require the exact required_text string; the
  // server's confirm_and_start gate rejects anything else.
  return destructive ? requiredText : "yes";
}