"""Safety review helper for recon-mode CLI runs."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from tools.attack_ui import AttackUi
from tools.goal_engine import AttackGoal
from tools.safety_reviewer import SafetyReview, SafetyReviewer

ui = AttackUi(plain=False)

if TYPE_CHECKING:  # pragma: no cover - typing only
    from tools.runtime_context import RuntimeContext


async def run_safety_review(
    client: Any,
    model: str,
    result: dict[str, Any],
    target_ip: str,
    goal: AttackGoal,
    *,
    ctx: "RuntimeContext | None" = None,
) -> SafetyReview:
    """After recon, send results to AI for safety review.

    ``ctx`` selects the UI explicitly (see ``RuntimeContext``); omitted
    means the module-global UI (back-compat).
    """
    _ui = ctx.ui if ctx is not None else ui
    _ui.status("Reconnaissance complete. Running safety review...")

    # Extract results text for review
    parts: list[str] = []
    for msg in result.get("messages", []):
        if isinstance(msg, dict) and msg.get("role") == "tool":
            content = msg.get("content", "")
            if content:
                parts.append(f"[{msg.get('tool_name', 'tool')}] {content[:500]}")

    recon_summary = "\n\n".join(parts[:20])
    reviewer = SafetyReviewer(client, model)
    review = reviewer.review(recon_summary, target_ip, goal.description)
    _ui.display_safety_review(review)
    return review


# ---------------------------------------------------------------------------
# Recon-first assessment — scan target, suggest goals with exploit ratings
# ---------------------------------------------------------------------------
