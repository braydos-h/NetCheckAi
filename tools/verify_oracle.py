"""Deterministic verify-or-it-didn't-happen oracle.

Scanner output (nuclei/nikto/ZAP/web_scan) is CANDIDATE only. A finding
becomes CONFIRMED (``VERIFIED``) only when this named machine oracle
re-proves it N/N times via a replayable proof capsule. LLM text,
OutcomeJudge text, and exit codes NEVER decide — every run classifies
through the authoritative ``outcome_truth`` classifier
(``tools/exploit_agent/outcome_truth.py``), and anything that is not
N/N compromise evidence fails closed to ``HOLDING``/``INCONCLUSIVE``.

Reuse (no new execution paths, no new stores):

- verdict vocabulary mirrors the closed-loop retest tool
  (``tools/mcp_tools/retest.py``): the same ``_INCONCLUSIVE_MARKERS``
  (``SANDBOX_*``/``BLOCKED:``/executor crashes) mean "the probe did not
  run to a verdict" and fail closed to ``INCONCLUSIVE`` — never a host
  fallback, never a pass;
- compromise evidence is ``outcome_truth`` ``COMPROMISE``/``CRED_DUMP``
  only (strong shell/root/SYSTEM markers), the same bar the retest
  ``STILL_OPEN`` verdict and the benchmark ``IndependentVerifier``
  (crash=FAIL) hold.

Verdict rules over the N probe outputs:

- any output carrying a containment/policy marker, empty, or ambiguous
  (``PARTIAL``/``UNKNOWN``/``NONE``) → ``INCONCLUSIVE``;
- all N outputs ``COMPROMISE``/``CRED_DUMP`` → ``VERIFIED``;
- otherwise (flaky N/N mix, or demonstrable ``FAILURE``) → ``HOLDING``.
"""

from __future__ import annotations

import asyncio
import hashlib
from dataclasses import dataclass, field
from typing import Any, Callable

from tools.exploit_agent.outcome_truth import ExploitOutcome, classify_exploit_outcome
from tools.mcp_tools.retest import _INCONCLUSIVE_MARKERS

VERIFIED = "VERIFIED"
HOLDING = "HOLDING"
INCONCLUSIVE = "INCONCLUSIVE"

VERIFY_VERDICTS = frozenset({VERIFIED, HOLDING, INCONCLUSIVE})

# Outcome_truth verdicts that count as machine proof of the finding.
_PROOF_OUTCOMES = frozenset({ExploitOutcome.COMPROMISE, ExploitOutcome.CRED_DUMP})


def proof_sha256(probe_exec: str, outputs: list[str]) -> str:
    """Replay identifier for a proof capsule (probe + ordered outputs)."""
    blob = str(probe_exec or "") + "\n" + "\n".join(str(o or "") for o in outputs)
    return hashlib.sha256(blob.encode("utf-8", errors="replace")).hexdigest()


def classify_verify_output(output: str) -> tuple[bool, bool, str]:
    """Map one probe output to ``(is_proof, is_inconclusive, detail)``.

    Proof = ``outcome_truth`` compromise/cred-dump. Demonstrable failure
    (``FAILURE``) is determinate non-proof → ``HOLDING`` territory, while
    containment markers, empty, and ambiguous outcomes are ``INCONCLUSIVE``.
    """
    text = str(output or "")
    if not text.strip():
        return False, True, "empty probe output"
    for marker in _INCONCLUSIVE_MARKERS:
        if marker in text:
            lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
            # ponytail: prefer the marker-bearing line so SANDBOX_* codes surface in DETAIL.
            detail = next((ln for ln in lines if marker in ln), lines[0] if lines else marker)
            return False, True, detail[:300]
    outcome = classify_exploit_outcome(text).get("outcome", ExploitOutcome.UNKNOWN)
    if outcome in _PROOF_OUTCOMES:
        return True, False, f"outcome_truth={outcome}"
    if outcome == ExploitOutcome.FAILURE:
        return False, False, f"outcome_truth={outcome}"
    return False, True, f"outcome_truth={outcome}"


def judge_outputs(outputs: list[str]) -> tuple[str, str]:
    """Deterministic N/N verdict over already-collected probe outputs."""
    if not outputs:
        return INCONCLUSIVE, "no probe outputs"
    per = [classify_verify_output(o) for o in outputs]
    for _proof, inc, detail in per:
        if inc:
            return INCONCLUSIVE, detail
    proofs = sum(1 for proof, _inc, _d in per if proof)
    if proofs == len(per):
        return VERIFIED, f"{proofs}/{len(per)} runs show compromise evidence"
    return HOLDING, f"only {proofs}/{len(per)} runs show compromise evidence"


@dataclass
class ProofCapsule:
    """Replayable proof: same probe exec, N outputs, content hash, run refs."""

    probe_exec: str = ""
    n: int = 0
    outputs: list[str] = field(default_factory=list)
    sha256: str = ""
    run_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "probe_exec": self.probe_exec,
            "n": self.n,
            "outputs": list(self.outputs),
            "sha256": self.sha256,
            "run_ids": list(self.run_ids),
        }


@dataclass
class VerifyOutcome:
    """Oracle verdict + the capsule that re-proves it."""

    verdict: str = HOLDING
    proof_capsule: ProofCapsule = field(default_factory=ProofCapsule)
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"verdict": self.verdict, "proof_capsule": self.proof_capsule.to_dict(), "detail": self.detail}


class VerifyOracle:
    """Re-proves one candidate N times through the injected run function.

    ``run_fn`` maps a resolved probe exec string to raw tool output; ``None``
    (and any raising run_fn) degrades to ``INCONCLUSIVE`` fail-closed — the
    ``IndependentVerifier`` None-session precedent. The oracle never inspects
    LLM text, judge text, or exit codes beyond what ``outcome_truth`` encodes.
    """

    def __init__(self, run_fn: Callable[[str], str] | None = None) -> None:
        self._run_fn = run_fn

    @staticmethod
    def _candidate_exec(candidate: dict[str, Any]) -> str:
        if not isinstance(candidate, dict):
            return ""
        probe = candidate.get("verification_probe")
        if isinstance(probe, dict) and str(probe.get("exec", "") or "").strip():
            return str(probe["exec"])
        # Also accept a pre-resolved candidate carrying the exec directly.
        return str(candidate.get("exec", "") or "")

    def verify_sync(
        self,
        candidate: dict[str, Any],
        *,
        repeats: int = 2,
        run_ids: list[str] | None = None,
    ) -> VerifyOutcome:
        """Synchronously re-prove ``candidate`` (call via ``asyncio.to_thread``)."""
        try:
            n = max(1, int(repeats or 2))
        except (TypeError, ValueError):
            n = 2
        exec_cmd = self._candidate_exec(candidate)
        outputs: list[str] = []
        if not exec_cmd.strip():
            verdict, detail = INCONCLUSIVE, "no stored verification probe for this finding"
        elif self._run_fn is None:
            verdict, detail = INCONCLUSIVE, "no probe executor available"
        else:
            for _ in range(n):
                try:
                    outputs.append(str(self._run_fn(exec_cmd)))
                except Exception as exc:  # noqa: BLE001 -- executor crash is INCONCLUSIVE, never a pass
                    outputs.append(f"TOOL_EXECUTION_ERROR: {exc}")
            verdict, detail = judge_outputs(outputs)
        capsule = ProofCapsule(
            probe_exec=exec_cmd,
            n=n,
            outputs=outputs,
            sha256=proof_sha256(exec_cmd, outputs),
            run_ids=list(run_ids or []),
        )
        return VerifyOutcome(verdict=verdict, proof_capsule=capsule, detail=detail)

    async def verify(
        self,
        candidate: dict[str, Any],
        *,
        repeats: int = 2,
        run_ids: list[str] | None = None,
    ) -> VerifyOutcome:
        """Async wrapper: verification runs on a worker thread (run_fn may block)."""
        return await asyncio.to_thread(self.verify_sync, candidate, repeats=repeats, run_ids=run_ids)


__all__ = [
    "HOLDING",
    "INCONCLUSIVE",
    "VERIFIED",
    "VERIFY_VERDICTS",
    "ProofCapsule",
    "VerifyOracle",
    "VerifyOutcome",
    "classify_verify_output",
    "judge_outputs",
    "proof_sha256",
]


def demo() -> None:
    """Good probe 2/2 -> VERIFIED, flaky 1/2 -> HOLDING, SANDBOX_* -> INCONCLUSIVE (no network)."""
    print("verify_oracle demo: candidate-only until the machine re-proves N/N")
    good = "exploit ok\nuid=0(root) gid=0(root)"
    bad = "curl: (7) Failed to connect: connection refused"
    sandbox = "TERMINAL_RESULT: BLOCKED\nSANDBOX_UNAVAILABLE\ndocker daemon unreachable"

    def _run(canned: list[str]) -> Callable[[str], str]:
        it = iter(canned)
        return lambda _cmd: next(it)

    outcome = VerifyOracle(_run([good, good])).verify_sync({"exec": "curl -s http://10.0.0.50/poc"})
    assert outcome.verdict == VERIFIED, outcome
    print(f"  good probe 2/2  -> {outcome.verdict} (sha256={outcome.proof_capsule.sha256[:16]}…)")

    outcome = VerifyOracle(_run([good, bad])).verify_sync({"exec": "curl -s http://10.0.0.50/poc"})
    assert outcome.verdict == HOLDING, outcome
    print(f"  flaky probe 1/2 -> {outcome.verdict} ({outcome.detail})")

    outcome = VerifyOracle(_run([good, sandbox])).verify_sync({"exec": "curl -s http://10.0.0.50/poc"})
    assert outcome.verdict == INCONCLUSIVE, outcome
    print(f"  sandbox-blocked -> {outcome.verdict} ({outcome.detail})")
    print("demo OK: VERIFIED only on N/N machine proof, fail closed otherwise")


if __name__ == "__main__":
    demo()
