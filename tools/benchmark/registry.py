"""Benchmark provider registry: suites -> scenarios.

A *provider* owns one benchmark suite (XBEN is one; future suites plug in
here). The runner never hard-codes XBEN — it resolves a suite through this
registry and works purely against :class:`tools.benchmark.models.BenchmarkScenario`.

Discovery seams are injectable (``manifest_dir`` / ``glob_fn``) so tests can
register fake suites without touching the repo's ``benchmarks/`` directory.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from tools.benchmark.models import BenchmarkScenario

__all__ = [
    "BenchmarkProvider",
    "register_provider",
    "get_provider",
    "list_suites",
    "list_scenarios",
    "scenario_summary",
    "default_manifest_dir",
]


class BenchmarkProvider:
    """Protocol-ish base class for one benchmark suite.

    Subclasses implement :meth:`load_scenarios`. ``suite_id`` names the suite
    (e.g. ``"xben"``).
    """

    suite_id: str = ""

    def load_scenarios(
        self,
        *,
        scenario_ids: list[str] | None = None,
        tags: list[str] | None = None,
    ) -> list[BenchmarkScenario]:
        """Return the suite's scenarios (optionally filtered)."""
        raise NotImplementedError

    def describe(self) -> dict[str, Any]:
        """Suite metadata for ``--benchmark-list`` / the WebUI suite picker."""
        return {"suite_id": self.suite_id, "scenarios": 0}


@dataclass
class _RegistryState:
    providers: dict[str, BenchmarkProvider] = field(default_factory=dict)


_STATE = _RegistryState()


def register_provider(provider: BenchmarkProvider) -> None:
    """Register (or replace) a suite provider by ``suite_id``."""
    if not getattr(provider, "suite_id", ""):
        raise ValueError("BenchmarkProvider requires a non-empty suite_id")
    _STATE.providers[provider.suite_id] = provider


def get_provider(suite_id: str) -> BenchmarkProvider:
    """Resolve a suite provider by ``suite_id``.

    Contract: returns the registered :class:`BenchmarkProvider`; raises
    :class:`KeyError` (message lists the known suites, or "(none
    registered)") when ``suite_id`` is unknown. Callers that surface this
    to operators should catch ``KeyError`` and report it as a user error,
    not a crash.
    """
    provider = _STATE.providers.get(suite_id)
    if provider is None:
        known = ", ".join(sorted(_STATE.providers)) or "(none registered)"
        raise KeyError(f"Unknown benchmark suite {suite_id!r}. Registered suites: {known}")
    return provider


def list_suites() -> list[dict[str, Any]]:
    """Describe every registered suite (stable order)."""
    return [_STATE.providers[sid].describe() for sid in sorted(_STATE.providers)]


def list_scenarios(suite_id: str) -> list[dict[str, Any]]:
    """Scenario summaries for one suite (used by the WebUI run panel)."""
    provider = get_provider(suite_id)
    return [scenario_summary(s) for s in provider.load_scenarios()]


def scenario_summary(scenario: BenchmarkScenario) -> dict[str, Any]:
    """Compact, UI-friendly scenario descriptor (no oracle payloads)."""
    oracle = scenario.oracle or {}
    flags = oracle.get("flags", []) or []
    return {
        "suite": scenario.suite,
        "scenario_id": scenario.scenario_id,
        "benchmark_id": scenario.benchmark_id,
        "name": scenario.name,
        "description": scenario.description,
        "target_type": scenario.target_type,
        "target_image": scenario.target_image,
        "target_host": scenario.target_host,
        "target_ports": list(scenario.target_ports),
        "goal": scenario.goal,
        "tags": list(scenario.tags),
        "difficulty": scenario.difficulty,
        "reset_strategy": scenario.reset_strategy,
        "timeout_seconds": scenario.timeout_seconds,
        "expected_flags": list(scenario.expected_flags),
        "oracle_flag_count": len(flags),
        "source_manifest": scenario.source_manifest,
        "requires_capabilities": list(scenario.requires_capabilities),
    }


def default_manifest_dir(suite_id: str) -> Path:
    """Default on-disk home for a suite's manifests: ``benchmarks/<suite>/``."""
    return Path("benchmarks") / suite_id


#: Glob seam (tests replace it to avoid touching the real filesystem).
GlobFn = Callable[[Path, str], list[Path]]
