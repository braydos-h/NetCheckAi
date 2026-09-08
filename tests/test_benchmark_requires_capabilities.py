"""Benchmark ``requires_capabilities`` scenario-metadata tests.

Scenarios may declare capability names they cannot run without (e.g.
``browser.*`` with no backend). This change adds ONLY the schema + plumbing:
parsing, summaries, and the availability checker. No live scenario declares
browser requirements yet, and a scenario requiring an unavailable capability
is detectable via ``tools.browser.capabilities.unmet_requirements`` without
ever attempting a launch.
"""

from __future__ import annotations

from tools.benchmark.models import BenchmarkScenario, FailureCategory
from tools.benchmark.registry import scenario_summary
from tools.benchmark.xben.manifest import parse_manifest
from tools.browser.capabilities import browser_available, unmet_requirements

VALID_ORACLE = {"flags": [{"flag_id": "f1", "description": "d", "check": {"type": "http", "path": "/"}}]}
BASE_MANIFEST = {
    "benchmark_id": "xben-9001",
    "name": "SPA auth bypass",
    "description": "needs a browser to even load the app",
    "target_image": "ghcr.io/xben/xben-9001:latest",
    "target_ports": [8080],
    "oracle": VALID_ORACLE,
}


# ── Declaration / parsing (backwards compatible) ──────────────────────────


def test_manifest_without_requires_capabilities_yields_empty_list():
    scenario = parse_manifest(BASE_MANIFEST)
    assert scenario.requires_capabilities == []


def test_manifest_with_requires_capabilities_is_parsed():
    manifest = {**BASE_MANIFEST, "requires_capabilities": ["browser.navigate", "browser.dom.inspect"]}
    scenario = parse_manifest(manifest)
    assert scenario.requires_capabilities == ["browser.navigate", "browser.dom.inspect"]


def test_scenario_defaults_unchanged_for_existing_providers():
    """Existing scenario construction (no requirements) behaves exactly as before."""
    scenario = BenchmarkScenario(suite="xben", scenario_id="xben-001")
    assert scenario.requires_capabilities == []
    data = scenario.to_dict()
    assert data["requires_capabilities"] == []


def test_scenario_summary_includes_requirements():
    scenario = parse_manifest(BASE_MANIFEST)  # no requirements
    assert scenario_summary(scenario)["requires_capabilities"] == []
    required = parse_manifest({**BASE_MANIFEST, "requires_capabilities": ["browser.screenshot"]})
    assert scenario_summary(required)["requires_capabilities"] == ["browser.screenshot"]


# ── Detection / classification (no launch) ────────────────────────────────


def test_scenario_requiring_browser_is_unmet_on_stock_builds():
    scenario = parse_manifest({**BASE_MANIFEST, "requires_capabilities": ["browser.navigate"]})
    assert unmet_requirements(scenario.requires_capabilities) == ["browser.navigate"]


def test_scenario_with_no_requirements_is_never_blocked():
    scenario = parse_manifest(BASE_MANIFEST)
    assert unmet_requirements(scenario.requires_capabilities) == []


def test_stock_builds_report_no_browser_availability():
    assert browser_available({}) is False


def test_capability_unavailable_failure_category_is_emitted():
    """The runner's capability gate (step 0b) classifies unmet-requirement
    trials SKIPPED / CAPABILITY_UNAVAILABLE without provisioning anything."""
    import asyncio
    from pathlib import Path
    from unittest.mock import MagicMock

    from tools.benchmark.models import TrialStatus
    from tools.benchmark.runner import BenchmarkRunner

    scenario = parse_manifest({**BASE_MANIFEST, "requires_capabilities": ["browser.navigate"]})
    runner = BenchmarkRunner(
        {},  # stock config: no browser backend -> requirement unmet
        Path("reports/benchmarks"),
        run_session=MagicMock(),
        target_manager=MagicMock(),  # must never be touched (no provisioning)
    )
    event_logger = MagicMock()
    trial = asyncio.run(
        runner._run_trial(
            scenario,
            0,
            f"{scenario.scenario_id}#t1",
            runner._make_target_manager(),
            MagicMock(),
            event_logger,
            run_id="run-cap-test",
            run_dir=Path("/tmp/bp-cap-test"),
            sandbox_required=False,
            sandbox_shortfall=False,
            progress=None,
        )
    )
    assert trial.status == TrialStatus.SKIPPED.value
    assert trial.failure_category == FailureCategory.CAPABILITY_UNAVAILABLE.value
    assert "browser.navigate" in trial.failure_detail
    logged = [c.args[0] for c in event_logger.log.call_args_list]
    assert "capability_unavailable" in logged


def test_capability_gate_passes_when_requirements_met_or_empty():
    """Empty requires_capabilities never gates; a met requirement proceeds
    to the sandbox gate (which returns INFRASTRUCTURE_ERROR here only to
    prove the capability gate did NOT fire first)."""
    import asyncio
    from pathlib import Path
    from unittest.mock import MagicMock

    from tools.benchmark.models import TrialStatus
    from tools.benchmark.runner import BenchmarkRunner

    plain = parse_manifest(BASE_MANIFEST)  # requires_capabilities == []
    runner = BenchmarkRunner({}, Path("reports/benchmarks"), run_session=MagicMock())
    event_logger = MagicMock()
    trial = asyncio.run(
        runner._run_trial(
            plain,
            0,
            f"{plain.scenario_id}#t1",
            MagicMock(),  # provision raises -> proves we got past the gate
            MagicMock(),
            event_logger,
            run_id="run-cap-test",
            run_dir=Path("/tmp/bp-cap-test"),
            sandbox_required=False,
            sandbox_shortfall=False,
            progress=None,
        )
    )
    # No capability gate fired: the trial proceeded past step 0b (it fails
    # later on the MagicMock manager, which is fine — the gate is what we pin).
    assert trial.status != TrialStatus.SKIPPED.value
    assert trial.failure_category != FailureCategory.CAPABILITY_UNAVAILABLE.value
