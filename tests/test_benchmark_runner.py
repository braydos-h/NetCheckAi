"""Integration-style tests for the BenchmarkRunner (fully mocked execution)."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import pytest

from tools.benchmark import BenchmarkScenario, seed_fake_suite
from tools.benchmark.agent_runner import MissionResult, SandboxSnapshot, TrialTelemetry
from tools.benchmark.models import FailureCategory, RunConfig, TrialStatus
from tools.benchmark.runner import BenchmarkRunner
from tools.benchmark.targets import TargetProvisionError


def _scenario(scenario_id: str = "s1", *, oracle_flags: list[dict] | None = None, **kw) -> BenchmarkScenario:
    return BenchmarkScenario(
        suite="fake",
        scenario_id=scenario_id,
        name=f"Scenario {scenario_id}",
        target_type="host",
        target_host="127.0.0.1",
        tags=["web"],
        oracle={
            "flags": oracle_flags if oracle_flags is not None else [{"id": "f1", "check": {}}],
            "host_owned_when": "any",
        },
        **kw,
    )


def _config(tmp_path: Path, **bm) -> dict[str, Any]:
    return {
        "benchmark": {"output_dir": str(tmp_path / "bench"), "sandbox_required": False, **bm},
        "models": {"default_alias": "glm"},
        "mcp": {"http_port": 8001},
    }


class _FakeMission:
    """MissionRunner stand-in returning canned MissionResults."""

    def __init__(self, outcomes: list[MissionResult]) -> None:
        self.outcomes = list(outcomes)
        self.calls: list[str] = []

    async def run_mission(self, scenario, *, workspace, trial_id, event_logger=None, goal=None, timeout_seconds=None):
        self.calls.append(trial_id)
        workspace.mkdir(parents=True, exist_ok=True)
        outcome = self.outcomes.pop(0) if self.outcomes else MissionResult()
        return outcome


def _verified_mission(**kw) -> MissionResult:
    base = dict(total_actions=5, telemetry=TrialTelemetry(model_calls=10, tool_calls=8, total_tokens=1000))
    base.update(kw)
    return MissionResult(**base)


def _make_runner(tmp_path, config, mission, *, verifier_factory=None, target_manager=None):
    runner = BenchmarkRunner(
        config, Path("config.yaml"), verifier_factory=verifier_factory, target_manager=target_manager
    )
    runner._make_mission = lambda: mission  # type: ignore[attr-defined]
    return runner


@pytest.fixture
def runner_cls_patched(monkeypatch):
    """Patch runner module's MissionRunner seam to route through our factory."""
    registry: dict[str, Any] = {}

    def install(outcomes: list[MissionResult]) -> _FakeMission:
        mission = _FakeMission(outcomes)
        registry["mission"] = mission
        return mission

    monkeypatch.setattr("tools.benchmark.runner.MissionRunner", lambda *a, **kw: registry["mission"])
    return install


def _pass_executor(check):
    return True, "ok"


def _fail_executor(check):
    return False, "not present"


# ---------------------------------------------------------------------------
# Outcomes
# ---------------------------------------------------------------------------


def test_verified_success(tmp_path, runner_cls_patched, monkeypatch):
    seed_fake_suite([_scenario("s1")])
    runner_cls_patched([_verified_mission(agent_claimed_success=True, claimed_summary="compromises: 1")])
    runner = BenchmarkRunner(_config(tmp_path), Path("config.yaml"), verifier_factory=lambda s: _v(s, _pass_executor))
    payload = asyncio.run(runner.run(RunConfig(suite="fake", scenario_ids=["s1"], trials=1, sandbox_required=False)))
    trial = payload["trials"][0]
    assert trial["status"] == "VERIFIED"
    assert trial["oracle_verified_success"] is True
    assert trial["false_positive"] is False
    assert payload["summary"]["verified_success_rate"] == 1.0
    assert payload["summary"]["false_positive_rate"] == 0.0
    # Persistence: run.json + summary.json + report + events exist.
    run_dir = Path(payload["run_dir"])
    assert (run_dir / "summary.json").exists()
    assert (run_dir / "report.md").exists()
    assert (run_dir / "report.html").exists()
    assert (run_dir / "events.jsonl").exists()
    assert "oracle_result" in (run_dir / "events.jsonl").read_text(encoding="utf-8")


def _v(scenario, executor):
    from tools.benchmark.verifier import IndependentVerifier

    v = IndependentVerifier.__new__(IndependentVerifier)
    v.scenario = scenario
    v._executor = executor
    v._session = None
    v._workspace = None
    v._loop = None
    return v


def test_false_positive(tmp_path, runner_cls_patched):
    """Agent claims success, oracle says no -> FALSE_POSITIVE trial."""
    seed_fake_suite([_scenario("s1")])
    runner_cls_patched([_verified_mission(agent_claimed_success=True, claimed_summary="compromises: 1")])
    runner = BenchmarkRunner(_config(tmp_path), Path("config.yaml"), verifier_factory=lambda s: _v(s, _fail_executor))
    payload = asyncio.run(runner.run(RunConfig(suite="fake", scenario_ids=["s1"], trials=1, sandbox_required=False)))
    trial = payload["trials"][0]
    assert trial["status"] == "FALSE_POSITIVE"
    assert trial["failure_category"] == FailureCategory.FALSE_POSITIVE.value
    assert trial["false_positive"] is True
    assert payload["summary"]["false_positive_rate"] == 1.0


def test_failed_trial_no_exploit_path(tmp_path, runner_cls_patched):
    seed_fake_suite([_scenario("s1")])
    runner_cls_patched([MissionResult(total_actions=4, telemetry=TrialTelemetry(tool_calls=4))])
    runner = BenchmarkRunner(_config(tmp_path), Path("config.yaml"), verifier_factory=lambda s: _v(s, _fail_executor))
    payload = asyncio.run(runner.run(RunConfig(suite="fake", scenario_ids=["s1"], trials=1, sandbox_required=False)))
    trial = payload["trials"][0]
    assert trial["status"] == "FAILED"
    assert trial["failure_category"] == FailureCategory.NO_EXPLOIT_PATH.value


def test_timeout_trial(tmp_path, runner_cls_patched):
    seed_fake_suite([_scenario("s1")])
    runner_cls_patched([MissionResult(timed_out=True, errors=["mission timeout after 30s"])])
    runner = BenchmarkRunner(_config(tmp_path), Path("config.yaml"), verifier_factory=lambda s: _v(s, _pass_executor))
    payload = asyncio.run(runner.run(RunConfig(suite="fake", scenario_ids=["s1"], trials=1, sandbox_required=False)))
    trial = payload["trials"][0]
    assert trial["status"] == TrialStatus.TIMEOUT.value
    assert trial["failure_category"] == FailureCategory.TIMEOUT.value
    # Timeout is a failure, not an infrastructure error.
    assert payload["summary"]["timeout_count"] == 1
    assert payload["summary"]["infra_error_count"] == 0


def test_provision_failure_is_infrastructure_error(tmp_path, runner_cls_patched):
    seed_fake_suite([_scenario("s1")])
    runner_cls_patched([_verified_mission()])

    class _BadTargetManager:
        def provision(self, scenario):
            raise TargetProvisionError("docker run failed")

        def reset(self, scenario):
            raise TargetProvisionError("docker run failed")

        def destroy_all(self):
            pass

    runner = BenchmarkRunner(_config(tmp_path), Path("config.yaml"), target_manager=_BadTargetManager())
    payload = asyncio.run(runner.run(RunConfig(suite="fake", scenario_ids=["s1"], trials=1, sandbox_required=False)))
    trial = payload["trials"][0]
    assert trial["status"] == TrialStatus.INFRASTRUCTURE_ERROR.value
    assert trial["failure_category"] == FailureCategory.TARGET_PROVISION_FAILED.value
    # Infrastructure failures are reported separately from exploitation failures.
    assert payload["summary"]["infra_error_count"] == 1


def test_sandbox_required_but_disabled_is_infrastructure_error(tmp_path, runner_cls_patched):
    """sandbox_required + sandbox disabled => INFRASTRUCTURE_ERROR/SANDBOX_FAILED
    (no host-execution fallback), never FAILED_TO_EXPLOIT."""
    seed_fake_suite([_scenario("s1")])
    runner_cls_patched([_verified_mission()])
    config = _config(tmp_path, sandbox_required=True)
    config["sandbox"] = {"enabled": False}
    runner = BenchmarkRunner(config, Path("config.yaml"))
    payload = asyncio.run(runner.run(RunConfig(suite="fake", scenario_ids=["s1"], trials=1, sandbox_required=True)))
    trial = payload["trials"][0]
    assert trial["status"] == TrialStatus.INFRASTRUCTURE_ERROR.value
    assert trial["failure_category"] == FailureCategory.SANDBOX_FAILED.value


def test_multiple_trials_and_cancellation(tmp_path, runner_cls_patched):
    """Repeated trials record per-scenario stats; cancel stops further trials."""
    seed_fake_suite([_scenario("s1"), _scenario("s2")])
    outcomes = [
        _verified_mission(),
        MissionResult(total_actions=1),
        _verified_mission(),
        MissionResult(total_actions=1),
    ]
    mission = runner_cls_patched(outcomes)
    runner = BenchmarkRunner(_config(tmp_path), Path("config.yaml"), verifier_factory=lambda s: _v(s, _pass_executor))
    cancel = asyncio.Event()

    async def _run():
        if True:  # cancel after the first scenario's first trial
            task = asyncio.create_task(
                runner.run(RunConfig(suite="fake", trials=2, sandbox_required=False), cancel=cancel)
            )
            await asyncio.sleep(0.05)
            if len(mission.calls) >= 1:
                cancel.set()
            return await task

    payload = asyncio.run(_run())
    assert payload["status"] == "cancelled"
    assert len(payload["trials"]) < 4  # cancelled before all trials ran


def test_run_records_reproducibility_metadata(tmp_path, runner_cls_patched, monkeypatch):
    seed_fake_suite([_scenario("s1", target_image="")])
    runner_cls_patched([_verified_mission()])
    monkeypatch.setattr("tools.benchmark.envinfo._git", lambda *a, **kw: "deadbeef" if a[0] == "rev-parse" else "")
    monkeypatch.setattr("tools.benchmark.envinfo.docker_image_digest", lambda image: "sha256:abc")
    runner = BenchmarkRunner(_config(tmp_path), Path("config.yaml"), verifier_factory=lambda s: _v(s, _pass_executor))
    payload = asyncio.run(runner.run(RunConfig(suite="fake", scenario_ids=["s1"], trials=1, sandbox_required=False)))
    run = json.loads((Path(payload["run_dir"]) / "run.json").read_text(encoding="utf-8"))
    env = run["environment"]
    assert env["git_sha"] == "deadbeef"
    assert env["model_alias"] == "glm"
    assert env["config_hash"] != "unknown"
    assert env["sandbox_image_digest"] == "sha256:abc"
    # Manifest carries the replay command + reproducibility pins.
    assert run["replay_manifest"]["replay_command"].startswith("python main.py --benchmark fake")
    assert run["replay_manifest"]["git_sha"] == "deadbeef"


def test_no_scenarios_match(tmp_path):
    from tools.benchmark import BenchmarkRunner as R

    seed_fake_suite([_scenario("s1")])
    runner = R(_config(tmp_path), Path("config.yaml"))
    payload = asyncio.run(
        runner.run(RunConfig(suite="fake", scenario_ids=["does-not-exist"], trials=1, sandbox_required=False))
    )
    assert "error" in payload


def test_target_ports_reachable_helper() -> None:
    """Unit probe: an open loopback port is reachable; closed and empty are not."""
    import socket as _socket

    from tools.benchmark.runner import _target_ports_reachable

    srv = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    open_port = srv.getsockname()[1]
    try:
        assert _target_ports_reachable("127.0.0.1", [open_port]) is True
    finally:
        srv.close()
    assert _target_ports_reachable("127.0.0.1", [open_port]) is False
    assert _target_ports_reachable("127.0.0.1", []) is False


def test_unreachable_target_ports_is_infrastructure_error(tmp_path, runner_cls_patched):
    """A host-type scenario whose declared ports all refuse fails fast as
    INFRASTRUCTURE_ERROR/TARGET_PROVISION_FAILED (down lab) without running
    the mission -- the test.log waste was 50 recon rounds vs refused ports."""
    import socket as _socket

    probe = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
    probe.bind(("127.0.0.1", 0))
    closed_port = probe.getsockname()[1]
    probe.close()

    seed_fake_suite([_scenario("s1", target_ports=[closed_port])])
    mission = runner_cls_patched([_verified_mission()])
    runner = BenchmarkRunner(_config(tmp_path), Path("config.yaml"), verifier_factory=lambda s: _v(s, _pass_executor))
    payload = asyncio.run(runner.run(RunConfig(suite="fake", scenario_ids=["s1"], trials=1, sandbox_required=False)))
    trial = payload["trials"][0]
    assert trial["status"] == TrialStatus.INFRASTRUCTURE_ERROR.value
    assert trial["failure_category"] == FailureCategory.TARGET_PROVISION_FAILED.value
    assert "up -d" in trial["failure_detail"]
    assert mission.calls == []  # mission never ran
    assert payload["summary"]["infra_error_count"] == 1
