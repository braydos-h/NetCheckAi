"""Benchmark result persistence: reports/benchmarks/<suite>/<run_id>/.

Layout (machine-readable files are the source of truth; reports render FROM
them)::

    reports/benchmarks/<suite>/<run_id>/
        run.json          RunConfig + RunEnvironment + trial list
        summary.json      RunSummary (aggregated metrics)
        events.jsonl      structured mission events (whole run)
        report.md / report.html   rendered public report
        scenarios/<scenario_id>/
            trial_<n>.json        per-trial result
            trial_<n>_events.jsonl  per-trial event stream

Writes are atomic (``.tmp`` + ``os.replace``) so a killed run never leaves a
half-written JSON behind. Reads tolerate partial runs (a run mid-flight has no
summary.json yet and is reported with ``status: running``).
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

from tools.benchmark.models import RunConfig, RunEnvironment, RunSummary, TrialResult

__all__ = ["BenchmarkStorage", "RUN_INDEX_FILENAME"]

RUN_INDEX_FILENAME = "runs_index.json"

_RUN_ID_RE = re.compile(r"^[A-Za-z0-9_.-]+$")
_SCENARIO_ID_RE = re.compile(r"^[A-Za-z0-9_.-]+$")


def _atomic_write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
    os.replace(tmp, path)


def _atomic_write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, path)


def _valid_id(value: str) -> bool:
    return bool(value) and bool(_RUN_ID_RE.match(value)) and ".." not in value


class BenchmarkStorage:
    """Filesystem-backed benchmark result store.

    The root is resolved to an ABSOLUTE path at construction so a mid-run CWD
    change (some MCP/session machinery manipulates process state) can never
    split one run's files across two trees.
    """

    def __init__(self, root: Path | str = "reports/benchmarks") -> None:
        self.root = Path(root).absolute()

    # ------------------------------------------------------------------ paths

    def run_dir(self, suite: str, run_id: str) -> Path:
        if not _valid_id(suite) or not _valid_id(run_id):
            raise ValueError(f"invalid benchmark path ids: suite={suite!r} run_id={run_id!r}")
        return self.root / suite / run_id

    def scenario_dir(self, suite: str, run_id: str, scenario_id: str) -> Path:
        if not _valid_id(scenario_id):
            raise ValueError(f"invalid scenario id: {scenario_id!r}")
        return self.run_dir(suite, run_id) / "scenarios" / scenario_id

    # ----------------------------------------------------------------- writes

    def init_run(
        self,
        suite: str,
        run_id: str,
        config: RunConfig,
        environment: RunEnvironment,
        scenario_ids: list[str],
    ) -> Path:
        """Create the run dir + initial run.json (status=running)."""
        run_dir = self.run_dir(suite, run_id)
        run_dir.mkdir(parents=True, exist_ok=True)
        _atomic_write_json(
            run_dir / "run.json",
            {
                "run_id": run_id,
                "suite": suite,
                "status": "running",
                "config": config.to_dict(),
                "environment": environment.to_dict(),
                "scenario_ids": list(scenario_ids),
                "trials": [],
            },
        )
        return run_dir

    def write_trial(self, suite: str, run_id: str, trial: TrialResult) -> Path:
        """Persist one trial result atomically."""
        path = self.scenario_dir(suite, run_id, trial.scenario_id) / f"trial_{trial.trial_index}.json"
        _atomic_write_json(path, trial.to_dict())
        return path

    def finalize_run(
        self,
        suite: str,
        run_id: str,
        *,
        status: str,
        trials: list[TrialResult],
        summary: RunSummary | None,
        config: RunConfig,
        environment: RunEnvironment,
        scenario_ids: list[str],
        manifest: dict[str, Any] | None = None,
    ) -> Path:
        """Write final run.json + summary.json (and refresh the suite index)."""
        run_dir = self.run_dir(suite, run_id)
        payload: dict[str, Any] = {
            "run_id": run_id,
            "suite": suite,
            "status": status,
            "config": config.to_dict(),
            "environment": environment.to_dict(),
            "scenario_ids": list(scenario_ids),
            "trials": [t.to_dict() for t in trials],
        }
        if manifest is not None:
            payload["replay_manifest"] = manifest
        _atomic_write_json(run_dir / "run.json", payload)
        if summary is not None:
            _atomic_write_json(run_dir / "summary.json", summary.to_dict())
            self._update_index(suite, run_id, summary, status)
        return run_dir

    def _update_index(self, suite: str, run_id: str, summary: RunSummary, status: str) -> None:
        """Suite-level index of completed runs (fast list + history charts)."""
        index_path = self.root / suite / RUN_INDEX_FILENAME
        try:
            entries = json.loads(index_path.read_text(encoding="utf-8")) if index_path.exists() else []
        except (json.JSONDecodeError, OSError):
            entries = []
        if not isinstance(entries, list):
            entries = []
        entries = [e for e in entries if isinstance(e, dict) and e.get("run_id") != run_id]
        entries.append(
            {
                "run_id": run_id,
                "status": status,
                "timestamp": summary.timestamp,
                "trials_total": summary.trials_total,
                "solved": summary.solved,
                "verified_success_rate": summary.verified_success_rate,
                "false_positive_rate": summary.false_positive_rate,
                "median_solve_time": summary.median_solve_time,
                "estimated_cost": summary.estimated_cost,
                "total_tokens": summary.total_tokens,
            }
        )
        entries.sort(key=lambda e: str(e.get("timestamp", "")))
        _atomic_write_json(index_path, entries)

    def write_report(self, suite: str, run_id: str, markdown: str, html: str) -> tuple[Path, Path]:
        run_dir = self.run_dir(suite, run_id)
        md_path = run_dir / "report.md"
        html_path = run_dir / "report.html"
        _atomic_write_text(md_path, markdown)
        _atomic_write_text(html_path, html)
        return md_path, html_path

    # ------------------------------------------------------------------ reads

    def load_run(self, suite: str, run_id: str) -> dict[str, Any] | None:
        """Load run.json (+ summary.json when present) for one run."""
        try:
            data = json.loads((self.run_dir(suite, run_id) / "run.json").read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError, ValueError):
            return None
        summary_path = self.run_dir(suite, run_id) / "summary.json"
        if summary_path.exists():
            try:
                data["summary"] = json.loads(summary_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                data["summary"] = None
        else:
            data["summary"] = None
        return data

    def load_summary(self, suite: str, run_id: str) -> dict[str, Any] | None:
        try:
            return json.loads((self.run_dir(suite, run_id) / "summary.json").read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError, ValueError):
            return None

    def list_runs(self, suite: str | None = None) -> list[dict[str, Any]]:
        """List runs (newest first) from the suite index files.

        Runs still in flight have a ``run.json`` but no index entry yet;
        those are surfaced as ``status: running`` rows so the WebUI never
        hides an active run.
        """
        suites = [suite] if suite else self.list_suites()
        runs: list[dict[str, Any]] = []
        for s in suites:
            if not _valid_id(s):
                continue
            indexed: set[str] = set()
            index_path = self.root / s / RUN_INDEX_FILENAME
            try:
                entries = json.loads(index_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                entries = []
            if isinstance(entries, list):
                for entry in entries:
                    if isinstance(entry, dict):
                        if entry.get("run_id") is not None:
                            indexed.add(str(entry.get("run_id")))
                        row = dict(entry)
                        row.setdefault("suite", s)
                        runs.append(row)
            suite_dir = self.root / s
            try:
                children = list(suite_dir.iterdir())
            except OSError:
                continue
            for child in children:
                if not child.is_dir() or not _valid_id(child.name) or child.name in indexed:
                    continue
                run_json = child / "run.json"
                if not run_json.exists():
                    continue
                try:
                    data = json.loads(run_json.read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError):
                    continue
                if not isinstance(data, dict):
                    continue
                runs.append(
                    {
                        "run_id": child.name,
                        "suite": s,
                        "status": data.get("status", "running"),
                        "timestamp": data.get("timestamp", ""),
                        "trials_total": len(data.get("trials", []) or []),
                        "solved": 0,
                        "verified_success_rate": 0.0,
                        "false_positive_rate": 0.0,
                        "median_solve_time": None,
                        "estimated_cost": None,
                        "total_tokens": 0,
                    }
                )
        runs.sort(key=lambda r: str(r.get("timestamp", "")), reverse=True)
        return runs

    def list_suites(self) -> list[str]:
        if not self.root.exists():
            return []
        return sorted(p.name for p in self.root.iterdir() if p.is_dir() and _valid_id(p.name))

    def load_events(
        self, suite: str, run_id: str, *, trial_id: str = "", after: int = 0, limit: int = 500
    ) -> list[dict[str, Any]]:
        """Read events.jsonl (optionally filtered by trial, after a sequence)."""
        path = self.run_dir(suite, run_id) / "events.jsonl"
        if not path.exists():
            return []
        events: list[dict[str, Any]] = []
        try:
            with path.open("r", encoding="utf-8") as handle:
                for line in handle:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        event = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if not isinstance(event, dict):
                        continue
                    if trial_id and event.get("trial_id") != trial_id:
                        continue
                    if after:
                        try:
                            if int(event.get("sequence", 0) or 0) <= after:
                                continue
                        except (TypeError, ValueError):
                            continue  # corrupt sequence — skip the row
                    events.append(event)
                    if len(events) >= limit:
                        break
        except OSError:
            return []
        return events
