"""Local guard mirroring the CI requirements/pyproject sync check.

``requirements.txt`` must cover ``[project.dependencies]`` + the ``dev``
extra (the ``browser`` extra is intentionally excluded — opt-in only).
"""

from __future__ import annotations

import pathlib
import re
import tomllib


def test_requirements_covers_pyproject() -> None:
    py = tomllib.loads(pathlib.Path("pyproject.toml").read_text(encoding="utf-8"))
    deps: set[str] = set()

    def _name(dep: str) -> str:
        return re.split(r"[<>=; ]", dep.strip())[0].lower()

    for d in py["project"]["dependencies"]:
        deps.add(_name(d))
    for d in py["project"]["optional-dependencies"]["dev"]:
        deps.add(_name(d))
    for d in py["project"]["optional-dependencies"].get("browser", []):
        deps.discard(_name(d))

    req_lines = [
        line.strip()
        for line in pathlib.Path("requirements.txt").read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    reqs = {_name(line) for line in req_lines}
    missing = sorted(deps - reqs)
    assert not missing, f"requirements.txt missing deps from pyproject.toml: {missing}"
