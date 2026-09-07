#!/usr/bin/env python3
"""Generate docs/mcp/tool-catalog-generated.md from MCP tool sources.

Stdlib only (ast + re + pathlib + datetime). Parses every
``tools/mcp_tools/*.py``, ``tools/mcp_tools/terminal/*.py`` and
``tools/mcp_tools/modules/*.py`` for ``register_*`` functions and the inner
``@mcp.tool`` defs (with their ``@audit_tool`` / ``@require_allowlist``
gate variants and docstring first lines), plus ``mcp_server.py``
(defensive) and ``mcp_engine_server.py`` (engine) tools.
"""

from __future__ import annotations

import ast
import re
from datetime import date
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
TOOL_GLOBS = [
    REPO / "tools" / "mcp_tools",
    REPO / "tools" / "mcp_tools" / "terminal",
    REPO / "tools" / "mcp_tools" / "modules",
]
SERVER_FILES = [REPO / "mcp_server.py", REPO / "mcp_engine_server.py"]
OUT = REPO / "docs" / "mcp" / "tool-catalog-generated.md"

_REGISTER_RE = re.compile(r"^_?register_.*")
_WS_RE = re.compile(r"\s+")


def _decor_text(d: ast.expr) -> str:
    try:
        return ast.unparse(d).strip()
    except Exception:
        return ""


def _is_mcp_tool(t: str) -> bool:
    return "mcp.tool" in t


def _gate_label(t: str) -> str | None:
    if _is_mcp_tool(t):
        return None
    if "audit_tool" in t or "require_allowlist" in t:
        return "@" + t.replace("'", '"')
    return None


def _first_line(doc: str | None) -> str:
    if not doc:
        return "—"
    for line in doc.splitlines():
        s = _WS_RE.sub(" ", line.strip())
        if s:
            return s[:240] + ("…" if len(s) > 240 else "")
    return "—"


def _esc(cell: str) -> str:
    return cell.replace("|", "\\|").replace("\n", " ")


def parse_file(path: Path) -> tuple[list[tuple[str, int]], list[dict]]:
    """Return (registrars, tools) for one source file."""
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except (OSError, SyntaxError):
        return [], []
    registrars: list[tuple[str, int]] = []
    tools: list[dict] = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if _REGISTER_RE.match(node.name):
                registrars.append((node.name, node.lineno))
            texts = [_decor_text(d) for d in node.decorator_list]
            if any(_is_mcp_tool(t) for t in texts):
                gates = [g for t in texts if (g := _gate_label(t)) is not None]
                tools.append(
                    {
                        "name": node.name,
                        "lineno": node.lineno,
                        "async": isinstance(node, ast.AsyncFunctionDef),
                        "gates": gates,
                        "purpose": _first_line(ast.get_docstring(node)),
                    }
                )
    tools.sort(key=lambda t: t["lineno"])
    registrars.sort(key=lambda r: r[1])
    return registrars, tools


def family_title(rel: str) -> str:
    if rel == "mcp_server.py":
        return "defensive (`mcp_server.py`)"
    if rel == "mcp_engine_server.py":
        return "engine (`mcp_engine_server.py`)"
    return f"`{rel}`"


def main() -> None:
    today = date.today().isoformat()
    files: list[Path] = []
    for d in TOOL_GLOBS:
        if d.is_dir():
            files.extend(sorted(p for p in d.glob("*.py") if p.name != "__init__.py"))
    files.extend(SERVER_FILES)
    sources = [str(p.relative_to(REPO)) for p in files]

    families: list[dict] = []
    for path in files:
        rel = str(path.relative_to(REPO))
        registrars, tools = parse_file(path)
        if not tools:
            continue
        families.append({"rel": rel, "registrars": registrars, "tools": tools})
    families.sort(key=lambda f: f["rel"])

    total = sum(len(f["tools"]) for f in families)
    gate_counts: dict[str, int] = {}
    for f in families:
        for t in f["tools"]:
            key = " + ".join(t["gates"]) if t["gates"] else "—"
            gate_counts[key] = gate_counts.get(key, 0) + 1

    lines: list[str] = []
    lines.append("---")
    lines.append("title: MCP Tool Catalog (Generated)")
    lines.append(
        "description: Machine-readable table for every MCP tool — gates, "
        "purpose, source location. Verified against tools/mcp_tools/ + "
        "mcp_server.py + mcp_engine_server.py."
    )
    lines.append(f"source: [{', '.join(sources)}]")
    lines.append(f"generated_from: [{', '.join(sources)}]")
    lines.append(f"verify: every tool listed exists as an @mcp.tool def at time of generation ({today}).")
    lines.append("---")
    lines.append("")
    lines.append("# MCP Tool Catalog (Generated)")
    lines.append("")
    lines.append(
        "> Machine-readable companion to `docs/mcp/tool-families/` and "
        "`docs/mcp/servers/`. Every tool below was verified to exist as an "
        "`@mcp.tool` def at generation time — no invented tools. Gates are the "
        "literal `@audit_tool` / `@require_allowlist(...)` decorators on each "
        "def; purpose is the docstring first line. Defensive-server tools "
        "enforce scope via an inline allowlist check instead of decorators; "
        "engine-server tools are read-only advisory with no gates."
    )
    lines.append("")
    lines.append(
        "Source locations use `<file>:<line>` relative to the repo root. "
        "Registration functions (`register_*_tools`) are auto-discovered via "
        "`tools/mcp_tools/registry.py:collect_tools()`; no manual list edit is needed."
    )
    lines.append("")
    lines.append("")
    lines.append(
        f"_Generated {today} from `{len(sources)} source files` "
        f"({total} tools across {len(families)} families)._"
    )
    lines.append("")

    for fam in families:
        tools = fam["tools"]
        lines.append(f"## {family_title(fam['rel'])} ({len(tools)})")
        lines.append("")
        if fam["registrars"]:
            regs = ", ".join(f"`{n}()` (`{fam['rel']}:{ln}`)" for n, ln in fam["registrars"])
            lines.append(f"- **Registration:** {regs} — auto-discovered; no edit to `mcp_exploit_server.py`.")
        else:
            lines.append("- **Registration:** inline `@mcp.tool` defs in `create_mcp_server()` — no `register_*` wrapper.")
        lines.append("")
        lines.append("| Tool | Gates | Purpose | Source |")
        lines.append("|------|-------|---------|--------|")
        for t in tools:
            gates = " + ".join(f"`{g}`" for g in t["gates"]) if t["gates"] else "—"
            lines.append(
                f"| `{t['name']}` | {gates} | {_esc(t['purpose'])} | `{fam['rel']}:{t['lineno']}` |"
            )
        lines.append("")

    lines.append("## Totals")
    lines.append("")
    lines.append(f"- **Tools:** {total} across {len(families)} families.")
    lines.append("")
    lines.append("| Gates | Count |")
    lines.append("|-------|-------|")
    for key in sorted(gate_counts, key=lambda k: (-gate_counts[k], k)):
        lines.append(f"| `{_esc(key)}` | {gate_counts[key]} |")
    lines.append("")

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text("\n".join(lines), encoding="utf-8")
    print(f"Wrote {OUT} ({total} tools, {len(families)} families)")


if __name__ == "__main__":
    main()
