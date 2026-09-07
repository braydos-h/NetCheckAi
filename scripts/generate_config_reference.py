#!/usr/bin/env python3
"""Regenerate docs/configuration/config-reference-generated.md.

Reads config.yaml (yaml.safe_load, nested dicts walked to leaf dotted paths),
ast-parses CONFIG_SCHEMA out of tools/config/schema.py for schema defaults,
reuses the top-level line number from the raw YAML text as the source
location, and preserves the hand-curated cells (Allowed + Consumer/Effect/
Env/Restart/Subsystem/Tests) for keys already in the table. Keys in
config.yaml but missing from the schema are marked lab-only.
"""

import ast
import re
from datetime import date
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
CONFIG_PATH = ROOT / "config.yaml"
SCHEMA_PATH = ROOT / "tools" / "config" / "schema.py"
OUT_PATH = ROOT / "docs" / "configuration" / "config-reference-generated.md"

# Best-effort subsystem for NEW keys only (existing rows keep their cell).
SUBSYSTEM_BY_TOP = {
    "adaptive_exploits": "exploit",
    "agent": "agent",
    "api": "api/webui",
    "autonomous": "autonomous",
    "benchmark": "benchmark",
    "browser": "browser",
    "caldera": "ad",
    "chatgpt": "providers",
    "cve_lookup": "research/cve",
    "embeddings": "embeddings",
    "engine_mcp": "mcp/engine",
    "eval": "eval",
    "exploit": "exploit/agent",
    "fsm": "fsm",
    "hitl": "hitl",
    "ics": "ics",
    "killchain": "killchain",
    "long_session": "long_session",
    "mcp": "mcp",
    "memory": "memory",
    "mitre": "mitre",
    "models": "models",
    "multi_model": "multi-model",
    "nmap": "recon",
    "ollama": "models/provider",
    "opencode_go": "providers",
    "operator_connection": "operator",
    "opsec": "opsec",
    "orchestrator": "autonomous",
    "outcome_judgment": "eval",
    "plugins": "plugins",
    "poc_verification": "poc",
    "providers": "providers",
    "reasoning": "reasoning",
    "recon": "recon",
    "replay_simulator": "—",
    "research": "research",
    "sandbox": "sandbox",
    "skills": "skills",
    "snapshots": "snapshots",
    "stealth": "opsec",
    "swarm": "swarm",
    "threat_intel": "threat_intel",
    "ticketing": "ticketing",
    "webhook_notify": "plugins",
    "witness": "witness",
}
SUBSYSTEM_OVERRIDES = {  # longest dotted-prefix match wins
    "models.info": "memory/context",
    "models.roles": "reasoning",
    "models.registry": "models",
    "models.provider": "providers",
}
# New keys under daemon/router-owned blocks need a restart to take effect.
RESTART_YES_TOPS = {"api", "models", "mcp", "engine_mcp", "ollama", "chatgpt", "opencode_go", "providers", "embeddings"}

PRESERVED = ("allowed", "consumers", "effect", "env", "restart", "subsystem", "tests")


def load_schema_defaults() -> dict:
    src = SCHEMA_PATH.read_text()
    tree = ast.parse(src)
    for node in tree.body:
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.target.id == "CONFIG_SCHEMA":
            return ast.literal_eval(node.value)
        if isinstance(node, ast.Assign) and any(
            isinstance(t, ast.Name) and t.id == "CONFIG_SCHEMA" for t in node.targets
        ):
            return ast.literal_eval(node.value)
    raise ValueError("CONFIG_SCHEMA not found in schema.py")


def walk_leaves(obj, prefix=""):
    """Yield (dotted_path, value) for every leaf; empty dicts count as leaves."""
    if isinstance(obj, dict) and obj:
        for k, v in obj.items():
            path = f"{prefix}.{k}" if prefix else str(k)
            yield from walk_leaves(v, path)
    else:
        yield prefix, obj


def top_line_map(raw_lines, tops):
    """Map each top-level key to its line number in the raw YAML text."""
    found = {}
    for i, line in enumerate(raw_lines, 1):
        m = re.match(r"^(\S[^:]*):", line)
        if m and m.group(1) in tops and m.group(1) not in found:
            found[m.group(1)] = i
    return found


def split_row(line):
    """Split on unescaped pipes; the Allowed cell may hold `\\|`."""
    inner = line.strip().strip("|")
    cells = [c.strip() for c in re.split(r"(?<!\\)\|", inner)]
    if len(cells) <= 11:
        return cells
    # Only Allowed holds pipes: rejoin everything between Default and Source.
    src_idx = next((i for i, c in enumerate(cells) if c.startswith("`config.yaml")), None)
    if src_idx is None:
        return cells
    head = cells[:3] + [" | ".join(cells[3:src_idx])]
    return head + cells[src_idx:]


def parse_existing(text):
    """Return {dotted_key: {cell-name: raw cell text}} for current table rows."""
    # Repair `\|` cells mangled to `\ |` by an earlier buggy run of this
    # script (idempotent: a clean `\|` has no whitespace, so is unchanged).
    # Done on raw text BEFORE splitting: the stray space un-escapes the pipe
    # and would otherwise shift every column after it.
    text = re.sub(r"\\\s+\|", "\\\\|", text)
    rows = {}
    for line in text.splitlines():
        if not line.startswith("| `"):
            continue
        cells = split_row(line)
        if len(cells) < 11 or cells[0].strip("`") == "Key":
            continue
        key = cells[0].strip("`").strip()
        rows[key] = {
            "type": cells[1],
            "default": cells[2],
            "allowed": cells[3],
            "source": cells[4],
            "consumers": cells[5],
            "effect": cells[6],
            "env": cells[7],
            "restart": cells[8],
            "subsystem": cells[9],
            "tests": cells[10] if len(cells) > 10 else "—",
        }
    return rows


def fmt_type(lab, sch):
    sample = lab
    if isinstance(lab, list) and not lab and isinstance(sch, list) and sch:
        sample = sch
    if isinstance(sample, bool):
        return "`bool`"
    if isinstance(sample, int):
        return "`int`"
    if isinstance(sample, float):
        return "`float`"
    if isinstance(sample, str):
        return "`str`"
    if isinstance(sample, list):
        if sample and all(isinstance(x, str) for x in sample):
            return "`list[str]`"
        if sample and all(isinstance(x, int) and not isinstance(x, bool) for x in sample):
            return "`list[int]`"
        return "`list`"
    if isinstance(sample, dict):
        return "`dict`"
    return "`str`"


def fmt_default(key, lab, schema_leaves):
    if key not in schema_leaves:
        return f"`{lab!r} (lab-only, not in CONFIG_SCHEMA)`"
    sch = schema_leaves[key]
    if sch == lab:
        return f"`{lab!r}`"
    return f"`{sch!r} (schema) → {lab!r} (lab)`"


def subsystem_for(key):
    for prefix in sorted(SUBSYSTEM_OVERRIDES, key=len, reverse=True):
        if key == prefix or key.startswith(prefix + "."):
            return SUBSYSTEM_OVERRIDES[prefix]
    return SUBSYSTEM_BY_TOP.get(key.split(".")[0], key.split(".")[0])


def main():
    today = date.today().isoformat()
    raw_text = CONFIG_PATH.read_text()
    cfg = yaml.safe_load(raw_text)
    schema = load_schema_defaults()
    lab_leaves = dict(walk_leaves(cfg))
    schema_leaves = dict(walk_leaves(schema))
    lines_map = top_line_map(raw_text.splitlines(), set(cfg.keys()))

    existing = parse_existing(OUT_PATH.read_text())
    n_blocks = len(cfg)

    out_rows = []
    for key in sorted(lab_leaves):
        lab = lab_leaves[key]
        top = key.split(".")[0]
        line_no = lines_map.get(top, "?")
        if key in schema_leaves:
            rest = key[len(top) + 1 :] if "." in key else ""
            schema_ref = f"`CONFIG_SCHEMA['{top}']" + (f".{rest}`" if rest else "`")
            source = f"`config.yaml:{line_no}` + {schema_ref}"
        else:
            source = f"`config.yaml:{line_no}` (lab extra)"
        old = existing.get(key, {})
        if old:
            row = {
                "type": fmt_type(lab, schema_leaves.get(key)),
                "default": fmt_default(key, lab, schema_leaves),
                "source": source,
                **{c: old[c] for c in PRESERVED},
            }
        else:
            row = {
                "type": fmt_type(lab, schema_leaves.get(key)),
                "default": fmt_default(key, lab, schema_leaves),
                "allowed": "—",
                "source": source,
                "consumers": "",
                "effect": "—",
                "env": "—",
                "restart": "yes" if top in RESTART_YES_TOPS else "no",
                "subsystem": subsystem_for(key),
                "tests": "—",
            }
        out_rows.append(
            f"| `{key}` | {row['type']} | {row['default']} | {row['allowed']} "
            f"| {row['source']} | {row['consumers']} | {row['effect']} "
            f"| {row['env']} | {row['restart']} | {row['subsystem']} "
            f"| {row['tests']} |"
        )

    text = OUT_PATH.read_text()
    text_lines = text.splitlines()
    hdr = next(i for i, ln in enumerate(text_lines) if ln.startswith("| Key |"))
    end = next(i for i, ln in enumerate(text_lines[hdr:], hdr) if not text_lines[i].startswith("|"))
    head = text_lines[:hdr]
    tail = text_lines[end:]
    head = [re.sub(r"\(\d{4}-\d{2}-\d{2}\)", f"({today})", ln) for ln in head]
    head = [
        re.sub(
            r"_Generated \d{4}-\d{2}-\d{2} from `config\.yaml` "
            r"\(\d+ leaf keys, \d+ top-level blocks\)",
            f"_Generated {today} from `config.yaml` ({len(lab_leaves)} leaf keys, {n_blocks} top-level blocks)",
            ln,
        )
        for ln in head
    ]
    sep = text_lines[hdr + 1]
    new_text = "\n".join(head + [text_lines[hdr], sep] + out_rows + tail) + "\n"
    OUT_PATH.write_text(new_text)

    n_new = sum(1 for k in lab_leaves if k not in existing)
    n_lab_only = sum(1 for k in lab_leaves if k not in schema_leaves)
    print(f"keys={len(lab_leaves)} blocks={n_blocks} new={n_new} lab_only={n_lab_only} date={today}")


if __name__ == "__main__":
    main()
