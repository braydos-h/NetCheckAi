"""Web scanner MCP tool registration.

Structured first-class wrapper around the Kali web scanners the agent
otherwise shells out to via ``run_exploit_terminal`` (nikto/nuclei/sqlmap/
gobuster/feroxbuster/whatweb/wpscan/dirb/dirbuster). Gives parsed output,
consistent audit records, and the same target-IP allowlist lock the shell-out
path already has (``_extract_scanner_targets`` already recognizes these verbs).

Nuclei interop: ``run_web_scan`` with ``scanner="nuclei"`` also persists the
machine-readable ``nuclei.jsonl`` next to ``<scanner>.log``;
``parse_nuclei_results`` maps those events to ``TechnicalFinding`` records and
``generate_nuclei_template`` turns a confirmed finding back into a reusable
Nuclei template. The parse/generate tools are local-only (no target arg, no
network).
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any

import yaml

from tools.enhanced_reporting import CVSSScore, TechnicalFinding
from tools.mcp_shared import _attempt_dir
from tools.mcp_tools.registry import ToolContext, _run_with_pgrp_timeout
from tools.validation_utils import validate_target_or_ip

_NUCLEI_JSONL_NAME = "nuclei.jsonl"
_NUCLEI_FINDINGS_NAME = "nuclei-findings.json"
_NUCLEI_TEMPLATE_PREFIX = "nuclei-template-"

_SEVERITY_DEFAULT_CVSS: dict[str, float] = {
    "critical": 9.1,
    "high": 7.5,
    "medium": 5.0,
    "low": 3.0,
    "info": 0.0,
}
_SEVERITY_TITLE: dict[str, str] = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "info": "Info",
}
_NUCLEI_SEVERITIES = ("critical", "high", "medium", "low", "info")

_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,128}$")


def _slug(value: Any, default: str = "unknown", limit: int = 40) -> str:
    """Filesystem/id-safe slug (empty -> ``default``)."""
    text = re.sub(r"[^A-Za-z0-9]+", "-", str(value or "").strip()).strip("-")
    return (text or default)[:limit].strip("-") or default


def _normalize_nuclei_severity(value: Any) -> str:
    """Nuclei severity string -> one of critical/high/medium/low/info."""
    sev = str(value or "").strip().lower()
    return sev if sev in _SEVERITY_TITLE else "info"


def _valid_local_id(value: str) -> bool:
    """True for safe workspace-local ids (no traversal, no separators)."""
    return bool(_ID_RE.match(value)) and ".." not in value and "/" not in value and "\\" not in value


def _mitre_technique_for_template(template_id: str) -> str:
    """ATT&CK technique for a Nuclei template id (overridable map, T1595 fallback)."""
    try:
        from tools.mitre_export import load_technique_map

        technique_map = load_technique_map(Path(__file__).resolve().parent.parent / "mitre_technique_map.json")
    except Exception:  # ponytail: map failure never breaks parsing
        technique_map = {}
    return technique_map.get(template_id) or technique_map.get("run_web_scan") or "T1595"


def _nuclei_event_to_finding(rec: dict[str, Any]) -> TechnicalFinding | None:
    """Map one Nuclei JSONL event to a ``TechnicalFinding`` (None when unusable)."""
    template_id = str(rec.get("template-id") or rec.get("templateID") or rec.get("template_id") or "").strip()
    if not template_id:
        return None  # ponytail: skip events with no template id, don't crash
    info = rec.get("info")
    if not isinstance(info, dict):
        info = {}
    name = str(info.get("name") or template_id).strip() or template_id
    severity = _normalize_nuclei_severity(info.get("severity"))
    classification = info.get("classification")
    if not isinstance(classification, dict):
        classification = {}
    raw_score = classification.get("cvss-score", classification.get("cvss_score"))
    try:
        base_score = (
            float(str(raw_score).strip())
            if raw_score is not None and str(raw_score).strip()
            else _SEVERITY_DEFAULT_CVSS[severity]
        )
    except (TypeError, ValueError):
        base_score = _SEVERITY_DEFAULT_CVSS[severity]
    base_score = min(max(base_score, 0.0), 10.0)
    vector = str(classification.get("cvss-metrics") or classification.get("cvss_metrics") or "").strip()
    matched = str(rec.get("matched-at") or rec.get("matched_at") or "").strip()
    host = str(rec.get("host") or rec.get("ip") or matched or "unknown").strip() or "unknown"
    asset = matched or host
    matcher = str(rec.get("matcher-name") or rec.get("matcher_name") or "").strip()
    evidence: list[str] = []
    if rec.get("request"):
        evidence.append(f"request: {str(rec['request'])[:500]}")
    if rec.get("response"):
        evidence.append(f"response: {str(rec['response'])[:500]}")
    if not evidence and matched:
        evidence.append(f"matched-at: {matched[:500]}")
    repro = [f"Run nuclei with template '{template_id}' against {asset}: nuclei -u {asset} -id {template_id}"]
    if matcher:
        repro.append(f"Matcher that fired: {matcher}")
    technique = _mitre_technique_for_template(template_id)
    references: list[str] = []
    for key in ("reference", "references"):
        value = info.get(key)
        if isinstance(value, list):
            references.extend(str(r)[:300] for r in value if str(r or "").strip())
        elif isinstance(value, str) and value.strip():
            references.append(value.strip()[:300])
    references.append(f"https://attack.mitre.org/techniques/{technique.replace('.', '/')}/")
    title = name if name == template_id else f"{name} ({template_id})"
    return TechnicalFinding(
        finding_id=f"NUCLEI-{_slug(template_id)}-{_slug(host)}",
        title=title[:200],
        affected_asset=asset[:300],
        vuln_class=template_id[:200],
        severity=_SEVERITY_TITLE[severity],
        cvss=CVSSScore(base_score=base_score, vector_string=vector[:300], severity=_SEVERITY_TITLE[severity]),
        confidence=0.7,
        summary=(
            f"Nuclei template '{template_id}' ({name}) matched on {asset} "
            f"with {severity} severity (ATT&CK {technique})."
        )[:1000],
        reproduction_steps=repro,
        evidence_refs=evidence,
        remediation=(
            f"Investigate the '{name}' exposure on {asset}, apply the vendor fix or workaround, "
            f"then re-run nuclei -id {template_id} to verify."
        )[:500],
        references=references[:10],
    )


def _template_matcher_word(record: dict[str, Any]) -> str:
    """Best-effort word matcher token from finding evidence, else a generic word."""
    texts: list[str] = []
    for ref in record.get("evidence_refs") or []:
        if isinstance(ref, str) and ref:
            texts.append(ref)
    texts.append(str(record.get("title") or ""))
    for tok in re.findall(r"[A-Za-z0-9][A-Za-z0-9_.\-/]{3,63}", "\n".join(texts)):
        if tok.lower() not in {"request", "response", "matched", "http", "https", "nuclei"}:
            return tok[:64]
    return "vulnerable"


def _render_nuclei_template(record: dict[str, Any]) -> tuple[str, str]:
    """Render a Nuclei template YAML from a finding record. Returns (yaml_text, template_id)."""
    fid = str(record.get("finding_id") or "finding")
    vuln_class = str(record.get("vuln_class") or fid)
    slug = re.sub(r"[^a-z0-9-]+", "-", vuln_class.lower()).strip("-") or "finding"
    slug = slug[:64].strip("-") or "finding"
    severity = _normalize_nuclei_severity(record.get("severity"))
    title = str(record.get("title") or vuln_class)[:150]
    summary = str(record.get("summary") or title)[:1000]
    asset = str(record.get("affected_asset") or "")[:300]
    cvss = record.get("cvss")
    raw_base = cvss.get("base_score") if isinstance(cvss, dict) else None
    try:
        base_score = float(raw_base) if raw_base is not None else _SEVERITY_DEFAULT_CVSS[severity]
    except (TypeError, ValueError):
        base_score = _SEVERITY_DEFAULT_CVSS[severity]
    vector = str(cvss.get("vector_string") or "")[:300] if isinstance(cvss, dict) else ""
    refs = [str(r)[:300] for r in (record.get("references") or []) if r]
    technique = _mitre_technique_for_template(vuln_class)
    mitre_url = f"https://attack.mitre.org/techniques/{technique.replace('.', '/')}/"
    if mitre_url not in refs:
        refs.append(mitre_url)
    classification: dict[str, Any] = {"cvss-score": base_score}
    if vector:
        classification["cvss-metrics"] = vector
    doc = {
        "id": slug,
        "info": {
            "name": title,
            "author": "breachpilot",
            "severity": severity,
            "description": summary,
            "reference": refs or [mitre_url],
            "classification": classification,
            "metadata": {"finding-id": fid, "affected-asset": asset, "mitre-technique": technique},
        },
        "http": [
            {
                "method": "GET",
                "path": ["{{BaseURL}}"],
                "matchers": [
                    {"type": "word", "words": [_template_matcher_word(record)], "part": "body", "condition": "or"}
                ],
            }
        ],
    }
    return yaml.safe_dump(doc, sort_keys=False, allow_unicode=False), slug


def _check_nuclei_template_schema(parsed: Any) -> str:
    """Nuclei template shape check. Returns "" when valid, else a short reason."""
    if not isinstance(parsed, dict):
        return "top-level mapping required"
    if not parsed.get("id"):
        return "missing template id"
    info = parsed.get("info")
    if not isinstance(info, dict):
        return "missing info block"
    for key in ("name", "severity", "description"):
        if not info.get(key):
            return f"missing info.{key}"
    if str(info.get("severity")).lower() not in (*_NUCLEI_SEVERITIES, "unknown"):
        return f"bad severity {info.get('severity')!r}"
    blocks = parsed.get("http") or parsed.get("requests")
    if not isinstance(blocks, list) or not blocks:
        return "missing http/requests block"
    for block in blocks:
        if not isinstance(block, dict):
            return "bad http block"
        matchers = block.get("matchers")
        if not isinstance(matchers, list) or not matchers:
            return "missing matchers"
        for matcher in matchers:
            if not isinstance(matcher, dict) or not matcher.get("type"):
                return "bad matcher (type required)"
    return ""


def _validate_nuclei_template(path: Path, text: str) -> tuple[str, str]:
    """Validate template YAML (parse-back + schema, plus ``nuclei -validate`` when on PATH)."""
    try:
        parsed = yaml.safe_load(text)
    except Exception as exc:  # ponytail: invalid YAML is a finding, not a crash
        return "INVALID", f"YAML parse failed: {exc}"[:500]
    schema_err = _check_nuclei_template_schema(parsed)
    if schema_err:
        return "INVALID", schema_err
    if not shutil.which("nuclei"):
        return "VALID", "schema check only (nuclei not on PATH)"
    try:
        returncode, out, err = _run_with_pgrp_timeout(
            ["nuclei", "-t", str(path), "-validate"],
            60,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except subprocess.TimeoutExpired:
        return "INVALID", "nuclei -validate timed out after 60s"
    except Exception as exc:  # ponytail: validator failure is INVALID, not a crash
        return "INVALID", f"nuclei -validate failed: {exc}"[:500]
    combined = f"{out or ''}\n{err or ''}".strip()[-1000:]
    if returncode == 0:
        return "VALID", "nuclei -validate passed" if not combined else f"nuclei -validate passed: {combined[:500]}"
    return "INVALID", combined or f"nuclei -validate exited {returncode}"


def register_web_scan_tools(mcp: Any, *, ctx: ToolContext) -> None:
    workspace = ctx.workspace
    config = ctx.config
    audit_tool = ctx.audit_tool
    require_allowlist = ctx.require_allowlist

    _SCANNERS = {"nikto", "nuclei", "sqlmap", "gobuster", "feroxbuster", "whatweb", "wpscan", "dirb", "dirbuster"}

    # Default wordlist for directory-content scanners (Kali standard location).
    _DEFAULT_WORDLIST = "/usr/share/wordlists/dirb/common.txt"

    def _build_argv(scanner: str, target_ip: str, port: int, path: str) -> list[str]:
        url = f"http://{target_ip}:{port}{path}" if path else f"http://{target_ip}:{port}"
        if scanner == "nikto":
            return ["nikto", "-h", target_ip, "-p", str(port)]
        if scanner == "nuclei":
            return ["nuclei", "-u", url]
        if scanner == "sqlmap":
            return ["sqlmap", "-u", url, "--batch"]
        if scanner in {"gobuster", "feroxbuster", "dirb", "dirbuster"}:
            return [scanner, "dir", "-u", url, "-w", _DEFAULT_WORDLIST]
        if scanner == "whatweb":
            return ["whatweb", url]
        if scanner == "wpscan":
            return ["wpscan", "--url", url, "--enumerate", "u"]
        # Unreachable: caller gates on _SCANNERS, but keep a sane fallback.
        return [scanner, url]

    def _resolve_attempt(attempt_id: str) -> tuple[Path | None, str]:
        """Workspace-contained attempt dir for ``attempt_id`` (error "" on success)."""
        attempt_dir = workspace / attempt_id
        try:
            root = workspace.resolve()
            resolved = attempt_dir.resolve()
        except OSError:
            return None, f"BLOCKED: could not resolve attempt_id {attempt_id!r}."
        try:
            resolved.relative_to(root)
        except ValueError:
            return None, f"BLOCKED: attempt_id {attempt_id!r} is outside the workspace."
        return resolved, ""

    @mcp.tool()
    @require_allowlist()
    def run_web_scan(
        scanner: str,
        target_ip: str,
        port: int = 80,
        path: str = "",
        options: str = "",
        timeout: int = 300,
    ) -> str:
        """Run a web scanner (nikto/nuclei/sqlmap/gobuster/feroxbuster/whatweb/wpscan/dirb/dirbuster) against the target. Returns the scanner's parsed output. The target must be in the explicit allowlist. ``options`` are extra scanner flags (space-separated, no shell metacharacters)."""
        if not scanner or not scanner.strip():
            return "BLOCKED: scanner is required."
        sc = scanner.strip().lower()
        if sc not in _SCANNERS:
            return f"BLOCKED: unsupported scanner '{sc}'. Allowed: {', '.join(sorted(_SCANNERS))}."
        if not target_ip or not target_ip.strip():
            return "BLOCKED: target_ip is required."
        if not validate_target_or_ip(target_ip):
            return "BLOCKED: target_ip must be a valid IP address or domain."
        if isinstance(port, str) and port.strip().isdigit():
            port = int(port.strip())
        if not isinstance(port, int) or isinstance(port, bool) or port < 1 or port > 65535:
            return "BLOCKED: port must be an integer between 1 and 65535."
        # Allowlist itself is enforced by @require_allowlist() on target_ip.

        # Sanitize extra options: shlex tokens, reject shell metacharacters
        # (mirrors generate_payload / run_msf_module so a malicious options
        # string can't inject into a shell -- though we never use a shell).
        extra_argv: list[str] = []
        opts = options.strip() if options else ""
        if opts:
            if re.search(r"[;|&$`()]|<|>|\n", opts):
                return "BLOCKED: options contains forbidden shell metacharacters."
            import shlex as _shlex

            try:
                extra_argv = _shlex.split(opts)
            except ValueError:
                return "BLOCKED: options string could not be parsed (unbalanced quotes)."

        if not shutil.which(sc) and getattr(ctx, "sandbox", None) is None:
            return (
                f"SCANNER_NOT_INSTALLED: {sc} is not on PATH. "
                f"Install it (e.g. apt install {sc}) on the operator box and retry."
            )

        argv = _build_argv(sc, target_ip, port, path.strip())
        argv.extend(extra_argv)
        cmd = " ".join(argv)  # reported for operator visibility

        # Nuclei JSONL path: machine-readable events for parse_nuclei_results.
        # Relative filename + cwd=attempt_dir so the host run and the sandbox
        # run (cwd_host=attempt_dir, mapped into the worker) persist it next
        # to <scanner>.log. Operator flags win: skip any flag already present.
        is_nuclei = sc == "nuclei"
        nuclei_attempt: tuple[Path, str] | None = None
        if is_nuclei:
            if "-jsonl" not in argv and "-json" not in argv:
                argv.append("-jsonl")
            if "-nc" not in argv:
                argv.append("-nc")
            if "-o" not in argv and "-output" not in argv:
                argv.extend(["-o", _NUCLEI_JSONL_NAME])
            nuclei_attempt = _attempt_dir(workspace)
            cmd = " ".join(argv)

        # ---- sandbox path: the scanner runs inside the disposable worker
        # (no host PATH requirement; only the scanners baked into the worker
        # image are available -- the base image is minimal by design).
        if getattr(ctx, "sandbox", None) is not None:
            from tools.mcp_tools.sandbox_exec import run_argv_in_sandbox, sandbox_error_block
            from tools.sandbox.exceptions import SandboxError

            attempt_dir, attempt_id = nuclei_attempt if nuclei_attempt is not None else _attempt_dir(workspace)
            log_path = attempt_dir / f"{sc}.log"
            start = time.monotonic()
            _elapsed = 0.0
            try:
                _ran, result = run_argv_in_sandbox(
                    ctx,
                    argv,
                    target_ip=str(target_ip),
                    command=cmd,
                    timeout=timeout,
                    cwd_host=attempt_dir,
                    tool_name=f"run_web_scan:{sc}",
                )
                _elapsed = result.duration_seconds
                output = (result.stdout or "") + ("\n" + result.stderr if result.stderr else "")
                output = output[-4000:]
                returncode = result.exit_code
                status = result.status
                if returncode == 127 or "No such file or directory" in output:
                    # The base worker image ships a minimal toolset (nmap, curl,
                    # netcat, git) -- whatweb/nikto/etc. live in a derived
                    # image. Say so explicitly so the agent picks another
                    # scanner instead of retrying the same missing binary.
                    output += (
                        f"\nHINT: scanner {sc!r} is not installed in the sandbox worker image "
                        "(breachpilot-sandbox:latest). Do not retry it; use a Python stdlib probe "
                        "via write_python_file + run_python_file, or extend a derived image "
                        "(FROM breachpilot-sandbox:latest) with the scanner."
                    )
            except SandboxError as exc:
                return f"WEB_SCAN_RESULT: blocked\n{sandbox_error_block(exc, tool_name='run_web_scan')}"
            try:
                log_path.write_text(str(output), encoding="utf-8")
            except OSError:
                pass
            return (
                f"WEB_SCAN_RESULT: {status}\n"
                f"ATTEMPT_ID: {attempt_id}\n"
                f"SCANNER: {sc}\n"
                f"TARGET: {target_ip}:{port}\n"
                f"COMMAND: {cmd}\n"
                f"EXIT_CODE: {returncode}\n"
                f"DURATION: {_elapsed:.1f}s (sandbox)\n"
                f"OUTPUT:\n{output}"
            )

        attempt_dir, attempt_id = nuclei_attempt if nuclei_attempt is not None else _attempt_dir(workspace)
        log_path = attempt_dir / f"{sc}.log"
        start = time.monotonic()
        try:
            returncode, out, err = _run_with_pgrp_timeout(
                argv,
                timeout,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                cwd=str(attempt_dir) if is_nuclei else None,
            )
            output = (out + "\n" + err)[-4000:]
            status = "completed" if returncode == 0 else "failed"
        except subprocess.TimeoutExpired:
            status = "timed_out"
            output = f"{sc} timed out after {timeout}s"
            returncode = None
        except Exception as exc:  # ponytail: bare except intentional
            status = "error"
            output = str(exc)
            returncode = None

        elapsed = time.monotonic() - start

        # Persist the raw scan log for the audit trail / later read_workspace_file.
        try:
            log_path.write_text(str(output), encoding="utf-8")
        except OSError:
            pass

        return (
            f"WEB_SCAN_RESULT: {status}\n"
            f"ATTEMPT_ID: {attempt_id}\n"
            f"SCANNER: {sc}\n"
            f"TARGET: {target_ip}:{port}\n"
            f"COMMAND: {cmd}\n"
            f"EXIT_CODE: {returncode}\n"
            f"DURATION: {elapsed:.1f}s\n"
            f"OUTPUT:\n{output}"
        )

    @mcp.tool()
    @audit_tool
    def parse_nuclei_results(attempt_id: str = "") -> str:
        """Parse a prior nuclei scan's JSONL events into confirmed-candidate TechnicalFindings (local only: no target arg, no network). Returns a NUCLEI_FINDINGS summary; full records are saved as nuclei-findings.json in the attempt dir."""
        if not attempt_id or not str(attempt_id).strip():
            return "BLOCKED: attempt_id is required."
        aid = str(attempt_id).strip()
        if not _valid_local_id(aid):
            return f"BLOCKED: invalid attempt_id {aid!r}."
        attempt_dir, err = _resolve_attempt(aid)
        if err or attempt_dir is None:
            return err
        jsonl_path = attempt_dir / _NUCLEI_JSONL_NAME
        if not attempt_dir.is_dir() or not jsonl_path.is_file():
            return (
                f"NUCLEI_FINDINGS: 0 confirmed-candidate\n"
                f"ATTEMPT_ID: {aid}\n"
                f"NOTE: no {_NUCLEI_JSONL_NAME} in this attempt (run run_web_scan with scanner nuclei first)."
            )
        try:
            text = jsonl_path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            return (
                f"NUCLEI_FINDINGS: 0 confirmed-candidate\nATTEMPT_ID: {aid}\nNOTE: could not read nuclei.jsonl: {exc}"
            )
        seen: set[tuple[str, str]] = set()
        by_id: dict[str, TechnicalFinding] = {}
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except (ValueError, json.JSONDecodeError):
                continue  # ponytail: skip malformed line, don't crash
            if not isinstance(rec, dict):
                continue
            finding = _nuclei_event_to_finding(rec)
            if finding is None:
                continue
            key = (finding.vuln_class, finding.affected_asset)
            if key in seen:
                continue  # dedup by (template-id, host)
            seen.add(key)
            fid = finding.finding_id
            suffix = 2
            while fid in by_id:
                fid = f"{finding.finding_id}-{suffix}"
                suffix += 1
            finding.finding_id = fid
            by_id[fid] = finding
        records = [f.to_dict() for f in by_id.values()]
        try:
            (attempt_dir / _NUCLEI_FINDINGS_NAME).write_text(
                json.dumps(records, indent=2, default=str), encoding="utf-8"
            )
        except OSError:
            pass
        lines = [f"NUCLEI_FINDINGS: {len(records)} confirmed-candidate", f"ATTEMPT_ID: {aid}"]
        for finding in list(by_id.values())[:20]:
            lines.append(
                f"FINDING: {finding.finding_id} | {finding.severity} | "
                f"{finding.vuln_class} | {finding.affected_asset} | "
                f"{_mitre_technique_for_template(finding.vuln_class)}"
            )
        if len(records) > 20:
            lines.append(f"... +{len(records) - 20} more (see {_NUCLEI_FINDINGS_NAME})")
        else:
            lines.append(f"SAVED: {_NUCLEI_FINDINGS_NAME} (full TechnicalFinding records)")
        return "\n".join(lines)

    @mcp.tool()
    @audit_tool
    def generate_nuclei_template(finding_id: str = "") -> str:
        """Generate a reusable Nuclei template YAML from a confirmed finding (local only: no target arg, no network). Validates by parsing the YAML back plus nuclei -validate when on PATH; reports VALID/INVALID."""
        if not finding_id or not str(finding_id).strip():
            return "BLOCKED: finding_id is required."
        fid = str(finding_id).strip()
        if not _valid_local_id(fid):
            return f"BLOCKED: invalid finding_id {fid!r}."
        record: dict[str, Any] | None = None
        source_dir: Path | None = None
        workspace.mkdir(parents=True, exist_ok=True)
        try:
            candidates = sorted(workspace.rglob(_NUCLEI_FINDINGS_NAME))
        except OSError:
            candidates = []
        for path in candidates:
            try:
                data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
            except (OSError, ValueError):
                continue  # ponytail: skip unreadable findings files, don't crash
            if not isinstance(data, list):
                continue
            for item in data:
                if isinstance(item, dict) and item.get("finding_id") == fid:
                    record = item
                    source_dir = path.parent
                    break
            if record is not None:
                break
        if record is None or source_dir is None:
            return f"BLOCKED: unknown finding_id {fid!r} (run parse_nuclei_results first)."
        template_text, template_slug = _render_nuclei_template(record)
        out_path = source_dir / f"{_NUCLEI_TEMPLATE_PREFIX}{fid}.yaml"
        try:
            out_path.write_text(template_text, encoding="utf-8")
        except OSError as exc:
            return f"NUCLEI_TEMPLATE: INVALID\nFINDING: {fid}\nDETAIL: could not write template: {exc}"
        verdict, detail = _validate_nuclei_template(out_path, template_text)
        try:
            rel = out_path.resolve().relative_to(workspace.resolve()).as_posix()
        except (OSError, ValueError):
            rel = out_path.name
        lines = [
            f"NUCLEI_TEMPLATE: {verdict}",
            f"FINDING: {fid}",
            f"TEMPLATE_ID: {template_slug}",
            f"PATH: {rel}",
            f"ATTEMPT_ID: {source_dir.name}",
        ]
        if detail:
            lines.append(f"DETAIL: {detail}")
        return "\n".join(lines)
