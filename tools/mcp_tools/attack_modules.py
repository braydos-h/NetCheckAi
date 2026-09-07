"""Attack Modules MCP tool registration — registry+ranking only (split from god file)."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from tools.attack_modules import ModuleContext, get_module, list_modules
from tools.exceptions import _EXC_GROUP_CATCH, _log_nested_exceptions
from tools.mcp_tools.modules.hash import _identify_hash_modes
from tools.mcp_tools.registry import ToolContext
from tools.validation_utils import validate_target_or_ip

# Re-exported for backwards compat: cracking.py and modules/synthesis.py
# import _identify_hash_modes from here. Single source lives in
# tools/mcp_tools/modules/hash.py.
__all__ = ["_identify_hash_modes", "register_attack_module_tools"]


def register_attack_module_tools(mcp: Any, *, ctx: ToolContext) -> None:
    workspace = ctx.workspace
    config = ctx.config
    search = ctx.search
    nvd = ctx.nvd
    researcher = ctx.researcher
    audit_tool = ctx.audit_tool
    require_allowlist = ctx.require_allowlist

    @mcp.tool()
    @audit_tool
    def list_attack_modules() -> str:
        """List all registered pre-packaged attack modules.

        Returns a formatted list of every AttackModule with its name, description,
        target services, target ports, and required CVEs. Use this to discover
        available exploit recipes before running them with run_attack_module.

        Returns:
            Formatted list of all registered attack modules.

        Example:
            list_attack_modules()
        """
        try:
            modules = list_modules()
            if not modules:
                return "NO_MODULES: No attack modules registered."

            lines = [f"ATTACK_MODULES: {len(modules)} available", ""]
            for mod in modules:
                lines.append(f"  [{mod.name}]")
                lines.append(f"    Description: {mod.description}")
                lines.append(f"    Target Services: {', '.join(mod.target_services) if mod.target_services else 'any'}")
                lines.append(f"    Target Ports: {mod.target_ports if mod.target_ports else 'any'}")
                lines.append(f"    Required CVEs: {', '.join(mod.required_cves) if mod.required_cves else 'none'}")
                lines.append("")
            return "\n".join(lines)
        except _EXC_GROUP_CATCH as exc:
            _log_nested_exceptions(exc)
            return f"ERROR: Module listing failed — {exc}"

    @mcp.tool()
    @require_allowlist()
    def run_attack_module(module_name: str, target_ip: str, options: str = "") -> str:
        """Execute a pre-packaged attack module against a target IP.

        Looks up the module by name, checks applicability against the target context
        (loading recon results if available), and executes the module. If the module
        generates a Python script, it is saved to the workspace.

        Args:
            module_name: Name of the attack module (e.g., 'SSHBruteForce', 'Log4jRCE').
                         Use list_attack_modules to see all available modules.
            target_ip: IPv4 address of the target host.
            options: Optional key=value pairs separated by spaces for module parameters
                (e.g. "callback_host=10.0.0.5 timeout=30"). Parsed into the module
                context parameters; unknown keys are ignored by modules that do not read them.

        Returns:
            Structured result: applicability score, success/failure, output summary,
            and script path if a Python exploit was generated.

        Example:
            run_attack_module("SSHBruteForce", "192.168.1.100", "timeout=30 threads=4")
        """
        if not validate_target_or_ip(target_ip):
            return "ERROR: Invalid target (IP or domain)."

        try:
            module = get_module(module_name)
            if module is None:
                return f"ERROR: Module '{module_name}' not found. Use list_attack_modules to see available modules."

            # Build context — try to load recon results for richer context
            services: list[dict[str, str]] = []
            target_os: str | None = None
            cves: list[str] = []

            # Search for the most recent recon_result.json for this target
            for attempt_dir in sorted(
                workspace.glob("*"), key=lambda p: p.stat().st_mtime if p.exists() else 0, reverse=True
            ):
                recon_file = attempt_dir / "recon_result.json"
                if recon_file.exists():
                    try:
                        recon_data = json.loads(recon_file.read_text(encoding="utf-8"))
                        if recon_data.get("target_ip") == target_ip:
                            target_os = recon_data.get("os_family")
                            for svc in recon_data.get("services", []):
                                services.append(
                                    {
                                        "service": svc.get("service", ""),
                                        "port": f"{svc.get('port', '')}/{svc.get('protocol', 'tcp')}",
                                        "version": svc.get("version", ""),
                                    }
                                )
                            # Extract CVEs from script results
                            for svc in recon_data.get("services", []):
                                for script_id, output in svc.get("scripts", {}).items():
                                    cve_matches = re.findall(r"CVE-\d{4}-\d{4,}", output)
                                    cves.extend(cve_matches)
                            break
                    except (json.JSONDecodeError, KeyError):
                        pass

            # Parse `options` ("k=v k=v", shlex) into ctx.parameters so
            # parameterized modules (callback hosts, ports, wordlists) can
            # read them. Unknown/malformed pairs are ignored, never fatal.
            parameters: dict[str, str] = {}
            if options and options.strip():
                try:
                    import shlex as _shlex

                    for pair in _shlex.split(options):
                        if "=" in pair:
                            k, v = pair.split("=", 1)
                            if k.strip():
                                parameters[k.strip()] = v
                except ValueError:  # shlex.split on a malformed options string; ignore, never fatal
                    parameters = {}

            # Thread recovered credentials for this target so cred-gated
            # modules (PassTheHash, DCSyncAttack, LateralMovement, ...) score
            # and behave differently when creds exist. Best-effort: a vault
            # read failure leaves credentials empty, never breaks the call.
            credentials: list[dict[str, str]] = []
            try:
                from tools.credential_store import CredentialStore

                store = CredentialStore(workspace)
                for rec in store.credentials_for_host(target_ip):
                    entry: dict[str, str] = {"username": rec.username}
                    if rec.password:
                        entry["password"] = rec.password
                    credentials.append(entry)
            except (OSError, ValueError, TypeError, KeyError):  # vault read failure leaves creds empty
                credentials = []

            ctx = ModuleContext(
                target_ip=target_ip,
                target_os=target_os,
                services=services,
                cves=cves,
                workspace=workspace,
                credentials=credentials,
                parameters=parameters,
            )

            # Check applicability
            score = module.applicability(ctx)
            if score == 0:
                try:
                    report = module.applicability_explain(ctx)
                    why = "; ".join(report.penalties) or "no match"
                except _EXC_GROUP_CATCH:  # arbitrary plugin code; explain must never break the call
                    why = "Module does not match any known services or CVEs on this target."
                return (
                    f"MODULE_RESULT: not_applicable\n"
                    f"MODULE: {module_name}\n"
                    f"TARGET: {target_ip}\n"
                    f"APPLICABILITY_SCORE: 0\n"
                    f"REASON: {why}"
                )

            # Execute module
            result = module.run(ctx)

            # Save generated script if present
            script_path = ""
            script_text = result.get("script", "")
            if script_text:
                modules_dir = workspace / "modules"
                modules_dir.mkdir(parents=True, exist_ok=True)
                safe_name = re.sub(r"[^A-Za-z0-9_.-]", "_", f"{module_name}_{target_ip}.py")
                script_path = str(modules_dir / safe_name)
                Path(script_path).write_text(script_text, encoding="utf-8")

            # Also try generate_python_script if run didn't produce one
            if not script_text:
                try:
                    script_text = module.generate_python_script(ctx)
                    if script_text:
                        modules_dir = workspace / "modules"
                        modules_dir.mkdir(parents=True, exist_ok=True)
                        safe_name = re.sub(r"[^A-Za-z0-9_.-]", "_", f"{module_name}_{target_ip}.py")
                        script_path = str(modules_dir / safe_name)
                        Path(script_path).write_text(script_text, encoding="utf-8")
                except Exception:  # ponytail: bare except intentional
                    pass

            lines = [
                f"MODULE_RESULT: {result.get('status', 'executed')}",
                f"MODULE: {module_name}",
                f"TARGET: {target_ip}",
                f"APPLICABILITY_SCORE: {score}",
            ]
            if result.get("note"):
                lines.append(f"NOTE: {result['note']}")
            if result.get("suggested_command"):
                lines.append(f"SUGGESTED_COMMAND: {result['suggested_command']}")
            if result.get("suggested_msf"):
                lines.append(f"SUGGESTED_MSF: {result['suggested_msf']}")
            # Phase 2.1: render the compromise / credential signals a typed
            # ModuleResult (or an enriched dict from the autonomous executor)
            # carries. These keys are what ``AttackState.record_success`` reads
            # to flip ``access_achieved`` -- surfacing them here lets the MCP
            # caller see whether a module verified a real foothold.
            if result.get("shell_type"):
                lines.append(f"SHELL_TYPE: {result['shell_type']}")
            if result.get("privilege_level"):
                lines.append(f"PRIVILEGE_LEVEL: {result['privilege_level']}")
            creds = result.get("credentials_found") or result.get("credentials") or []
            if creds:
                creds_str = "; ".join(
                    c if isinstance(c, str) else " ".join(f"{k}={v}" for k, v in c.items()) for c in creds
                )
                lines.append(f"CREDENTIALS_FOUND: {creds_str}")
            if result.get("evidence"):
                lines.append(f"EVIDENCE: {'; '.join(str(e) for e in result['evidence'])}")
            if result.get("references"):
                lines.append(f"REFERENCES: {'; '.join(str(r) for r in result['references'])}")
            if result.get("confidence") is not None:
                lines.append(f"CONFIDENCE: {result['confidence']}")
            if result.get("verdict") not in (None, "", "inconclusive"):
                lines.append(f"VERDICT: {result['verdict']}")
            # Advisory extras previously invisible to MCP callers (workflow /
            # techniques / prompt carriers / produced artifacts / follow-ups).
            if result.get("workflow"):
                steps = result["workflow"]
                steps_txt = "; ".join(str(s) for s in steps) if isinstance(steps, list) else str(steps)
                lines.append(f"WORKFLOW: {steps_txt[:2000]}")
            if result.get("techniques"):
                lines.append(f"TECHNIQUES: {str(result['techniques'])[:2000]}")
            if result.get("produced_artifacts"):
                lines.append(f"PRODUCED_ARTIFACTS: {'; '.join(str(a) for a in result['produced_artifacts'])}")
            if result.get("follow_ups"):
                lines.append(f"FOLLOW_UPS: {'; '.join(str(f) for f in result['follow_ups'])}")
            if result.get("prompt_template"):
                lines.append(f"PROMPT_TEMPLATE:\n{str(result['prompt_template'])[:2000]}")
            if script_path:
                lines.append(f"SCRIPT_SAVED: {script_path}")
            if result.get("script"):
                lines.append(f"SCRIPT_PREVIEW:\n{result['script'][:500]}")

            return "\n".join(lines)
        except Exception as exc:  # ponytail: bare except intentional
            return f"ERROR: Module execution failed — {exc}"
