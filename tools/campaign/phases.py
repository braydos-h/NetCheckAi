"""Campaign phases — exploitation / privesc / lateral / validation / persistence.

Extracted from AutonomousOrchestrator to keep each file <1000 LOC / 72kB.
These are the phase handlers that were previously methods on AutonomousOrchestrator;
they are defined here as functions and bound to the orchestrator class after import
to preserve the original ``self._phase_*`` call sites without an extra base class.

Each function takes ``self`` (the orchestrator instance) as first arg so the
body can stay verbatim from the monolith.
"""

from __future__ import annotations

import asyncio
import re
from pathlib import Path
from typing import Any

from tools.attack_modules import ModuleContext
from tools.logging_setup import get_logger
from tools.validation_utils import is_local_target

from tools.campaign.state import AttackPhase, AttackState, AttackTask, TaskStatus, _report_autonomous_progress

logger = get_logger()

from tools.attack_ui import get_ui

ui = get_ui()


async def _phase_local_takeover(self, state: AttackState) -> None:
    """Local-target playbook (Gap 2): the operator box IS the target.

    The network-brute-force phase (recon -> exploit -> lateral) attacks the
    box's own listeners -- the wrong shape when the operator is already on
    the host. Instead, read the local filesystem FIRST (the LOCAL TARGET
    PLAYBOOK from ``tools/exploit_agent/prompt.py``), then go straight to
    privilege escalation. The privesc modules (``LinuxPrivescCheck``,
    ``SUIDEnumeration``, ``KernelExploitCheck``, ``ContainerBreakout``) do
    their own local enumeration and still route through
    ``AttackModuleExecutor.execute`` -> ``scope_gate.check_scope``.

    The raw local-read commands run via the optional ``tool_executor``
    callback when wired; if it is None (standalone orchestrator), the reads
    are skipped and only the privesc modules run.
    """
    logger.info(f"[LOCAL] Target {state.target} is this host -- local-takeover phase")
    ui.phase_change("local_takeover")
    state.current_phase = AttackPhase.PRIVILEGE_ESCALATION
    _report_autonomous_progress(phase=state.current_phase.value, target=state.target)
    state.add_timeline_event(
        "local_takeover",
        "Local-target playbook: filesystem enumeration + privilege escalation",
    )

    # The playbook's local-read commands (mirrors exploit_agent/prompt.py
    # LOCAL TARGET PLAYBOOK). Best-effort: a failure in one command does
    # not abort the phase.
    local_cmds = [
        "cat /etc/passwd",
        "sudo -n cat /etc/shadow 2>/dev/null",
        "ls -la /home/*/.ssh /root/.ssh 2>/dev/null",
        "find / -perm -4000 -type f 2>/dev/null",
        "find / -perm -2000 -type f 2>/dev/null",
        "find / -writable -type d 2>/dev/null | head",
        "cat /etc/crontab; ls -la /etc/cron.*; crontab -l 2>/dev/null",
        "ls -la /opt /srv /var/www /etc/mysql",
        "grep -rIl 'password' /etc/ 2>/dev/null | head",
        "env; cat ~/.bash_history ~/.zsh_history 2>/dev/null",
    ]
    if self._tool_executor:
        for cmd in local_cmds:
            try:
                out = await asyncio.to_thread(
                    self._tool_executor,
                    cmd,
                    {"target": state.target},
                )
                state.add_timeline_event("local_read", cmd, {"output_len": len(str(out or ""))})
            except Exception as exc:  # noqa: BLE001 -- best-effort reads
                state.add_timeline_event("local_read_err", f"{cmd}: {exc}")
    else:
        state.add_timeline_event(
            "local_read_skipped",
            "No tool_executor wired -- privesc modules still run local enumeration",
        )

    # Privesc modules do their own local enumeration (SUID, kernel, container).
    await self._phase_privilege_escalation(state)


async def _phase_reconnaissance(self, state: AttackState) -> None:
    """Run deep reconnaissance and store results.

    Tier 1.3 resume: if ``state.recon_result`` already carries open ports
    (rebuilt from ``attack_states.json`` by ``load_state``), the prior
    run's recon is REUSED rather than re-scanned. Re-scanning on resume
    would defeat the entire point of reattaching: it's the loudest,
    slowest, most detection-prone phase, and the operator resumed
    specifically to avoid redoing it. An empty/missing prior recon (fresh
    start, or a prior run that found nothing) falls through to a real
    scan as before.
    """
    logger.info(f"[RECON] Starting reconnaissance against {state.target}")
    ui.phase_change("reconnaissance")
    state.current_phase = AttackPhase.RECONNAISSANCE
    _report_autonomous_progress(phase=state.current_phase.value, target=state.target)
    state.add_timeline_event("phase_start", "Reconnaissance phase started")

    if state.recon_result and state.recon_result.open_ports:
        logger.info(
            f"[RECON] Resuming with prior recon ({len(state.recon_result.open_ports)} ports) — skipping re-scan"
        )
        state.add_timeline_event(
            "recon_reused",
            f"Reused prior recon with {len(state.recon_result.open_ports)} open ports",
            {"ports": state.recon_result.open_ports, "resumed": True},
        )
        return

    recon_result = await self._recon.recon_host(state.target)
    state.recon_result = recon_result

    if recon_result.open_ports:
        state.add_timeline_event(
            "recon_complete",
            f"Found {len(recon_result.open_ports)} open ports",
            {"ports": recon_result.open_ports, "services": [s.service for s in recon_result.services]},
        )
        logger.info(f"[RECON] Found {len(recon_result.open_ports)} ports on {state.target}")
    else:
        state.add_timeline_event("recon_empty", "No open ports found")

    # Domain targeting: when the operator gave a domain, run subdomain
    # expansion after the primary recon to discover the full attack
    # surface. Each discovered (subdomain, ip) pair is auto-authorized
    # via add_discovered_target so the agent can attack them. This is
    # best-effort: a failure degrades to no expansion (the primary
    # target is still attacked). The actual subdomain discovery uses
    # the same crt.sh + DNS bruteforce as the enumerate_subdomains MCP
    # tool, but runs inline here (Path B has no MCP session).
    if state.original_target and state.original_target != state.target:
        try:
            from tools.mcp_shared import add_discovered_target
            from tools.validation_utils import is_fqdn, is_subdomain_of, resolve_target_to_ip

            if is_fqdn(state.original_target):
                logger.info(
                    f"[RECON] Domain target {state.original_target} -- "
                    f"expanding attack surface via subdomain enumeration"
                )
                # Reuse the crt.sh passive source (no external dep).
                import json as _json
                import urllib.request as _urlreq

                dom = state.original_target.strip().lower()
                try:
                    req = _urlreq.Request(
                        f"https://crt.sh/?q=%25.{dom}&output=json",
                        headers={"User-Agent": "BreachPilot-Orchestrator/1.0"},
                    )
                    with _urlreq.urlopen(req, timeout=20) as resp:  # noqa: S310
                        body = resp.read().decode(errors="replace")
                    subs: set[str] = set()
                    if body:
                        for row in _json.loads(body):
                            for nv in str(row.get("name_value", "")).splitlines():
                                for s in nv.split(","):
                                    s = s.strip().lstrip("*.").strip().lower()
                                    if s and is_subdomain_of(s, dom) and s != dom:
                                        subs.add(s)
                    for sub in sorted(subs)[:200]:
                        ip = resolve_target_to_ip(sub)
                        if ip:
                            state.discovered_subdomains.append({"subdomain": sub, "ip": ip})
                            add_discovered_target(sub, ip, source="campaign:subdomain_expansion")
                except Exception as exc:
                    logger.warning(f"[RECON] Subdomain expansion failed for {dom}: {exc}")
                if state.discovered_subdomains:
                    state.add_timeline_event(
                        "subdomain_expansion",
                        f"Discovered {len(state.discovered_subdomains)} subdomains",
                        {"subdomains": state.discovered_subdomains[:20]},
                    )
                    logger.info(
                        f"[RECON] Discovered {len(state.discovered_subdomains)} subdomains of {state.original_target}"
                    )
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning(f"[RECON] Domain expansion hook failed: {exc}")


async def _phase_exploitation(self, state: AttackState, *, skip_failed: bool = False) -> None:
    """Automatically select and execute attack modules based on recon.

    ``skip_failed`` (Phase 2.4 adaptive replan) drops modules that already
    failed this campaign from the ranked list, so an adaptive round attacks
    a different surface instead of re-attacking the same dead module.
    Default False preserves the single-pass behavior.
    """
    logger.info(f"[EXPLOIT] Starting exploitation against {state.target}")
    ui.phase_change("exploitation")
    state.current_phase = AttackPhase.EXPLOITATION
    _report_autonomous_progress(phase=state.current_phase.value, target=state.target)
    state.add_timeline_event("phase_start", "Exploitation phase started")

    if not state.recon_result:
        logger.warning("No recon result available for exploitation")
        return

    # Get applicable modules sorted by score
    # Evidence-aware ranking: carry version + CPE + the full per-service CVE
    # list (the audit flagged these were dropped -- the ranking's
    # service:version:os signature at registry.py:249-298 needs version to
    # query the ExperienceStore, and the dormant Bayesian boost never fired
    # because experience_store was never passed).
    ctx = self._module_context(state)

    # shim-aware: tests patch tools.autonomous_orchestrator.find_modules
    try:
        import tools.autonomous_orchestrator as _ao_shim  # type: ignore[import]

        _find_modules = getattr(_ao_shim, "find_modules", None)
    except Exception:
        _find_modules = None
    if _find_modules is None:
        from tools.attack_modules import find_modules as _find_modules  # type: ignore[import]
    scored_modules = _find_modules(ctx, experience_store=self._experience_store)
    if skip_failed:
        # Adaptive replan: exclude modules that already failed this campaign
        # so the round tries a different attack surface. Preserves ranking.
        failed = set(state.failed_attempts.keys())
        scored_modules = [(s, m) for (s, m) in scored_modules if m.name not in failed]
        logger.info(
            f"[EXPLOIT] Adaptive replan: {len(scored_modules)} modules after dropping {len(failed)} previously-failed"
        )
    logger.info(f"[EXPLOIT] {len(scored_modules)} applicable modules found")

    # Create attack tasks for top modules
    tasks: list[AttackTask] = []
    ranked_names: set[tuple[str, str]] = set()  # (module_name, port) for dedupe
    for score, module in scored_modules[:15]:  # Top 15 modules
        # Derive the effective port from the module's primary service if
        # available, so service-specific tasks (below) can dedupe against it.
        _port = ""
        for s in state.recon_result.services:
            if s.service.lower() in {t.lower() for t in module.target_services}:
                _port = f"{s.port}/{s.protocol}"
                break
        ranked_names.add((module.name, _port))
        task = AttackTask(
            task_id=self._new_task_id(),
            phase=AttackPhase.EXPLOITATION,
            module_name=module.name,
            target=state.target,
            parameters={"score": score, **module.to_json()},
            aggression=state.aggression,
            priority=score,
        )
        tasks.append(task)
        self._tasks[task.task_id] = task

    # Also add service-specific tasks, skipping any that duplicate a ranked
    # module (same name + port). The audit flagged the ranked and
    # service-specific lists were merged without dedupe, so the same module
    # could execute twice against the same port.
    service_tasks = self._create_service_specific_tasks(state)
    for st in service_tasks:
        _key = (st.module_name, str(st.parameters.get("port", "")))
        if _key in ranked_names:
            logger.info(f"[EXPLOIT] Dropping duplicate service task {st.module_name} on {_key[1]}")
            continue
        tasks.append(st)

    # Execute tasks with concurrency limit
    await self._execute_task_batch(tasks, state)

    # If no success and aggression can be escalated, retry with higher aggression
    if not state.access_achieved and state.aggression != self._max_aggression:
        state.escalate_aggression()
        logger.info(f"[EXPLOIT] Escalating aggression to {state.aggression.value}, retrying failed modules")
        await self._retry_failed_modules(state)


async def _phase_privilege_escalation(self, state: AttackState) -> None:
    """Attempt privilege escalation after successful exploitation."""
    logger.info(f"[PRIVESC] Starting privilege escalation against {state.target}")
    ui.phase_change("privilege_escalation")
    state.current_phase = AttackPhase.PRIVILEGE_ESCALATION
    _report_autonomous_progress(phase=state.current_phase.value, target=state.target)
    state.add_timeline_event("phase_start", "Privilege escalation phase started")

    privesc_modules = []
    if state.recon_result and "linux" in state.recon_result.os_family.lower():
        privesc_modules = ["LinuxPrivescCheck", "SUIDEnumeration", "KernelExploitCheck"]
    elif state.recon_result and "windows" in state.recon_result.os_family.lower():
        privesc_modules = ["WindowsPrivescCheck", "TokenImpersonation", "ServiceMisconfiguration"]
    else:
        privesc_modules = ["LinuxPrivescCheck", "WindowsPrivescCheck", "ContainerBreakout"]

    # Phase 4: cloud/container privesc modules were previously unreachable
    # from Path B (they appeared in NO privesc list). Gate them on the
    # recon port set intersecting the cloud/container API surface
    # (Docker 2375/2376, kubelet 10250, kube-apiserver 6443, IMDS-adjacent
    # 80/443) OR an os_family hint of cloud/container. The modules
    # themselves stay target-locked (they run ON the owned target).
    if state.recon_result:
        open_ports = {s.port for s in state.recon_result.services}
        cloud_ports = {2375, 2376, 10250, 6443, 443, 80}
        os_hint = (state.recon_result.os_family or "").lower()
        if open_ports & cloud_ports or "cloud" in os_hint or "container" in os_hint:
            privesc_modules += [
                "CloudPrivesc",
                "K8sPrivesc",
                "IMDSExploit",
                "DockerSockEscape",
                "S3BucketTakeover",
            ]

    tasks: list[AttackTask] = []
    for mod_name in privesc_modules:
        task = AttackTask(
            task_id=self._new_task_id(),
            phase=AttackPhase.PRIVILEGE_ESCALATION,
            module_name=mod_name,
            target=state.target,
            aggression=state.aggression,
            priority=80,
        )
        tasks.append(task)
        self._tasks[task.task_id] = task

    await self._execute_task_batch(tasks, state)

    # Phase 3: advisory local_exploit_suggester follow-up. Only when the
    # config flag is on AND access was achieved (so a meterpreter session
    # plausibly exists). The module is info-only -- it suggests the MSF
    # recipe and does NOT fabricate a session id (Path B has none).
    if self._auto_local_exploit_suggester and state.access_achieved:
        les_task = AttackTask(
            task_id=self._new_task_id(),
            phase=AttackPhase.PRIVILEGE_ESCALATION,
            module_name="LocalExploitSuggester",
            target=state.target,
            aggression=state.aggression,
            priority=60,
        )
        self._tasks[les_task.task_id] = les_task
        await self._executor.execute(les_task, state)
        state.add_timeline_event(
            "local_exploit_suggester",
            "Advisory local_exploit_suggester follow-up dispatched (info-only)",
        )


async def _phase_lateral_movement(self, state: AttackState, _depth: int = 0) -> None:
    """Attempt lateral movement to discovered pivot targets.

    ``_depth`` is the pivot-hop count of the calling target; further recursion
    is capped at ``self._max_pivot_depth`` (Tier 0 item 0.6a) and any pivot we
    have already attacked is skipped (visited guard) so a rediscovered host
    can't loop the campaign.
    """
    logger.info(f"[LATERAL] Starting lateral movement from {state.target} (pivot depth {_depth})")
    ui.phase_change("lateral_movement")
    state.current_phase = AttackPhase.LATERAL_MOVEMENT
    _report_autonomous_progress(phase=state.current_phase.value, target=state.target)
    state.add_timeline_event("phase_start", "Lateral movement phase started")

    # Gap 2: defense-in-depth. A local target has no internal network to
    # pivot to from itself; even if pivot_targets somehow got populated,
    # never recurse from a local host.
    if is_local_target(state.target):
        state.add_timeline_event(
            "lateral_skip_local",
            "Skipping lateral movement -- target is this host (no pivot from self)",
        )
        logger.info(f"[LATERAL] Skipping lateral movement for local target {state.target}")
        return

    for pivot in state.pivot_targets[:5]:  # Limit to 5 pivot targets per level
        if pivot in self._states:
            state.add_timeline_event("lateral_skip", f"Skipping already-attacked pivot {pivot}")
            continue
        task = AttackTask(
            task_id=self._new_task_id(),
            phase=AttackPhase.LATERAL_MOVEMENT,
            module_name="LateralMovement",
            target=pivot,
            parameters={"source": state.target},
            aggression=state.aggression,
            priority=70,
        )
        self._tasks[task.task_id] = task
        result = await self._executor.execute(task, state)
        if result.get("success"):
            state.add_timeline_event("lateral_success", f"Moved to {pivot}")
            # Recursively attack the new target, capped at max_pivot_depth so
            # a pivot chain can't run away (the old code recursed unbounded).
            if _depth + 1 < self._max_pivot_depth:
                await self._attack_target(pivot, _depth=_depth + 1)
            else:
                state.add_timeline_event(
                    "pivot_depth_cap",
                    f"Pivot-depth cap ({self._max_pivot_depth}) reached; not recursing into {pivot}",
                )
                logger.info(f"[LATERAL] Pivot-depth cap reached at {pivot} (depth {_depth + 1})")
        else:
            state.add_timeline_event("lateral_failed", f"Failed to move to {pivot}: {result.get('error')}")


async def _phase_validation(self, state: AttackState) -> None:
    """Validate all findings and generate evidence."""
    logger.info(f"[VALIDATE] Starting validation for {state.target}")
    ui.phase_change("validation")
    state.current_phase = AttackPhase.VALIDATION
    _report_autonomous_progress(phase=state.current_phase.value, target=state.target)
    state.add_timeline_event("phase_start", "Validation phase started")

    # Validate each successful exploit
    for exploit in state.successful_exploits:
        task = AttackTask(
            task_id=self._new_task_id(),
            phase=AttackPhase.VALIDATION,
            module_name="ValidateFinding",
            target=state.target,
            parameters={"exploit": exploit},
            priority=90,
        )
        self._tasks[task.task_id] = task
        await self._executor.execute(task, state)


# ── Phase 2.2: Persistence (opt-in) ──────────────────────────────────

_PERSISTENCE_MARKER_RE = re.compile(r"PERSISTENCE_INSTALLED:\s*(\S+)", re.IGNORECASE)


def _extract_persistence_marker(self, output_text: str) -> str | None:
    """Return the lowercased persistence method a dispatch output confirms.

    Persistence modules print ``PERSISTENCE_INSTALLED: <method>`` (cron /
    schtask / webshell) when they install a foothold. Unlike shell
    compromise, this is NOT a signal ``classify_exploit_result`` looks for
    (persistence runs after access is achieved), so the handler scans the
    raw dispatch output itself.
    """
    m = _PERSISTENCE_MARKER_RE.search(str(output_text or ""))
    return m.group(1).lower() if m else None


def _module_context(
    self,
    state: AttackState,
    task: AttackTask | None = None,
) -> ModuleContext:
    """Build the ModuleContext the attack modules expect from current state.

    Carries version + CPE + the full per-service CVE list (the audit flagged
    these were dropped, so the ranking's service:version:os signature at
    registry.py:249-298 always read an empty version and the Bayesian boost
    never fired). The CVE list now pulls from openssh_cves plus any CVE the
    recon pipeline attached to the service's scripts (broader than the
    OpenSSH-only gate).

    Capability-upgrade (§12): threads live attack state (access/priv/
    sessions/phase/evidence_refs) and, when a task is supplied, its
    parameters -- the audit flagged this builder omitted ``parameters``
    while the execute() builder omitted the live-state fields. The
    ``task`` kwarg is optional so existing call sites (which pass only
    ``state``) stay byte-identical (``parameters`` defaults to {}).
    """
    services_full = []
    cves: list[str] = []
    import re as _re

    for s in state.recon_result.services if state.recon_result else []:
        services_full.append(
            {
                "service": s.service,
                "port": f"{s.port}/{s.protocol}",
                "version": s.version,
                "cpe": list(s.cpe),
                "banner": s.banner,
            }
        )
        # openssh_cves may be a list of CVE IDs OR a single string. Handle
        # both (the audit flagged a character-iteration bug where a string
        # value was iterated char-by-char into the CVE list).
        openssh = s.scripts.get("openssh_cves", [])
        if isinstance(openssh, str):
            cves.extend(_re.findall(r"CVE-\d{4}-\d{4,}", openssh, _re.IGNORECASE))
        else:
            for cve in openssh:
                cves.append(str(cve))
        # Also carry CVEs the recon pipeline attached under other script keys.
        for key, val in s.scripts.items():
            if key == "openssh_cves":
                continue
            if isinstance(val, str):
                cves.extend(_re.findall(r"CVE-\d{4}-\d{4,}", val, _re.IGNORECASE))
    return ModuleContext(
        target_ip=state.target,
        target_os=state.recon_result.os_family if state.recon_result else "",
        services=services_full,
        cves=sorted(set(cves)),
        # Phase 2: thread recovered creds + config so post-foothold modules
        # (persistence callback host, lateral movement) can read them.
        credentials=list(state.credentials_found),
        config=self._mission,
        # Capability-upgrade (§12): live attack state + task parameters so
        # modules queried via find_modules (and persistence modules) see
        # the same prerequisite/evidence surface the execute() builder
        # threads. ``parameters`` is {} when no task is supplied (the
        # legacy call shape) -> byte-identical with the prior builder.
        parameters=dict(task.parameters) if task is not None else {},
        access_achieved=state.access_achieved,
        privilege_level=state.privilege_level,
        sessions=([{"shell": state.shell_type}] if state.access_achieved and state.shell_type else []),
        phase=state.current_phase.value,
        evidence_refs=list(state.loot)[-10:],
    )


async def _phase_persistence(self, state: AttackState) -> None:
    """Establish persistence on a compromised host (Phase 2.2, opt-in).

    Runs only after ``access_achieved`` is True -- persisting on a host you
    do not yet control is meaningless. Selects OS-appropriate persistence
    modules (LinuxPersistence / WindowsPersistence) plus WebShellPersistence
    when a web service is exposed, dispatches each module's generated
    script through the wired ``tool_executor``, and records confirmed
    methods in ``state.persistence_established`` by scanning the dispatch
    output for the ``PERSISTENCE_INSTALLED:`` marker. Without a
    tool_executor the phase is skipped (best-effort, like the local-takeover
    reads). A failure in one module never aborts the phase.
    """
    if not state.access_achieved:
        return
    logger.info(f"[PERSIST] Starting persistence against {state.target}")
    ui.phase_change("persistence")
    state.current_phase = AttackPhase.PERSISTENCE
    _report_autonomous_progress(phase=state.current_phase.value, target=state.target)
    state.add_timeline_event("phase_start", "Persistence phase started")

    os_family = (state.recon_result.os_family if state.recon_result else "") or ""
    mod_names: list[str] = []
    if "windows" in os_family.lower():
        mod_names.append("WindowsPersistence")
    else:
        mod_names.append("LinuxPersistence")
    web_services = {"http", "https"}
    if state.recon_result and any((s.service or "").lower() in web_services for s in state.recon_result.services):
        mod_names.append("WebShellPersistence")

    if not self._tool_executor:
        state.add_timeline_event(
            "persistence_skipped",
            "No tool_executor wired -- persistence scripts not dispatched",
        )
        logger.info("[PERSIST] No tool_executor; persistence scripts not dispatched")
        return

    ctx = self._module_context(state)
    for mod_name in mod_names:
        # shim-aware get_module
        try:
            import tools.autonomous_orchestrator as _ao_shim2  # type: ignore[import]

            _get_module2 = getattr(_ao_shim2, "get_module", None)
        except Exception:
            _get_module2 = None
        if _get_module2 is None:
            from tools.attack_modules import get_module as _get_module2  # type: ignore[import]
        module = _get_module2(mod_name)
        if module is None:
            state.add_timeline_event("persistence_skip", f"Module {mod_name} unavailable")
            continue
        try:
            mresult_dict = await asyncio.to_thread(module.run, ctx) or {}
        except Exception as exc:  # noqa: BLE001 -- one bad module shouldn't abort the phase
            state.add_timeline_event("persistence_err", f"{mod_name}.run: {exc}")
            continue
        script = mresult_dict.get("script") or mresult_dict.get("suggested_command") or ""
        if not script:
            state.add_timeline_event("persistence_skip", f"{mod_name}: no runnable artifact")
            continue
        task = AttackTask(
            task_id=self._new_task_id(),
            phase=AttackPhase.PERSISTENCE,
            module_name=mod_name,
            target=state.target,
            aggression=state.aggression,
            priority=60,
        )
        self._tasks[task.task_id] = task
        try:
            out = await asyncio.to_thread(
                self._tool_executor,
                script,
                {"target": state.target, "module": mod_name},
            )
        except Exception as exc:  # noqa: BLE001 -- dispatch failure is not fatal
            task.status = TaskStatus.FAILED
            task.error = str(exc)
            state.add_timeline_event("persistence_err", f"{mod_name} dispatch: {exc}")
            continue
        marker = self._extract_persistence_marker(str(out or ""))
        if marker:
            state.persistence_established.append(marker)
            task.status = TaskStatus.COMPLETED
            task.result = {"status": "success", "persistence": marker}
            state.add_timeline_event(
                "persistence_established",
                f"{mod_name} installed persistence via {marker}",
                {"module": mod_name, "method": marker},
            )
        else:
            task.status = TaskStatus.FAILED
            task.error = "no PERSISTENCE_INSTALLED marker in dispatch output"
            state.add_timeline_event(
                "persistence_failed",
                f"{mod_name} dispatch did not confirm persistence",
                {"module": mod_name},
            )


# ── Phase 2.4: Adaptive replan + vuln-chaining (opt-in) ──────────────


async def _run_adaptive_rounds(self, state: AttackState, _depth: int) -> None:
    """Run the exploit/privesc/lateral sequence as a bounded multi-round loop.

    Each round re-runs exploitation with already-failed modules dropped
    (adaptive replan), then privesc + lateral if their gates fire, then
    schedules vuln-chain metadata from the round's successes. The loop
    stops when ``state.should_continue()`` is False (access at max
    privilege and no pivot targets remain), the round cap
    (``max_cycles``) is hit, OR a round produces no novel candidate tasks
    (audit: the loop used to spin empty rounds after all modules were
    dropped, because ``should_continue()`` stayed true on
    ``not access_achieved`` even with nothing left to try). Bounded by
    construction -- no unbounded recursion, no re-attacking the same dead
    module forever.
    """
    max_rounds = max(1, int(self._max_cycles))
    rounds = 0
    while rounds < max_rounds and self._running:
        rounds += 1
        state.add_timeline_event("adaptive_round", f"Adaptive round {rounds}/{max_rounds}")
        logger.info(f"[ADAPTIVE] {state.target} round {rounds}/{max_rounds}")

        # Pre-round replan: skip_failed drops modules that already failed
        # this campaign so the round attacks a different surface.
        _tasks_before = len(self._tasks)
        await self._phase_exploitation(state, skip_failed=True)
        _tasks_after = len(self._tasks)

        # No-novel-candidate stop: if the exploitation phase created no new
        # tasks (all applicable modules already failed), continuing would
        # spin an empty round -- the audit flagged this could burn the full
        # ``max_cycles`` budget doing nothing. Stop instead.
        if _tasks_after == _tasks_before and not state.access_achieved:
            logger.info(
                f"[ADAPTIVE] {state.target} round {rounds}: no novel "
                f"candidate modules remain and no access achieved; stopping."
            )
            state.add_timeline_event(
                "adaptive_stop",
                "No novel candidate modules remain; stopping adaptive rounds.",
            )
            break

        if state.access_achieved and state.privilege_level not in ("system", "root", "admin"):
            await self._phase_privilege_escalation(state)
        if state.pivot_targets:
            await self._phase_lateral_movement(state, _depth)

        self._schedule_vuln_chain(state)

        # Phase 5: hard-target cutoff. If this round still produced no
        # access, count it. After ``hard_target_max_rounds`` consecutive
        # rounds without a foothold, give up on the target rather than
        # burning the remaining ``max_cycles`` budget on a host that has
        # answered nothing so far. Distinct from the no-novel-candidate
        # stop above (that one fires when there is literally nothing left
        # to try; this one fires when there IS plenty to try but it all
        # keeps failing). 0 = off (current behavior).
        if not state.access_achieved:
            state.hard_target_rounds += 1
            if self._hard_target_max_rounds and state.hard_target_rounds >= self._hard_target_max_rounds:
                logger.info(
                    f"[ADAPTIVE] {state.target} gave up after "
                    f"{state.hard_target_rounds} rounds with no access "
                    f"(hard_target_max_rounds={self._hard_target_max_rounds})"
                )
                state.add_timeline_event(
                    "hard_target_give_up",
                    f"Target {state.target} produced no access in "
                    f"{state.hard_target_rounds} adaptive rounds; giving up "
                    f"to preserve campaign budget for remaining targets.",
                    {"rounds": state.hard_target_rounds},
                )
                break

        if not state.should_continue():
            break


def _schedule_vuln_chain(self, state: AttackState) -> None:
    """Record vulnerability-chain metadata from the current foothold.

    Chains the last successful exploit -> harvested credentials -> discovered
    pivot targets into ``state.attack_paths`` (the report consumes these as
    the chain graph) and emits a ``vuln_chain_scheduled`` timeline event so
    the chain is observable. The actual lateral dispatch into pivot targets
    is handled by ``_phase_lateral_movement`` on the next round; this
    scheduler formalizes the chain links.
    """
    if not state.successful_exploits:
        return
    tail = f"exploit:{state.successful_exploits[-1]}"
    chains: list[list[str]] = []
    for cred in state.credentials_found[-3:]:
        chains.append([tail, f"creds:{cred}"])
    for pivot in state.pivot_targets[:5]:
        chains.append([tail, f"pivot:{pivot}"])
    if chains:
        state.attack_paths.extend(chains)
        state.add_timeline_event(
            "vuln_chain_scheduled",
            f"Scheduled {len(chains)} vuln-chain step(s) from {tail}",
            {"chains": chains},
        )


# ── Kill-chain state machine (design §killchain) ─────────────────────


def _killchain_context(state: AttackState) -> dict[str, Any]:
    """Playbook placeholders from the freshest usable credential.

    Entries may be dicts ({username, password/ntlm_hash, domain?}) or
    flattened "user=.. password=.." strings (ModuleResult.to_dict shape).
    Missing pieces stay "" so resolve_placeholders leaves a visible
    {token} instead of silently injecting structure.
    """
    ctx: dict[str, Any] = {"user": "", "password": "", "domain": "", "port": ""}
    for entry in reversed(list(getattr(state, "credentials_found", None) or [])):
        parts: dict[str, str] = {}
        if isinstance(entry, dict):
            parts = {str(k): str(v) for k, v in entry.items()}
        elif isinstance(entry, str):
            parts = dict(kv.split("=", 1) for kv in entry.split() if "=" in kv)
        user = parts.get("username") or parts.get("user", "")
        secret = parts.get("password") or parts.get("ntlm_hash", "")
        if user and secret:
            ctx["user"] = user
            ctx["password"] = secret
            ctx["domain"] = parts.get("domain", "")
            break
    return ctx


def _get_killchain_machine(self, state: AttackState) -> Any | None:
    """Build (once) the campaign's kill-chain machine, or None when off/unavailable.

    The machine's tool executor adapts the campaign's SYNC ``tool_executor``
    (the same dispatch ``AttackModuleExecutor`` uses) onto the async machine
    seam — edge playbooks therefore run through the exact same tool layer,
    so allowlist + audit semantics are unchanged. Any build failure degrades
    to None and the caller falls back to free-form planning.
    """
    if not getattr(self, "_killchain_enabled", False):
        return None
    if self._killchain_machine is not None:
        return self._killchain_machine
    try:
        from tools.intelligence.graph.store import AttackGraphStore
        from tools.killchain import KillChainMachine

        kc_cfg = (self._mission or {}).get("killchain", {}) or {}
        db_path = Path(str(kc_cfg.get("graph_db") or (self._workspace / "killchain_graph.db")))
        db_path.parent.mkdir(parents=True, exist_ok=True)

        def _sync_exec(tool_name: str, args: dict[str, Any]) -> str:
            if self._tool_executor is None:
                raise NotImplementedError("no tool executor wired for killchain playbooks")
            return str(self._tool_executor(tool_name, args))

        async def _executor(tool_name: str, args: dict[str, Any]) -> str:
            return await asyncio.to_thread(_sync_exec, tool_name, args)

        # shell_command verifies route through the same campaign tool layer
        # (sync callable shape); unwired -> UNVERIFIED fail-closed as before.
        _check_executor: Any | None = None
        if self._tool_executor is not None:
            from tools.eval_checks import default_check_executor

            _exec = self._tool_executor

            def _shell_call(tool_name: str, args: dict[str, Any]) -> str:
                return str(_exec(tool_name, args))

            _check_executor = default_check_executor(session=_shell_call, workspace=self._workspace)

        self._killchain_machine = KillChainMachine(
            graph_store=AttackGraphStore(db_path, scope=f"target:{state.target}"),
            workspace=self._workspace,
            config=self._mission,
            tool_executor=_executor,
            check_executor=_check_executor,
            run_dir=self._workspace,
            decision_log_enabled=bool(
                (((self._mission or {}).get("agent", {}) or {}).get("decision_log_enabled", True))
            ),
        )
        return self._killchain_machine
    except Exception as exc:  # noqa: BLE001 -- killchain must never break the campaign
        logger.debug("killchain machine build failed: %r", exc)
        self._killchain_machine = None
        return None


async def _phase_killchain(self, state: AttackState) -> bool:
    """Prefer verified kill-chain edges before free-form module planning.

    Opt-in via ``killchain.enabled`` (default off). Walks the BFS edge path
    from the target's current state toward the configured goal state,
    attempting each edge (up to twice per the design's fail-twice rule). The
    machine runs each playbook through the campaign tool executor and
    verifies independently — an unverified edge NEVER commits state. On the
    first unverified edge the phase gives up and the caller falls back to
    the normal module-planning phases.

    Returns True only when the FULL edge path verified (goal state reached —
    the caller skips free-form exploitation); False otherwise (verified
    partial progress is kept on the graph, but the caller falls back to the
    normal module-planning phases to finish the job).

    P3-11 pack gate: no snapshot net means fail fast with guidance
    (timeline event, no playbook runs) instead of running net-less.
    """
    try:
        from tools.snapshots import autonomy_pack_guidance as _pack_guidance

        _guidance = _pack_guidance(self._mission)
        if _guidance:
            state.add_timeline_event("killchain_blocked_no_snapshots", _guidance)
            return False
    except Exception:  # ponytail: bare except intentional — gate failure means no gate
        pass
    machine = self._get_killchain_machine(state)
    if machine is None:
        return False
    plan = machine.plan(state.target, self._killchain_goal_state)
    if not plan:
        state.add_timeline_event(
            "killchain_no_path",
            f"No registered kill-chain edge path to {self._killchain_goal_state}",
        )
        return False
    state.add_timeline_event(
        "killchain_plan",
        f"Kill-chain edge path selected: {' -> '.join(plan)}",
        {"path": plan},
    )
    progressed = False
    for edge_id in plan:
        edge = None
        try:
            from tools.killchain import get_edge

            edge = get_edge(edge_id)
        except Exception:  # noqa: BLE001
            edge = None
        if edge is None:
            return False
        result: dict[str, Any] = {}
        for _attempt in range(2):  # design: fall back after verification fails twice
            context = _killchain_context(state)
            result = await machine.attempt_transition(
                state.target,
                edge["from_state"],
                edge["to_state"],
                edge_id=edge_id,
                context=context,
            )
            if result.get("success"):
                break
        if not result.get("success"):
            state.add_timeline_event(
                "killchain_edge_failed",
                f"Edge {edge_id} not verified; falling back to free-form planning",
                {"edge_id": edge_id},
            )
            return False
        progressed = True
        to_state = edge["to_state"]
        state.add_timeline_event(
            "killchain_state_advanced",
            f"Verified transition via {edge_id}: {edge['from_state']} -> {to_state}",
            {"edge_id": edge_id, "to_state": to_state},
        )
        if to_state == "shell_as_user" and not state.access_achieved:
            state.access_achieved = True
            state.privilege_level = "user"
        elif to_state == "shell_as_root":
            state.access_achieved = True
            state.privilege_level = "root"
    # Full path verified — the goal state was reached via registered edges.
    return True


# ── Task execution ───────────────────────────────────────────────────


async def _attack_target(self, target: str, *, _depth: int = 0) -> dict[str, Any]:
    """Run full attack lifecycle against a single target.

    ``_depth`` tracks how many pivot hops from the operator's original
    target (depth 0) this call is. ``_phase_lateral_movement`` caps further
    recursion at ``self._max_pivot_depth`` so a chain of pivots can't run away.
    """
    if not self._running:
        return {"status": "stopped", "state": self.get_state(target).to_dict()}
    state = self.get_state(target)
    logger.info(f"Starting attack lifecycle for {target} (pivot depth {_depth})")
    state.add_timeline_event("campaign_start", f"Attack campaign started against {target}")

    # Gap 2: local-target short-circuit. If the target is the operator's
    # own host (loopback / a local interface), the network-brute-force
    # phase would attack our own listeners -- recon, exploit, and lateral
    # movement are all the wrong shape for "you are already on the box."
    # Run the local-takeover playbook (filesystem reads + privesc) instead.
    # The scope gate is NOT bypassed: _phase_privilege_escalation routes
    # through AttackModuleExecutor.execute -> scope_gate.check_scope(
    # asset=task.target) per CLAUDE.md -- the local shortcut only adds a
    # locality branch before the existing phase calls.
    if is_local_target(state.target):
        await self._phase_local_takeover(state)
        await self._phase_validation(state)
        state.add_timeline_event("campaign_end", "Local-takeover campaign completed for local target")
        return {"status": "complete", "state": state.to_dict()}

    # Phase 1: Deep reconnaissance
    await self._phase_reconnaissance(state)
    if not state.recon_result or not state.recon_result.open_ports:
        logger.warning(f"No open ports on {target}, ending campaign")
        state.add_timeline_event("no_attack_surface", "No open ports found")
        return {"status": "no_attack_surface", "state": state.to_dict()}

    # Phase 2: Service enumeration (already done in recon pipeline)
    state.current_phase = AttackPhase.ENUMERATION
    _report_autonomous_progress(phase=state.current_phase.value, target=state.target)

    # Phases 3-6. The default path is a single pass (exploit -> privesc ->
    # lateral -> persistence -> validation). When ``adaptive_replan`` is on
    # (Phase 2.4, opt-in) the exploit/privesc/lateral sequence runs as a
    # bounded multi-round loop with pre-round replan and post-success
    # vuln-chaining; persistence still runs once after the rounds converge.
    # Kill-chain preference (design §killchain, opt-in): before either
    # branch, attempt the verified edge path toward the configured goal
    # state. A fully-verified path short-circuits free-form planning; the
    # first unverified edge falls back to the normal phases unchanged.
    if self._killchain_enabled and await self._phase_killchain(state):
        pass  # verified edge path reached its goal (or progressed); keep the normal post-phases below
    elif self._adaptive_replan:
        await self._run_adaptive_rounds(state, _depth)
    else:
        # Phase 3: Exploitation - automatically select and run attack modules
        await self._phase_exploitation(state)

        # Phase 5: hard-target cutoff (single-pass path). _phase_exploitation
        # escalates aggression and retries once internally, so after it
        # returns with no access AND aggression already at the configured
        # ceiling there is nothing left to escalate into -- skip privesc /
        # lateral and let validation run. Opt-in (default off).
        if not state.access_achieved and self._hard_target_max_rounds and state.aggression >= self._max_aggression:
            logger.info(
                f"[HARD] {state.target} at max aggression with no access "
                f"-- giving up (hard_target_max_rounds={self._hard_target_max_rounds})"
            )
            state.add_timeline_event(
                "hard_target_give_up",
                f"Target {state.target} reached max aggression ({state.aggression.value}) with no access; giving up.",
                {"aggression": state.aggression.value},
            )

        # Phase 4: Privilege escalation
        if state.access_achieved and state.privilege_level not in ("system", "root", "admin"):
            await self._phase_privilege_escalation(state)

        # Phase 5: Lateral movement
        if state.pivot_targets:
            await self._phase_lateral_movement(state, _depth)

    # Phase 5.5: Persistence (opt-in, Phase 2.2). Only after a foothold is
    # established -- persisting on a host you do not yet control is a no-op.
    if self._persistence_enabled and state.access_achieved:
        await self._phase_persistence(state)

    # Phase 6: Validation
    await self._phase_validation(state)

    state.add_timeline_event("campaign_end", f"Attack campaign completed for {target}")
    return {"status": "complete", "state": state.to_dict()}
