"""Vulnerability Agent — specialist swarm agent for vulnerability research.

Deep vuln specialist with:
- Multi-source CVE correlation (NVD + Exploit-DB + web search)
- CVSS-aware exploitability scoring
- LLM-driven exploit path recommendation
- Attack module matching from recon findings
- Shared blackboard updates for exploit agent handoff
"""

from __future__ import annotations

import json
import time
from typing import Any

from tools.attack_modules import ModuleContext, find_modules, get_module
from tools.cve_lookup import CVESearchSettings, NVDClient, format_cve_results
from tools.exploit_search import ExploitSearch, ExploitSearchSettings
from tools.mcp_shared import build_researcher
from tools.swarm.base import Agent, AgentResult, AgentStatus
from tools.swarm.bb_compat import bb_set

_VULN_SYSTEM_PROMPT = """You are a VULNERABILITY RESEARCH SPECIALIST agent in an autonomous penetration testing swarm.

YOUR MISSION: Identify the most exploitable vulnerabilities on the target and recommend attack paths.

CAPABILITIES:
- Cross-reference CVEs across NVD, Exploit-DB, and public PoC databases
- Score exploitability based on: CVSS severity, exploit availability, service exposure, OS match
- Match discovered services to known attack modules (Log4j, EternalBlue, SMBGhost, etc.)
- Generate prioritized exploit recommendations with confidence scores

DEEP VULNERABILITY RESEARCH METHODOLOGY:
1. CVE CORRELATION: For each service+version pair:
   - Query NVD with CPE-formatted search: "cpe:2.3:a:vendor:product:version"
   - Cross-reference with Exploit-DB for working exploit code
   - Search GitHub/GitLab for public PoC repositories
   - Check Metasploit module database for existing modules
   - Look for write-ups on exploit-db.com, packetstorm, and 0day.today
2. EXPLOITABILITY SCORING (0.0-1.0):
   - Base score from CVSS v3 severity (Critical 9.0+ = 0.9, High 7.0+ = 0.7, Medium 4.0+ = 0.5, Low = 0.3)
   - +0.2 if Metasploit module exists (reliable, well-tested)
   - +0.15 if public Python PoC available on GitHub/Exploit-DB
   - +0.1 if exploit is remote (RCE) vs local (LPE)
   - +0.1 if no authentication required
   - -0.1 if exploit requires user interaction
   - -0.2 if target OS doesn't match exploit requirements
   - Cap at 1.0
3. ATTACK MODULE MATCHING:
   - Map services to known attack modules:
     SMB (445) → EternalBlue, SMBGhost, SMBRelay, PrintNightmare, PetitPotam
     RDP (3389) → BlueKeep, CVE-2019-0708, RDPScan
     HTTP/HTTPS → Log4j (if Java detected), Spring4Shell, Confluence, Struts2, SharePoint
     SSH (22) → OpenSSH user enumeration, weak cipher detection, CVE-2024-6387 (regreSSHion)
     WinRM (5985/5986) → Pass-the-Hash, credential brute force
     LDAP (389/636) → Anonymous bind, LDAP injection, domain enumeration
     MySQL/PostgreSQL → Authentication bypass, UDF privilege escalation
     Redis (6379) → Unauthorized access, master-slave RCE, cron/LUA sandbox escape
     Docker (2375/2376) → API exposure, container breakout
4. ATTACK CHAINING:
   - Identify multi-step attack paths:
     Anonymous FTP → upload webshell → RCE
     SMB null session → enumerate users → password spray → WinRM access
     SQL injection → extract hashes → crack → SSH/RDP login
     SSRF → hit internal services → metadata service → cloud creds
     LFI → log poisoning → RCE
5. PRIORITIZATION:
   - Sort by: exploitability_score × service_risk_score
   - Prefer remote over local exploits
   - Prefer authenticated over unauthenticated if creds available
   - Flag "quick wins": default creds, anonymous access, known RCE with public exploit

OUTPUT FORMAT:
- cves: [{id, cvss_score, cvss_vector, description, exploit_available, exploit_type, references, cpe_match}]
- exploits: [{id, title, path, type, platform, reliability, author, date}]
- hypotheses: [{service, version, port, cve_count, exploit_count, exploitability_score, confidence, recommended_module, attack_chain}]
- recommended_exploit_path: ordered list of exploit attempts with rationale, expected outcome, and fallback
- quick_wins: [{finding, action, expected_result, risk}]

RULES:
- Always check BOTH NVD and Exploit-DB for each service
- Prefer exploits with known Metasploit modules or public Python PoCs
- Score confidence higher when CVSS >= 7.0 AND exploit code is available
- Match services to attack modules from the module registry
- Update blackboard with findings for the ExploitAgent to consume
- If a service has no known CVEs, still check for misconfiguration-based attacks
- Consider the full attack chain, not just individual exploits
- Flag any service running on default ports with default credentials
"""


class VulnAgent(Agent):
    """Agent specialized in vulnerability identification and exploit discovery.

    Deep analysis with multi-source CVE correlation, CVSS scoring,
    attack module matching, and LLM-driven exploit path recommendation.
    """

    SYSTEM_PROMPT = _VULN_SYSTEM_PROMPT

    def run(self, task: dict[str, Any], context: dict[str, Any]) -> AgentResult:
        self._set_status(AgentStatus.RUNNING)
        start = time.monotonic()

        target = task.get("target", "")
        task_id = task.get("task_id", task.get("id", ""))
        services = task.get("services", [])
        config = context.get("config", {})
        # §13: prefer the role-routed planner client (models.roles.planner,
        # resolved by SwarmOrchestrator._ensure_role_clients) over the shared
        # default client. Unset -> shared client, unchanged behavior.
        model_client = context.get("planner_model_client") or context.get("model_client")
        blackboard = context.get("blackboard", {})

        # Pull services from blackboard if not in task
        if not services:
            services = blackboard.get("discovered_services", [])

        output: dict[str, Any] = {
            "target": target,
            "cves": [],
            "exploits": [],
            "hypotheses": [],
            "recommended_exploit_path": [],
        }
        evidence_refs: list[str] = []
        new_tasks: list[dict[str, Any]] = []
        memory_updates: list[dict[str, Any]] = []
        findings: list[dict[str, Any]] = []
        error = ""

        try:
            # ── Initialize search clients ──
            cve_cfg = config.get("cve_lookup", {})
            cve_client = NVDClient(
                CVESearchSettings(
                    enabled=bool(cve_cfg.get("enabled", True)),
                    timeout_seconds=int(cve_cfg.get("timeout_seconds", 30)),
                    max_results=int(cve_cfg.get("max_results", 5)),
                    rate_limit_seconds=float(cve_cfg.get("rate_limit_seconds", 6.0)),
                    circuit_failure_threshold=int(cve_cfg.get("circuit_failure_threshold", 5)),
                    circuit_recovery_timeout=float(cve_cfg.get("circuit_recovery_timeout", 60.0)),
                    epss_enabled=bool(cve_cfg.get("epss_enabled", False)),
                    kev_enabled=bool(cve_cfg.get("kev_enabled", False)),
                    kev_cache_ttl_seconds=int(cve_cfg.get("kev_cache_ttl_seconds", 86400)),
                    kev_cache_path=str(cve_cfg.get("kev_cache_path", "")),
                )
            )

            exploit_cfg = config.get("exploit", {})
            search_cfg = config.get("search", {})
            research_cfg = config.get("research", {}) or {}
            serpapi_cfg = research_cfg.get("serpapi", {}) or {}
            exploit_search = ExploitSearch(
                ExploitSearchSettings(
                    enabled=bool(exploit_cfg.get("enabled", False)),
                    searchsploit_path=str(exploit_cfg.get("searchsploit_path", "searchsploit")),
                    web_endpoint=str(
                        serpapi_cfg.get("endpoint", search_cfg.get("endpoint", "https://serpapi.com/search.json"))
                    ),
                    web_engine=str(serpapi_cfg.get("engine", search_cfg.get("engine", "duckduckgo"))),
                    web_api_key_env=str(
                        serpapi_cfg.get("api_key_env", search_cfg.get("api_key_env", "SERPAPI_API_KEY"))
                    ),
                    web_timeout_seconds=int(research_cfg.get("timeout_seconds", search_cfg.get("timeout_seconds", 20))),
                    web_max_results=int(research_cfg.get("max_results", search_cfg.get("max_results", 5))),
                ),
                researcher=build_researcher(config),
            )

            # ── Build module context for matching ──
            os_hint = blackboard.get("target_os", {}).get("name", "")
            module_ctx = ModuleContext(
                target_ip=target,
                target_os=os_hint,
                services=services,
                cves=[],
            )
            # Tier 1.7: pass the swarm's shared ExperienceStore so find_modules
            # ranks by Bayesian confidence (proven modules promoted, repeatedly
            # failing ones demoted) in addition to static service/port/CVE match.
            # None when the swarm context carries no store -> static ranking only.
            experience_store = context.get("experience")

            # ── Per-service vulnerability research ──
            all_cves: list[dict[str, Any]] = []
            all_exploits: list[dict[str, Any]] = []

            for svc in services:
                name = svc.get("service", svc.get("name", ""))
                version = svc.get("version", "")
                port = svc.get("port", 0)
                if not name:
                    continue

                query = f"{name} {version}".strip()

                # ponytail: per-service accumulators reset each iteration. The
                # NVD/exploit lookups below assign inside try blocks, so without a
                # reset a throw leaves the name unbound (NameError) or stale from
                # the previous service (wrong-service CVEs/exploits). The old code
                # scored confidence against the cumulative all_cves/all_exploits
                # lists of {service, results} dicts via str(), so severity leaked
                # across services and the "counts" measured service entries, not
                # CVEs/exploits. Score against this service's own results instead.
                cves: list = []
                cve_results: list = []
                svc_exploits: list = []

                # NVD lookup
                try:
                    cves = cve_client.search_sync(query)
                    cve_results = format_cve_results(cves, query)
                    all_cves.append({"service": name, "version": version, "port": port, "results": cve_results})
                except Exception:
                    pass

                # Exploit-DB lookup
                try:
                    exploits = exploit_search.search_exploit_db(query)
                    svc_exploits.extend(exploits or [])
                    all_exploits.append({"service": name, "version": version, "port": port, "results": exploits})
                except Exception:
                    pass

                # Web search for PoCs
                try:
                    web_results = exploit_search.search_web_exploit(f"{name} {version} exploit PoC")
                    svc_exploits.extend(web_results or [])
                    all_exploits.append(
                        {"service": name, "version": version, "port": port, "results": web_results, "source": "web"}
                    )
                except Exception:
                    pass

                # Match attack modules (Tier 1.7: experience-blended ranking)
                matched_modules = find_modules(module_ctx, experience_store=experience_store)
                top_modules = [(score, mod.name) for score, mod in matched_modules[:5]]

                # Confidence scoring (per-service, see ponytail note above)
                has_exploit = any("exploit" in str(e).lower() or "poc" in str(e).lower() for e in svc_exploits)
                has_critical_cve = any(
                    "critical" in str(c).lower() or "9." in str(c) or "high" in str(c).lower() for c in cve_results
                )
                confidence = (
                    0.9
                    if (has_exploit and has_critical_cve)
                    else 0.7
                    if has_exploit
                    else 0.5
                    if has_critical_cve
                    else 0.3
                )

                # Derive missing prerequisites from the top matched module's
                # declared ``requires`` (capability metadata). Empty when the
                # module needs nothing or no module matched — downstream
                # consumers (exploit agent, planner) read this to decide whether
                # to schedule a producer module first.
                prerequisite: list[str] = []
                if top_modules:
                    top_mod = get_module(top_modules[0][1])
                    if top_mod is not None:
                        prerequisite = list(getattr(top_mod, "requires", []) or [])

                hypothesis = {
                    "service": name,
                    "version": version,
                    "port": port,
                    "cve_count": len(cve_results),
                    "exploit_count": len(svc_exploits),
                    "confidence": confidence,
                    "matched_modules": top_modules,
                    "prerequisite": prerequisite,
                    "reason": f"{len(cve_results)} CVEs, {len(svc_exploits)} exploits, {len(top_modules)} matching attack modules.",
                }
                output["hypotheses"].append(hypothesis)

                # Generate exploit tasks for high-confidence findings.
                # depends_on=[target, "analysis"] engages route_parallel's
                # milestone gating so exploit tasks wait for THIS host's vuln
                # research to complete before running.
                if confidence >= 0.7:
                    new_tasks.append(
                        {
                            "phase": "exploit",
                            "target": target,
                            "asset_type": "service",
                            "objective": f"Exploit {name} {version} on {target}:{port}",
                            "hypothesis": f"{name} {version} is likely exploitable (confidence={confidence:.0%}).",
                            "allowed_tools": ["python", "msfconsole", "hydra"],
                            "risk_level": "high" if confidence >= 0.9 else "medium",
                            "priority": int(confidence * 100),
                            "service_context": json.dumps(svc),
                            "known_cves": [c.get("id", "") for c in (cves if isinstance(cves, list) else [])],
                            "matched_modules": [m[1] for m in top_modules],
                            "depends_on": [target, "analysis"],
                        }
                    )

            output["cves"] = all_cves
            output["exploits"] = all_exploits

            # ── LLM-driven exploit path recommendation ──
            if model_client and output["hypotheses"]:
                llm_analysis = self._llm_analyze(
                    model_client,
                    target,
                    output["hypotheses"],
                    all_cves,
                    all_exploits,
                    skill_selection=context.get("skill_selection"),
                    os_hint=os_hint,
                )
                if llm_analysis:
                    if llm_analysis.get("refined_hypotheses"):
                        output["hypotheses"] = llm_analysis["refined_hypotheses"]
                    if llm_analysis.get("recommended_exploit_path"):
                        output["recommended_exploit_path"] = llm_analysis["recommended_exploit_path"]

            # ── Update blackboard ──
            # Atomic overwrites via the Blackboard API (bb_compat bridges the
            # plain-dict test/legacy path). Vuln research replaces these keys
            # (not append) so bb_set preserves the prior semantics; the lock
            # makes the writes safe under parallel per-service dispatch in
            # Phase 3.
            bb_set(blackboard, "vuln_research_complete", True)
            bb_set(blackboard, "vulnerability_hypotheses", output["hypotheses"])
            bb_set(blackboard, "recommended_exploit_path", output["recommended_exploit_path"])
            bb_set(
                blackboard,
                "matched_attack_modules",
                [
                    {"service": h["service"], "modules": h["matched_modules"]}
                    for h in output["hypotheses"]
                    if h.get("matched_modules")
                ],
            )

            # Memory updates
            memory_updates.append(
                {
                    "target": target,
                    "memory_type": "vuln_research",
                    "content": json.dumps(
                        {
                            "hypotheses_count": len(output["hypotheses"]),
                            "high_confidence": len([h for h in output["hypotheses"] if h["confidence"] >= 0.7]),
                            "top_recommendation": output["recommended_exploit_path"][:1]
                            if output["recommended_exploit_path"]
                            else None,
                        }
                    ),
                    "tags": ["vuln", "cve", "exploit", "hypothesis"],
                }
            )

            self._set_status(AgentStatus.COMPLETE)
        except Exception as exc:
            error = str(exc)
            self._set_status(AgentStatus.FAILED)

        return AgentResult(
            agent_type=self.agent_type,
            status=self.status,
            task_id=task_id,
            output=output,
            error=error,
            execution_time=time.monotonic() - start,
            evidence_refs=evidence_refs,
            new_tasks=new_tasks,
            memory_updates=memory_updates,
            findings=findings,
        )

    def _llm_analyze(
        self,
        client: Any,
        target: str,
        hypotheses: list[dict[str, Any]],
        cves: list[dict[str, Any]],
        exploits: list[dict[str, Any]],
        skill_selection: Any = None,
        os_hint: str = "",
    ) -> dict[str, Any] | None:
        """Use LLM to refine vulnerability hypotheses and recommend exploit paths.

        Sends the rich ``_VULN_SYSTEM_PROMPT`` as the system message so the
        specialist framing is live. Returns ``None`` on failure so the
        deterministic hypotheses are kept (NOT a silent error -- the failure
        is logged so a persistent LLM problem is debuggable).
        """
        try:
            # Match truncation across all three inputs so the model isn't
            # ranking 5 hypotheses against only 3 CVE/exploit blocks.
            prompt = f"""You are a senior vulnerability researcher analyzing scan results for target {target}.

TARGET OS (detected): {os_hint or "unknown"}

SERVICE HYPOTHESES (from automated scanning):
{json.dumps(hypotheses[:5], indent=2)}

CVE FINDINGS (each entry has a 'results' list with the real CVE records):
{json.dumps(cves[:5], indent=2)}

EXPLOIT FINDINGS (each entry has a 'results' list with the real exploit records):
{json.dumps(exploits[:5], indent=2)}

Your task:
1. Rank hypotheses by real-world exploitability (not just CVSS score).
2. Consider: is there a public exploit? Is the service version confirmed vulnerable? Is the OS match correct? (use the TARGET OS above)
3. Recommend the SINGLE best exploit path to try first, with a fallback.
4. For each hypothesis, suggest which attack module would work best.

Return JSON only (no markdown fences):
{{
  "refined_hypotheses": [
    {{"service": "...", "version": "...", "port": 0, "confidence": 0.0, "rationale": "...", "recommended_module": "...", "matched_modules": [], "reason": "..."}}
  ],
  "recommended_exploit_path": [
    {{"step": 1, "action": "...", "tool": "...", "rationale": "...", "expected_outcome": "...", "fallback": "..."}}
  ]
}}
Notes:
- "confidence" MUST be a number between 0.0 and 1.0 (not the string "0.0-1.0").
- Keep the fields "version", "port", "matched_modules" from the deterministic
  hypotheses so downstream consumers (ExploitAgent) get a consistent shape.
- If you have no refinement for a hypothesis, echo it unchanged rather than dropping it."""

            # Advisory skill hints for this phase (no-op when no selection).
            from tools.skill_pipeline import append_phase_skill_hints

            prompt = append_phase_skill_hints(prompt, skill_selection, "vuln")

            resp = client.chat(
                messages=[
                    {"role": "system", "content": _VULN_SYSTEM_PROMPT},
                    {"role": "user", "content": prompt},
                ],
                tools=None,
                stream=False,
            )
            message = resp.get("message", {}) if isinstance(resp, dict) else getattr(resp, "message", None)
            if isinstance(message, dict):
                text = message.get("content", "")
            else:
                text = getattr(message, "content", resp if isinstance(resp, str) else "")
            text = str(text or "").strip()
            if not text:
                return None
            if "```json" in text:
                text = text.split("```json")[1].split("```")[0]
            elif "```" in text:
                text = text.split("```")[1].split("```")[0]
            parsed = json.loads(text)
            return parsed if isinstance(parsed, dict) else None
        except Exception as exc:
            # Log so a persistent LLM failure is debuggable instead of silently
            # degrading to deterministic-only hypotheses on every call.
            print(f"[VulnAgent] LLM analysis failed: {exc}")
            return None
