"""Enhanced Report Generator — professional red-team style reporting.

Generates:
- Executive summary with critical risks
- Technical findings with CVSS scoring
- Attack timelines
- Failure analysis with reasoning
- Exploitation chains
- Machine-readable JSON + human-readable markdown

Usage::
    from tools.enhanced_reporting import EnhancedReportGenerator
    generator = EnhancedReportGenerator(db, mission_id, workspace)
    generator.generate_full_report(campaign_result)
"""

from __future__ import annotations

import html
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from tools.logging_setup import get_logger

logger = get_logger()

# ── CVSS 3.1 Scoring ───────────────────────────────────────────────────────


@dataclass
class CVSSScore:
    """CVSS 3.1 score components."""

    base_score: float = 0.0
    temporal_score: float | None = None
    environmental_score: float | None = None
    vector_string: str = ""
    severity: str = "None"

    def to_dict(self) -> dict[str, Any]:
        return {
            "base_score": self.base_score,
            "temporal_score": self.temporal_score,
            "environmental_score": self.environmental_score,
            "vector_string": self.vector_string,
            "severity": self.severity,
        }


def calculate_cvss(
    attack_vector: str = "N",  # N=Network, A=Adjacent, L=Local, P=Physical
    attack_complexity: str = "L",  # L=Low, H=High
    privileges_required: str = "N",  # N=None, L=Low, H=High
    user_interaction: str = "N",  # N=None, R=Required
    scope: str = "U",  # U=Unchanged, C=Changed
    confidentiality: str = "N",  # N=None, L=Low, H=High
    integrity: str = "N",
    availability: str = "N",
) -> CVSSScore:
    """Calculate CVSS 3.1 base score from metric values.

    Args:
        attack_vector: N/A/L/P
        attack_complexity: L/H
        privileges_required: N/L/H
        user_interaction: N/R
        scope: U/C
        confidentiality: N/L/H
        integrity: N/L/H
        availability: N/L/H

    Returns:
        CVSSScore with base score and severity
    """
    # Metric weights
    av_weights = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
    ac_weights = {"L": 0.77, "H": 0.44}
    pr_weights = {"N": 0.85, "L": 0.62, "H": 0.27}
    pr_weights_scope_changed = {"N": 0.85, "L": 0.68, "H": 0.5}
    ui_weights = {"N": 0.85, "R": 0.62}
    cia_weights = {"N": 0.0, "L": 0.22, "H": 0.56}

    # Calculate ISS (Impact Sub-Score)
    iss = 1 - (
        (1 - cia_weights.get(confidentiality, 0))
        * (1 - cia_weights.get(integrity, 0))
        * (1 - cia_weights.get(availability, 0))
    )

    # Calculate Impact
    if scope == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15

    # Calculate Exploitability
    pr_weight = (
        pr_weights_scope_changed.get(privileges_required, 0.85)
        if scope == "C"
        else pr_weights.get(privileges_required, 0.85)
    )
    exploitability = (
        8.22
        * av_weights.get(attack_vector, 0.85)
        * ac_weights.get(attack_complexity, 0.77)
        * pr_weight
        * ui_weights.get(user_interaction, 0.85)
    )

    # Calculate Base Score
    if impact <= 0:
        base_score = 0.0
    elif scope == "U":
        base_score = min((impact + exploitability), 10)
    else:
        base_score = min(1.08 * (impact + exploitability), 10)

    # Round to one decimal place
    base_score = round(base_score, 1)

    # Determine severity
    if base_score == 0.0:
        severity = "None"
    elif base_score < 4.0:
        severity = "Low"
    elif base_score < 7.0:
        severity = "Medium"
    elif base_score < 9.0:
        severity = "High"
    else:
        severity = "Critical"

    vector = f"CVSS:3.1/AV:{attack_vector}/AC:{attack_complexity}/PR:{privileges_required}/UI:{user_interaction}/S:{scope}/C:{confidentiality}/I:{integrity}/A:{availability}"

    return CVSSScore(
        base_score=base_score,
        vector_string=vector,
        severity=severity,
    )


# ── Report data structures ─────────────────────────────────────────────────


@dataclass
class AttackTimelineEntry:
    timestamp: str
    event_type: str
    description: str
    target: str = ""
    module: str = ""
    result: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "event_type": self.event_type,
            "description": self.description,
            "target": self.target,
            "module": self.module,
            "result": self.result,
            "metadata": self.metadata,
        }


@dataclass
class ExploitationChain:
    chain_id: str
    target: str
    entries: list[dict[str, Any]] = field(default_factory=list)
    successful: bool = False
    final_privilege: str = "none"
    total_duration: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "chain_id": self.chain_id,
            "target": self.target,
            "entries": self.entries,
            "successful": self.successful,
            "final_privilege": self.final_privilege,
            "total_duration": self.total_duration,
        }


@dataclass
class FailureAnalysis:
    operation: str
    failure_count: int
    primary_error: str
    error_breakdown: dict[str, int] = field(default_factory=dict)
    mitigation_suggestion: str = ""
    recovery_actions: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "operation": self.operation,
            "failure_count": self.failure_count,
            "primary_error": self.primary_error,
            "error_breakdown": self.error_breakdown,
            "mitigation_suggestion": self.mitigation_suggestion,
            "recovery_actions": self.recovery_actions,
        }


@dataclass
class TechnicalFinding:
    finding_id: str
    title: str
    affected_asset: str
    vuln_class: str
    severity: str
    cvss: CVSSScore
    confidence: float
    summary: str
    reproduction_steps: list[str] = field(default_factory=list)
    evidence_refs: list[str] = field(default_factory=list)
    exploitation_result: str = ""
    persistence_achieved: bool = False
    privilege_level_gained: str = ""
    attack_chain: ExploitationChain | None = None
    remediation: str = ""
    references: list[str] = field(default_factory=list)
    # Closed-loop retest ("prove the fix"): the stored verification probe
    # re-executes ONLY the original PoC command; retest_status is one of
    # "" (never retested) | STILL_OPEN | FIXED | INCONCLUSIVE.
    verification_probe: dict[str, Any] = field(default_factory=dict)
    retest_status: str = ""
    retest_history: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "title": self.title,
            "affected_asset": self.affected_asset,
            "vuln_class": self.vuln_class,
            "severity": self.severity,
            "cvss": self.cvss.to_dict(),
            "confidence": self.confidence,
            "summary": self.summary,
            "reproduction_steps": self.reproduction_steps,
            "evidence_refs": self.evidence_refs,
            "exploitation_result": self.exploitation_result,
            "persistence_achieved": self.persistence_achieved,
            "privilege_level_gained": self.privilege_level_gained,
            "attack_chain": self.attack_chain.to_dict() if self.attack_chain else None,
            "remediation": self.remediation,
            "references": self.references,
            "verification_probe": self.verification_probe,
            "retest_status": self.retest_status,
            "retest_history": self.retest_history,
        }


# ── Enhanced Report Generator ────────────────────────────────────────────────


class EnhancedReportGenerator:
    """Professional red-team style report generator."""

    def __init__(
        self,
        db: Any | None = None,
        mission_id: str = "",
        workspace: Path | None = None,
    ) -> None:
        self._db = db
        self._mission_id = mission_id
        self._workspace = workspace or Path("reports")
        self._workspace.mkdir(parents=True, exist_ok=True)
        self._reports_dir = self._workspace / "enhanced"
        self._reports_dir.mkdir(parents=True, exist_ok=True)

    # ── Main API ────────────────────────────────────────────────────────

    def generate_full_report(
        self,
        campaign_result: dict[str, Any],
        *,
        output_format: str = "both",  # json, markdown, both, html, all
        evidence_store: Any | None = None,
        outcome_assessments: Mapping[str, Any] | None = None,
    ) -> dict[str, Path]:
        """Generate a complete red-team style report from campaign results.

        Args:
            campaign_result: Output from AutonomousOrchestrator.run_autonomous_campaign()
            output_format: Output format(s). ``json``/``markdown``/``html``
                produce a single format; ``both`` (default) produces JSON +
                Markdown; ``all`` produces JSON + Markdown + HTML.
            evidence_store: Optional ``EvidenceStore``. When supplied, each
                technical finding is back-filled with evidence refs and
                reproduction steps drawn from the promoted exploit-audit rows
                tagged for that target (see ``evidence.promote_exploit_audit``).
            outcome_assessments: Optional mapping keyed by target IP to an
                ``OutcomeAssessment`` (or dict carrying ``hypothesis_status``).
                When supplied, finding confidence is derived from the verdict
                (CONFIRMED -> 0.95, REFUTED -> 0.2, INCONCLUSIVE -> 0.5);
                otherwise the existing 0.9 default is kept.

        Returns:
            Dict mapping format to file path
        """
        logger.info("Generating full red-team report")
        report_data = self._build_report_data(
            campaign_result,
            evidence_store=evidence_store,
            outcome_assessments=outcome_assessments,
        )

        paths: dict[str, Path] = {}

        if output_format in ("json", "both", "all"):
            json_path = self._reports_dir / f"report_{self._mission_id}_{self._now()}.json"
            json_path.write_text(json.dumps(report_data, indent=2, default=str), encoding="utf-8")
            paths["json"] = json_path
            logger.info(f"JSON report saved to {json_path}")

        if output_format in ("markdown", "both", "all"):
            md_path = self._reports_dir / f"report_{self._mission_id}_{self._now()}.md"
            md_content = self._generate_markdown(report_data)
            md_path.write_text(md_content, encoding="utf-8")
            paths["markdown"] = md_path
            logger.info(f"Markdown report saved to {md_path}")

        if output_format in ("html", "all"):
            html_path = self._reports_dir / f"report_{self._mission_id}_{self._now()}.html"
            html_content = self._generate_html(report_data)
            html_path.write_text(html_content, encoding="utf-8")
            paths["html"] = html_path
            logger.info(f"HTML report saved to {html_path}")

        return paths

    def generate_executive_summary(
        self,
        campaign_result: dict[str, Any],
    ) -> str:
        """Generate executive summary markdown."""
        states = campaign_result.get("states", {})
        total_targets = len(states)
        successful_exploits = sum(len(s.get("successful_exploits", [])) for s in states.values())
        total_attempts = sum(
            len(s.get("successful_exploits", [])) + sum(len(v) for v in s.get("failed_attempts", {}).values())
            for s in states.values()
        )
        privilege_escalations = sum(
            1 for s in states.values() if s.get("privilege_level") in ("root", "system", "admin")
        )
        credentials_found = sum(len(s.get("credentials_found", [])) for s in states.values())

        critical_count = sum(
            1
            for s in states.values()
            for e in s.get("successful_exploits", [])
            if any(c in e for c in ["RCE", "CVE-2024-6387", "EternalBlue", "BlueKeep"])
        )

        lines = [
            "# Executive Summary",
            "",
            f"**Assessment Date**: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
            f"**Mission ID**: {self._mission_id}",
            f"**Total Targets Assessed**: {total_targets}",
            "",
            "---",
            "",
            "## Key Findings",
            "",
            f"- **Critical Vulnerabilities Exploited**: {critical_count}",
            f"- **Total Successful Exploits**: {successful_exploits}",
            f"- **Total Exploit Attempts**: {total_attempts}",
            f"- **Privilege Escalations Achieved**: {privilege_escalations}",
            f"- **Credentials Discovered**: {credentials_found}",
            f"- **Success Rate**: {(successful_exploits / total_attempts * 100):.1f}%"
            if total_attempts > 0
            else "- **Success Rate**: N/A",
            "",
            "## Risk Assessment",
            "",
        ]

        if critical_count > 0:
            lines.append(
                "🔴 **CRITICAL**: Immediate action required. Multiple critical vulnerabilities were successfully exploited."
            )
        elif successful_exploits > 0:
            lines.append("🟠 **HIGH**: Significant security weaknesses identified and exploited.")
        elif total_attempts > 0:
            lines.append("🟡 **MEDIUM**: Some attack vectors were identified but exploitation was limited.")
        else:
            lines.append("🟢 **LOW**: No successful exploits achieved during the assessment.")

        lines.extend(
            [
                "",
                "## Attack Surface Summary",
                "",
            ]
        )

        for target, state in states.items():
            recon = state.get("recon_result", {})
            lines.append(f"### {target}")
            lines.append(f"- **OS**: {recon.get('os_family', 'Unknown')}")
            lines.append(f"- **Open Ports**: {recon.get('total_open_ports', 0)}")
            lines.append(f"- **Services**: {recon.get('total_services', 0)}")
            lines.append(f"- **Access Achieved**: {'Yes' if state.get('access_achieved') else 'No'}")
            if state.get("privilege_level"):
                lines.append(f"- **Privilege Level**: {state.get('privilege_level')}")
            # Phase 3 Round 2 additive recon fields — tolerant of old runs
            # (recon_result snapshots that predate these keys).
            udp_ports = recon.get("udp_ports") or []
            if udp_ports:
                lines.append(f"- **UDP Ports**: {len(udp_ports)} - {udp_ports}")
            spider_results = recon.get("spider_results") or []
            if spider_results:
                lines.append(f"- **Web Spider**: {len(spider_results)} site(s) crawled")
            osint = recon.get("osint") or {}
            if isinstance(osint, dict) and osint:
                ipv6 = osint.get("ipv6_addresses") or []
                rev = osint.get("reverse_dns") or ""
                if ipv6 or rev:
                    bits = []
                    if ipv6:
                        bits.append(f"{len(ipv6)} IPv6 addr(s)")
                    if rev:
                        bits.append(f"rDNS={rev}")
                    lines.append(f"- **OSINT**: {', '.join(bits)}")
            ipv6_direct = recon.get("ipv6_addresses") or []
            if ipv6_direct:
                lines.append(f"- **IPv6 (passive)**: {ipv6_direct}")
            lines.append("")

        return "\n".join(lines)

    def generate_attack_timeline(
        self,
        campaign_result: dict[str, Any],
    ) -> str:
        """Generate attack timeline markdown."""
        states = campaign_result.get("states", {})

        lines = [
            "# Attack Timeline",
            "",
            "| Time | Target | Event Type | Module | Description | Result |",
            "|------|--------|------------|--------|-------------|--------|",
        ]

        all_events: list[tuple[str, str, dict]] = []
        for target, state in states.items():
            for event in state.get("timeline", []):
                all_events.append((event.get("timestamp", ""), target, event))

        all_events.sort(key=lambda x: x[0])

        for timestamp, target, event in all_events:
            time_str = timestamp.split("T")[1].split(".")[0] if "T" in timestamp else timestamp
            event_type = event.get("event_type", "")
            module = event.get("metadata", {}).get("module", "")
            description = event.get("description", "")[:60]
            result = (
                "✅" if "success" in event_type else "❌" if "fail" in event_type or "error" in event_type else "⏳"
            )
            lines.append(f"| {time_str} | {target} | {event_type} | {module} | {description} | {result} |")

        return "\n".join(lines)

    def generate_failure_analysis(
        self,
        campaign_result: dict[str, Any],
    ) -> str:
        """Generate failure analysis markdown."""
        states = campaign_result.get("states", {})

        lines = [
            "# Failure Analysis",
            "",
            "## Failed Exploit Attempts",
            "",
        ]

        all_failures: dict[str, list[str]] = {}
        for target, state in states.items():
            for module, errors in state.get("failed_attempts", {}).items():
                if module not in all_failures:
                    all_failures[module] = []
                all_failures[module].extend(errors)

        if not all_failures:
            lines.append("No failed attempts recorded.")
            return "\n".join(lines)

        for module, errors in sorted(all_failures.items(), key=lambda x: len(x[1]), reverse=True):
            lines.append(f"### {module}")
            lines.append(f"- **Total Failures**: {len(errors)}")

            # Analyze error types
            error_types: dict[str, int] = {}
            for error in errors:
                error_type = self._categorize_error(error)
                error_types[error_type] = error_types.get(error_type, 0) + 1

            lines.append("- **Error Breakdown**:")
            for error_type, count in sorted(error_types.items(), key=lambda x: x[1], reverse=True):
                lines.append(f"  - {error_type}: {count}")

            # Suggest mitigation
            primary_error = max(error_types, key=error_types.get)
            mitigation = self._suggest_mitigation(primary_error)
            lines.append(f"- **Suggested Mitigation**: {mitigation}")
            lines.append("")

        return "\n".join(lines)

    def generate_exploitation_chains(
        self,
        campaign_result: dict[str, Any],
    ) -> str:
        """Generate exploitation chain analysis markdown."""
        states = campaign_result.get("states", {})

        lines = [
            "# Exploitation Chains",
            "",
        ]

        for target, state in states.items():
            exploits = state.get("successful_exploits", [])
            if not exploits:
                continue

            lines.append(f"## {target}")
            lines.append("")
            lines.append("### Chain of Successful Exploits")
            lines.append("")

            for i, exploit in enumerate(exploits, 1):
                lines.append(f"{i}. **{exploit}**")

            # Show privilege progression
            priv_level = state.get("privilege_level", "none")
            if priv_level != "none":
                lines.append("")
                lines.append(f"**Final Privilege Level**: {priv_level}")

            # Show credentials
            creds = state.get("credentials_found", [])
            if creds:
                lines.append("")
                lines.append("**Credentials Discovered**:")
                for cred in creds[:5]:  # Limit to 5
                    user = cred.get("user", "unknown")
                    lines.append(f"- {user}: ***")

            # Show pivot targets
            pivots = state.get("pivot_targets", [])
            if pivots:
                lines.append("")
                lines.append(f"**Lateral Movement Targets**: {', '.join(pivots[:5])}")

            lines.append("")
            lines.append("---")
            lines.append("")

        return "\n".join(lines)

    def generate_technical_findings(
        self,
        campaign_result: dict[str, Any],
    ) -> str:
        """Generate technical findings with CVSS scoring."""
        states = campaign_result.get("states", {})

        lines = [
            "# Technical Findings",
            "",
        ]

        finding_count = 0
        for target, state in states.items():
            exploits = state.get("successful_exploits", [])
            recon = state.get("recon_result", {})
            services = recon.get("services", [])

            for exploit in exploits:
                finding_count += 1
                cvss = self._estimate_cvss(exploit, services)

                lines.append(f"## Finding {finding_count}: {exploit}")
                lines.append("")
                lines.append(f"**Affected Asset**: {target}")
                lines.append(f"**CVSS Score**: {cvss.base_score} ({cvss.severity})")
                lines.append(f"**Vector**: `{cvss.vector_string}`")
                lines.append("")
                lines.append("### Description")
                lines.append(f"Successfully exploited {exploit} on {target}.")
                lines.append("")
                lines.append("### Evidence")
                lines.append("- Attack timeline entries")
                lines.append("- Tool output logs")
                lines.append("")
                lines.append("### Remediation")
                lines.append(self._get_remediation(exploit))
                lines.append("")
                lines.append("---")
                lines.append("")

        if finding_count == 0:
            lines.append("No successful exploits were achieved during this assessment.")

        return "\n".join(lines)

    # ── Internal helpers ────────────────────────────────────────────────

    def _build_report_data(
        self,
        campaign_result: dict[str, Any],
        *,
        evidence_store: Any | None = None,
        outcome_assessments: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Build structured report data dict.

        When ``evidence_store`` is supplied, technical findings are back-filled
        with evidence refs and reproduction steps drawn from the promoted
        exploit-audit rows for that target. When ``outcome_assessments`` is
        supplied (keyed by target IP), finding confidence reflects the verdict.
        """
        states = campaign_result.get("states", {})

        # Index promoted evidence by target once (best-effort; never fatal).
        evidence_by_target: dict[str, list[dict[str, Any]]] = {}
        if evidence_store is not None:
            try:
                mission_evidence = evidence_store.list_for_mission(limit=500)
            except Exception:
                mission_evidence = []
            for item in mission_evidence or []:
                meta = item.get("metadata", {}) or {}
                tgt = meta.get("target_ip", "") or item.get("target", "")
                if tgt:
                    evidence_by_target.setdefault(tgt, []).append(item)

        # Build attack timeline
        timeline: list[AttackTimelineEntry] = []
        for target, state in states.items():
            for event in state.get("timeline", []):
                timeline.append(
                    AttackTimelineEntry(
                        timestamp=event.get("timestamp", ""),
                        event_type=event.get("event_type", ""),
                        description=event.get("description", ""),
                        target=target,
                        module=event.get("metadata", {}).get("module", ""),
                        result="success" if "success" in event.get("event_type", "") else "failure",
                        metadata=event.get("metadata", {}),
                    )
                )

        # Build exploitation chains (timestamps back-filled from audit records /
        # timeline events when available).
        chains: list[ExploitationChain] = []
        for target, state in states.items():
            exploits = state.get("successful_exploits", [])
            if exploits:
                chain_entries = []
                for exploit in exploits:
                    ts = self._chain_entry_timestamp(exploit, target, state)
                    chain_entries.append(
                        {
                            "module": exploit,
                            "timestamp": ts,
                            "result": "success",
                        }
                    )
                chains.append(
                    ExploitationChain(
                        chain_id=f"CHAIN-{target.replace('.', '-')}",
                        target=target,
                        entries=chain_entries,
                        successful=True,
                        final_privilege=state.get("privilege_level", "none"),
                    )
                )

        # Build failure analysis
        failures: list[FailureAnalysis] = []
        all_failed: dict[str, list[str]] = {}
        for target, state in states.items():
            for module, errors in state.get("failed_attempts", {}).items():
                if module not in all_failed:
                    all_failed[module] = []
                all_failed[module].extend(errors)

        for module, errors in all_failed.items():
            error_types: dict[str, int] = {}
            for error in errors:
                et = self._categorize_error(error)
                error_types[et] = error_types.get(et, 0) + 1
            primary = max(error_types, key=error_types.get) if error_types else "Unknown"
            failures.append(
                FailureAnalysis(
                    operation=module,
                    failure_count=len(errors),
                    primary_error=primary,
                    error_breakdown=error_types,
                    mitigation_suggestion=self._suggest_mitigation(primary),
                )
            )

        # Build technical findings
        findings: list[TechnicalFinding] = []
        for target, state in states.items():
            recon = state.get("recon_result", {})
            services = recon.get("services", [])
            target_evidence = evidence_by_target.get(target, [])
            verdict = _resolve_verdict(outcome_assessments, target) if outcome_assessments else None
            for exploit in state.get("successful_exploits", []):
                cvss = self._estimate_cvss(exploit, services)
                refs, repro = self._evidence_for_finding(exploit, target, state, target_evidence)
                confidence = _confidence_from_verdict(verdict)
                summary = f"Successfully exploited {exploit}"
                if verdict is not None:
                    summary = f"{summary} (hypothesis {verdict})"
                # Closed-loop retest: carry the stored verification probe so
                # retest_finding can re-execute ONLY the original PoC command.
                raw_probe = (state.get("exploit_probes", {}) or {}).get(exploit, {})
                probe = dict(raw_probe) if isinstance(raw_probe, dict) else {}
                findings.append(
                    TechnicalFinding(
                        finding_id=f"F-{target.replace('.', '-')}-{exploit}",
                        title=f"{exploit} on {target}",
                        affected_asset=target,
                        vuln_class=self._classify_vulnerability(exploit),
                        severity=cvss.severity,
                        cvss=cvss,
                        confidence=confidence,
                        summary=summary,
                        reproduction_steps=repro,
                        evidence_refs=refs,
                        exploitation_result="Shell access achieved"
                        if state.get("access_achieved")
                        else "Exploit verified",
                        privilege_level_gained=state.get("privilege_level", ""),
                        remediation=self._get_remediation(exploit),
                        verification_probe=probe,
                    )
                )

        # T1.13: rank findings by CVSS base score (desc) so both render paths
        # (_generate_findings_md / _generate_findings_html, which iterate this
        # list in order) surface the highest-severity findings first. Guard
        # against None base scores (treat as 0).
        findings.sort(key=lambda f: f.cvss.base_score or 0, reverse=True)

        return {
            "report_metadata": {
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "mission_id": self._mission_id,
                "generator_version": "2.0",
                "total_targets": len(states),
                "total_exploits": sum(len(s.get("successful_exploits", [])) for s in states.values()),
                "total_failures": sum(
                    sum(len(v) for v in s.get("failed_attempts", {}).values()) for s in states.values()
                ),
            },
            "executive_summary": self.generate_executive_summary(campaign_result),
            "attack_timeline": [t.to_dict() for t in timeline],
            "exploitation_chains": [c.to_dict() for c in chains],
            "failure_analysis": [f.to_dict() for f in failures],
            "technical_findings": [f.to_dict() for f in findings],
        }

    def _chain_entry_timestamp(
        self,
        exploit: str,
        target: str,
        state: dict[str, Any],
    ) -> str:
        """Best-effort timestamp for a chain step from audit records / timeline."""
        exploit_lower = (exploit or "").lower()
        # 1. ExploitRecord rows carried in campaign state.
        for rec in state.get("exploit_records", []) or state.get("audit_records", []):
            if not isinstance(rec, dict):
                continue
            hay = " ".join(
                str(v)
                for v in (
                    rec.get("action", ""),
                    rec.get("tool_name", ""),
                    (rec.get("full_args", {}) or {}).get("command", ""),
                    (rec.get("args", {}) or {}).get("command", ""),
                )
            ).lower()
            if exploit_lower and exploit_lower in hay:
                ts = rec.get("timestamp") or rec.get("created_at", "")
                if ts:
                    return str(ts)
        # 2. Timeline events whose module/event_type mentions the exploit.
        for event in state.get("timeline", []) or []:
            if not isinstance(event, dict):
                continue
            module = str(event.get("metadata", {}).get("module", "")).lower()
            etype = str(event.get("event_type", "")).lower()
            if exploit_lower and (exploit_lower in module or exploit_lower in etype):
                ts = event.get("timestamp", "")
                if ts:
                    return str(ts)
        return ""

    def _evidence_for_finding(
        self,
        exploit: str,
        target: str,
        state: dict[str, Any],
        target_evidence: list[dict[str, Any]],
    ) -> tuple[list[str], list[str]]:
        """Collect evidence ids + reproduction steps for a finding.

        Precedence:
        1. Explicit ``state["exploit_evidence"][exploit]`` list of evidence ids.
        2. ``state["evidence_refs"]`` list shared across the target's findings.
        3. Promoted audit evidence for this target (filtered by the exploit
           substring against the action/command when possible).
        """
        explicit = (state.get("exploit_evidence", {}) or {}).get(exploit)
        if isinstance(explicit, list) and explicit:
            refs = [str(r) for r in explicit if r]
            repro = self._reproduction_from_evidence(target_evidence, exploit, refs)
            return refs, repro

        shared = state.get("evidence_refs")
        if isinstance(shared, list) and shared:
            refs = [str(r) for r in shared if r]
            repro = self._reproduction_from_evidence(target_evidence, exploit, refs)
            return refs, repro

        if not target_evidence:
            # No promoted evidence for this target -- synthesize a single
            # fallback reproduction step so the report still documents the
            # exploit path even without an EvidenceStore.
            return [], [f"Execute {exploit} against the target and capture tool output."]

        exploit_lower = (exploit or "").lower()
        matched: list[dict[str, Any]] = []
        for item in target_evidence:
            meta = item.get("metadata", {}) or {}
            action = str(meta.get("action", "")).lower()
            cmd = str(meta.get("command", "")).lower()
            if exploit_lower and (exploit_lower in action or exploit_lower in cmd):
                matched.append(item)
        pool = matched if matched else target_evidence
        refs = [item.get("evidence_id", "") for item in pool if item.get("evidence_id")]
        repro = self._reproduction_from_evidence(pool, exploit, refs)
        return refs, repro

    def _reproduction_from_evidence(
        self,
        pool: list[dict[str, Any]],
        exploit: str,
        refs: list[str],
    ) -> list[str]:
        """Derive concise reproduction steps from evidence summaries."""
        ref_set = set(refs)
        steps: list[str] = []
        for item in pool:
            eid = item.get("evidence_id", "")
            if ref_set and eid not in ref_set:
                continue
            meta = item.get("metadata", {}) or {}
            action = str(meta.get("action", "") or meta.get("tool_name", "")).strip()
            summary = str(item.get("summary", "")).strip()
            if not summary:
                continue
            label = f"{action}: " if action else ""
            steps.append(f"{label}{summary[:120]}")
        if not steps:
            steps = [f"Execute {exploit} against the target and capture tool output."]
        return steps[:10]

    def _generate_markdown(self, report_data: dict[str, Any]) -> str:
        """Generate full markdown report from structured data."""
        lines = [
            "# Red Team Assessment Report",
            "",
            f"**Mission ID**: {report_data['report_metadata']['mission_id']}",
            f"**Generated**: {report_data['report_metadata']['generated_at']}",
            f"**Targets Assessed**: {report_data['report_metadata']['total_targets']}",
            "",
            "---",
            "",
        ]

        # Executive Summary
        lines.append(report_data["executive_summary"])
        lines.append("")
        lines.append("---")
        lines.append("")

        # Attack Timeline
        lines.append(self._generate_timeline_md(report_data["attack_timeline"]))
        lines.append("")
        lines.append("---")
        lines.append("")

        # Exploitation Chains
        lines.append(self._generate_chains_md(report_data["exploitation_chains"]))
        lines.append("")
        lines.append("---")
        lines.append("")

        # Technical Findings
        lines.append(self._generate_findings_md(report_data["technical_findings"]))
        lines.append("")
        lines.append("---")
        lines.append("")

        # Failure Analysis
        lines.append(self._generate_failures_md(report_data["failure_analysis"]))
        lines.append("")

        return "\n".join(lines)

    # ── HTML rendering ────────────────────────────────────────────────────

    def _generate_html(self, report_data: dict[str, Any]) -> str:
        """Generate a self-contained HTML report (inline CSS, no externals).

        All user-controlled strings (target IPs, exploit names, summaries,
        remediation text) are HTML-escaped. Empty sections are omitted.
        """
        meta = report_data.get("report_metadata", {})
        parts: list[str] = [
            "<!DOCTYPE html>",
            "<html lang='en'>",
            "<head>",
            "<meta charset='utf-8'>",
            f"<title>{_esc(meta.get('mission_id', 'Red Team Report'))} - Red Team Assessment</title>",
            "<style>",
            _HTML_CSS,
            "</style>",
            "</head>",
            "<body>",
            "<main class='report'>",
            "<header class='report-header'>",
            "<h1>Red Team Assessment Report</h1>",
            "<div class='meta'>",
            f"<span><strong>Mission ID:</strong> {_esc(meta.get('mission_id', ''))}</span>",
            f"<span><strong>Generated:</strong> {_esc(meta.get('generated_at', ''))}</span>",
            f"<span><strong>Targets Assessed:</strong> {_esc(meta.get('total_targets', ''))}</span>",
            "</div>",
            "</header>",
        ]

        # Executive summary is markdown-ish prose; render as preformatted escaped text.
        exec_summary = report_data.get("executive_summary", "")
        if exec_summary:
            parts.append("<section class='section'>")
            parts.append("<h2>Executive Summary</h2>")
            parts.append(f"<pre class='prose'>{_esc(exec_summary)}</pre>")
            parts.append("</section>")

        timeline = report_data.get("attack_timeline", [])
        if timeline:
            parts.append(self._generate_timeline_html(timeline))

        chains = report_data.get("exploitation_chains", [])
        if chains:
            parts.append(self._generate_chains_html(chains))

        findings = report_data.get("technical_findings", [])
        if findings:
            parts.append(self._generate_findings_html(findings))

        failures = report_data.get("failure_analysis", [])
        if failures:
            parts.append(self._generate_failures_html(failures))

        parts.append("</main>")
        parts.append("</body>")
        parts.append("</html>")
        return "\n".join(parts)

    def _generate_timeline_html(self, timeline: list[dict]) -> str:
        rows = []
        for entry in timeline:
            ts = entry.get("timestamp", "")
            ts_short = ts.split("T")[1].split(".")[0] if "T" in ts else ts
            result_cls = "ok" if entry.get("result") == "success" else "fail"
            rows.append(
                "<tr>"
                f"<td>{_esc(ts_short)}</td>"
                f"<td>{_esc(entry.get('target', ''))}</td>"
                f"<td>{_esc(entry.get('event_type', ''))}</td>"
                f"<td>{_esc(entry.get('module', ''))}</td>"
                f"<td class='{result_cls}'>{_esc(entry.get('result', ''))}</td>"
                "</tr>"
            )
        return (
            "<section class='section'>"
            "<h2>Attack Timeline</h2>"
            "<table class='data-table'><thead><tr>"
            "<th>Time</th><th>Target</th><th>Event</th><th>Module</th><th>Result</th>"
            "</tr></thead><tbody>" + "".join(rows) + "</tbody></table>"
            "</section>"
        )

    def _generate_chains_html(self, chains: list[dict]) -> str:
        sections: list[str] = ["<section class='section'>", "<h2>Exploitation Chains</h2>"]
        for chain in chains:
            sections.append("<div class='chain'>")
            sections.append(
                f"<h3>{_esc(chain.get('target', ''))} "
                f"<span class='chain-id'>({_esc(chain.get('chain_id', ''))})</span></h3>"
            )
            sections.append(
                f"<p><strong>Successful:</strong> {_esc(chain.get('successful', ''))} "
                f"&middot; <strong>Final Privilege:</strong> {_esc(chain.get('final_privilege', ''))}</p>"
            )
            sections.append("<ol class='chain-steps'>")
            for entry in chain.get("entries", []):
                ts = entry.get("timestamp", "")
                ts_short = ts.split("T")[1].split(".")[0] if "T" in ts else ts
                sections.append(
                    f"<li><strong>{_esc(entry.get('module', ''))}</strong> "
                    f"<span class='muted'>({_esc(entry.get('result', ''))}"
                    f"{(' &middot; ' + _esc(ts_short)) if ts_short else ''})</span></li>"
                )
            sections.append("</ol>")
            sections.append("</div>")
        sections.append("</section>")
        return "".join(sections)

    def _generate_findings_html(self, findings: list[dict]) -> str:
        sections: list[str] = ["<section class='section'>", "<h2>Technical Findings</h2>"]
        for finding in findings:
            cvss = finding.get("cvss", {}) or {}
            sections.append("<article class='finding'>")
            sections.append(f"<h3>{_esc(finding.get('title', ''))}</h3>")
            sections.append("<div class='finding-meta'>")
            sev = _esc(str(finding.get("severity", "")))
            confidence_label = f"{float(finding.get('confidence', 0) or 0):.0%}"
            sections.append(
                f"<span class='badge sev-{_sev_class(finding.get('severity', ''))}'>"
                f"{sev}</span>"
                f"<span><strong>CVSS:</strong> {_esc(cvss.get('base_score', 0))}</span>"
                f"<span><strong>Class:</strong> {_esc(finding.get('vuln_class', ''))}</span>"
                f"<span><strong>Confidence:</strong> {_esc(confidence_label)}</span>"
                f"<span><strong>Asset:</strong> {_esc(finding.get('affected_asset', ''))}</span>"
            )
            sections.append("</div>")
            sections.append(f"<p><strong>Summary:</strong> {_esc(finding.get('summary', ''))}</p>")
            if finding.get("hitl_status"):
                sections.append(f"<p><strong>HITL:</strong> {_esc(finding.get('hitl_status', ''))}</p>")
            retest_html = _format_retest_html(finding)
            if retest_html:
                sections.append(f"<p><strong>Retest:</strong> {retest_html}</p>")
            if finding.get("exploitation_result"):
                sections.append(f"<p><strong>Exploitation:</strong> {_esc(finding.get('exploitation_result', ''))}</p>")
            if finding.get("privilege_level_gained"):
                sections.append(
                    f"<p><strong>Privilege Gained:</strong> {_esc(finding.get('privilege_level_gained', ''))}</p>"
                )
            repro = finding.get("reproduction_steps", []) or []
            if repro:
                sections.append("<h4>Reproduction Steps</h4><ol class='repro'>")
                for step in repro:
                    sections.append(f"<li>{_esc(step)}</li>")
                sections.append("</ol>")
            refs = finding.get("evidence_refs", []) or []
            if refs:
                sections.append("<h4>Evidence References</h4><ul class='evidence-refs'>")
                for ref in refs:
                    sections.append(f"<li><code>{_esc(ref)}</code></li>")
                sections.append("</ul>")
            if finding.get("remediation"):
                sections.append(f"<p><strong>Remediation:</strong> {_esc(finding.get('remediation', ''))}</p>")
            sections.append("</article>")
        sections.append("</section>")
        return "".join(sections)

    def _generate_failures_html(self, failures: list[dict]) -> str:
        sections: list[str] = ["<section class='section'>", "<h2>Failure Analysis</h2>"]
        for failure in failures:
            sections.append("<article class='failure'>")
            sections.append(f"<h3>{_esc(failure.get('operation', ''))}</h3>")
            sections.append(
                f"<p><strong>Total Failures:</strong> {_esc(failure.get('failure_count', ''))} "
                f"&middot; <strong>Primary Error:</strong> {_esc(failure.get('primary_error', ''))}</p>"
            )
            breakdown = failure.get("error_breakdown", {}) or {}
            if breakdown:
                sections.append("<ul class='error-breakdown'>")
                for etype, count in breakdown.items():
                    sections.append(f"<li>{_esc(etype)}: {_esc(count)}</li>")
                sections.append("</ul>")
            if failure.get("mitigation_suggestion"):
                sections.append(f"<p><strong>Mitigation:</strong> {_esc(failure.get('mitigation_suggestion', ''))}</p>")
            sections.append("</article>")
        sections.append("</section>")
        return "".join(sections)

    def _generate_timeline_md(self, timeline: list[dict]) -> str:
        lines = ["# Attack Timeline", ""]
        if not timeline:
            lines.append("No timeline events recorded.")
            return "\n".join(lines)

        lines.append("| Time | Target | Event | Module | Result |")
        lines.append("|------|--------|-------|--------|--------|")
        for entry in timeline:
            ts = entry.get("timestamp", "").split("T")[1].split(".")[0] if "T" in entry.get("timestamp", "") else ""
            result = "✅" if entry.get("result") == "success" else "❌"
            lines.append(
                f"| {ts} | {entry.get('target', '')} | {entry.get('event_type', '')} | {entry.get('module', '')} | {result} |"
            )
        return "\n".join(lines)

    def _generate_chains_md(self, chains: list[dict]) -> str:
        lines = ["# Exploitation Chains", ""]
        if not chains:
            lines.append("No successful exploitation chains.")
            return "\n".join(lines)

        for chain in chains:
            lines.append(f"## {chain['target']}")
            lines.append(f"- **Chain ID**: {chain['chain_id']}")
            lines.append(f"- **Successful**: {'Yes' if chain['successful'] else 'No'}")
            lines.append(f"- **Final Privilege**: {chain['final_privilege']}")
            lines.append("")
            lines.append("### Chain Steps")
            for i, entry in enumerate(chain["entries"], 1):
                lines.append(f"{i}. {entry['module']} ({entry['result']})")
            lines.append("")
        return "\n".join(lines)

    def _generate_findings_md(self, findings: list[dict]) -> str:
        lines = ["# Technical Findings", ""]
        if not findings:
            lines.append("No findings to report.")
            return "\n".join(lines)

        for finding in findings:
            cvss = finding.get("cvss", {})
            lines.append(f"## {finding['title']}")
            lines.append(f"- **Severity**: {finding['severity']} (CVSS: {cvss.get('base_score', 0)})")
            lines.append(f"- **Class**: {finding['vuln_class']}")
            lines.append(f"- **Confidence**: {finding['confidence']:.0%}")
            lines.append(f"- **Asset**: {finding['affected_asset']}")
            lines.append(f"- **Retest**: {_format_retest_md(finding)}")
            if finding.get("hitl_status"):
                lines.append(f"- **HITL**: {finding.get('hitl_status')}")
            lines.append("")
            lines.append(f"**Summary**: {finding['summary']}")
            lines.append("")
            if finding.get("exploitation_result"):
                lines.append(f"**Exploitation**: {finding['exploitation_result']}")
            if finding.get("privilege_level_gained"):
                lines.append(f"**Privilege Gained**: {finding['privilege_level_gained']}")
            lines.append("")
            lines.append(f"**Remediation**: {finding.get('remediation', 'No remediation provided.')}")
            lines.append("")
            lines.append("---")
            lines.append("")
        return "\n".join(lines)

    def _generate_failures_md(self, failures: list[dict]) -> str:
        lines = ["# Failure Analysis", ""]
        if not failures:
            lines.append("No failures recorded.")
            return "\n".join(lines)

        for failure in failures:
            lines.append(f"## {failure['operation']}")
            lines.append(f"- **Total Failures**: {failure['failure_count']}")
            lines.append(f"- **Primary Error**: {failure['primary_error']}")
            lines.append("")
            lines.append("### Error Breakdown")
            for error_type, count in failure.get("error_breakdown", {}).items():
                lines.append(f"- {error_type}: {count}")
            lines.append("")
            lines.append(f"**Mitigation**: {failure['mitigation_suggestion']}")
            lines.append("")
        return "\n".join(lines)

    def _estimate_cvss(self, exploit_name: str, services: list[dict]) -> CVSSScore:
        """Estimate CVSS score based on exploit type and exposed services.

        The exploit-name branches below take precedence (they encode known
        exploit mechanics). When none of them fire, the ``services`` list is
        consulted to pick a sane profile from the exposed surface (SMB / SSH /
        Redis / LDAP / SQL / HTTP). A recognized vulnerable-version banner can
        also bump Confidentiality/Integrity/Availability to High.
        """
        # Default: Network, Low complexity, None privileges, None interaction
        av, ac, pr, ui = "N", "L", "N", "N"
        c, i, a = "H", "H", "H"
        scope = "U"

        exploit_lower = exploit_name.lower()
        matched = True

        if "brute" in exploit_lower or "spray" in exploit_lower:
            ac = "H"  # High complexity (time-based)
            pr = "N"
            c, i, a = "H", "L", "N"
        elif "cve-2024-6387" in exploit_lower or "regresshion" in exploit_lower:
            av, ac, pr = "N", "L", "N"
            c, i, a = "H", "H", "H"
            scope = "C"
        elif "eternalblue" in exploit_lower or "smbghost" in exploit_lower:
            av, ac, pr = "N", "L", "N"
            c, i, a = "H", "H", "H"
            scope = "C"
        elif "bluekeep" in exploit_lower:
            av, ac, pr = "N", "L", "N"
            c, i, a = "H", "H", "H"
        elif "webshell" in exploit_lower or "upload" in exploit_lower:
            av, ac, pr = "N", "L", "L"
            c, i, a = "H", "H", "L"
        elif "sql" in exploit_lower:
            av, ac, pr = "N", "L", "N"
            c, i, a = "H", "L", "L"
        elif "xss" in exploit_lower:
            av, ac, pr, ui = "N", "L", "N", "R"
            c, i, a = "L", "L", "N"
        elif "privesc" in exploit_lower or "suid" in exploit_lower:
            av = "L"
            pr = "L"
            c, i, a = "H", "H", "H"
        elif "container" in exploit_lower or "docker" in exploit_lower:
            av = "L"
            pr = "L"
            c, i, a = "H", "H", "H"
            scope = "C"
        elif "ldap" in exploit_lower or "anonymous" in exploit_lower:
            av, ac, pr = "N", "L", "N"
            c, i, a = "H", "L", "N"
        elif "redis" in exploit_lower:
            av, ac, pr = "N", "L", "N"
            c, i, a = "H", "H", "L"
        else:
            matched = False

        # Service-aware fallback / refinement using the (previously unused)
        # ``services`` arg. Only applies when no exploit-name branch fired.
        if not matched:
            profile = _cvss_profile_from_services(services)
            av, ac, pr, ui, c, i, a, scope = profile

        # A vulnerable-version banner in any exposed service bumps impact to High.
        if _service_indicates_vulnerable_version(services):
            c = "H"
            i = _bump_cia(i)
            a = _bump_cia(a)

        return calculate_cvss(av, ac, pr, ui, scope, c, i, a)

    def _classify_vulnerability(self, exploit_name: str) -> str:
        """Classify vulnerability type from exploit name."""
        exploit_lower = exploit_name.lower()
        classifications = {
            "brute": "Weak Credentials",
            "spray": "Weak Credentials",
            "cve": "Known CVE",
            "eternalblue": "Known CVE",
            "smbghost": "Known CVE",
            "bluekeep": "Known CVE",
            "regresshion": "Known CVE",
            "sql": "SQL Injection",
            "xss": "Cross-Site Scripting",
            "webshell": "File Upload",
            "upload": "File Upload",
            "privesc": "Privilege Escalation",
            "suid": "Privilege Escalation",
            "container": "Container Escape",
            "docker": "Container Escape",
            "ldap": "Information Disclosure",
            "anonymous": "Information Disclosure",
            "redis": "Unauthorized Access",
        }
        for key, value in classifications.items():
            if key in exploit_lower:
                return value
        return "Other"

    def _get_remediation(self, exploit_name: str) -> str:
        """Get remediation guidance for an exploit."""
        exploit_lower = exploit_name.lower()
        remediations = {
            "brute": "Implement account lockout policies and enforce strong password requirements. Enable MFA.",
            "spray": "Implement rate limiting and account lockout. Use MFA.",
            "cve-2024-6387": "Upgrade OpenSSH to version 9.8p1 or later. Apply vendor patches immediately.",
            "eternalblue": "Apply MS17-010 patch. Disable SMBv1. Enable SMB signing.",
            "smbghost": "Apply KB4551762 patch. Disable SMBv3 compression if not needed.",
            "bluekeep": "Apply CVE-2019-0708 patch. Enable Network Level Authentication (NLA).",
            "sql": "Use parameterized queries. Implement input validation and WAF rules.",
            "xss": "Implement Content Security Policy (CSP). Encode all output. Use modern frameworks.",
            "webshell": "Validate file uploads by type and content. Store uploads outside web root.",
            "upload": "Validate file uploads. Use allowlists for extensions. Scan uploaded files.",
            "privesc": "Apply principle of least privilege. Regularly patch systems. Audit SUID binaries.",
            "suid": "Remove unnecessary SUID permissions. Audit with tools like LinPEAS.",
            "container": "Run containers as non-root. Use read-only root filesystems. Apply seccomp profiles.",
            "docker": "Secure Docker daemon with TLS. Use user namespaces. Enable Docker Content Trust.",
            "ldap": "Disable anonymous binds. Implement LDAPS. Enforce strong authentication.",
            "redis": "Enable AUTH. Bind to localhost only. Use firewall rules. Enable TLS.",
        }
        for key, value in remediations.items():
            if key in exploit_lower:
                return value
        return "Review and apply vendor security advisories. Implement defense-in-depth measures."

    def _categorize_error(self, error: str) -> str:
        """Categorize an error message."""
        error_lower = error.lower()
        if "timeout" in error_lower:
            return "Timeout"
        elif "connection" in error_lower and "refused" in error_lower:
            return "Connection Refused"
        elif "connection" in error_lower:
            return "Connection Error"
        elif "permission" in error_lower or "denied" in error_lower:
            return "Permission Denied"
        elif "not found" in error_lower:
            return "Not Found"
        elif "scope" in error_lower or "out of scope" in error_lower:
            return "Scope Violation"
        elif "rate" in error_lower or "429" in error_lower:
            return "Rate Limited"
        elif "tool" in error_lower and ("not found" in error_lower or "not installed" in error_lower):
            return "Missing Tool"
        else:
            return "Other"

    def _suggest_mitigation(self, error_type: str) -> str:
        """Suggest mitigation for an error type."""
        mitigations = {
            "Timeout": "Increase timeout values or reduce scan scope. Check network latency.",
            "Connection Refused": "Target service may be down or firewall blocking. Verify target state.",
            "Connection Error": "Check network connectivity and target accessibility.",
            "Permission Denied": "Verify credentials and permissions. Try with elevated privileges if authorized.",
            "Not Found": "Verify target exists and path is correct.",
            "Scope Violation": "Review scope configuration. Do not target out-of-scope assets.",
            "Rate Limited": "Reduce request rate. Implement delays between requests.",
            "Missing Tool": "Install required tools or use fallback alternatives.",
            "Other": "Review error details and adjust parameters accordingly.",
        }
        return mitigations.get(error_type, "Review error details and adjust parameters.")

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")


# ── Module-level helpers ─────────────────────────────────────────────────────


def _esc(value: Any) -> str:
    """HTML-escape a value rendered into the HTML report."""
    return html.escape(str(value), quote=True)


def _sev_class(severity: str) -> str:
    """Map a severity label to a CSS class slug."""
    s = str(severity or "").lower()
    if s == "critical":
        return "critical"
    if s == "high":
        return "high"
    if s == "medium":
        return "medium"
    if s == "low":
        return "low"
    return "none"


def approved_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return only human-APPROVED findings (the HITL final-report filter).

    Agents propose candidates (``hitl_status=PROPOSED``); a human Approves /
    Rejects them via the WebUI Evidence tab or ``hitl_decide``. Only
    ``APPROVED`` findings surface in the final report — PROPOSED, REJECTED,
    and undecided (missing status) findings are hidden. Never raises: a
    non-list input yields ``[]`` and non-dict rows are skipped.
    """
    if not isinstance(findings, list):
        return []
    return [
        item
        for item in findings
        if isinstance(item, dict) and str(item.get("hitl_status") or "").strip().upper() == "APPROVED"
    ]


def _confidence_from_verdict(verdict: str | None) -> float:
    """Map an OutcomeJudge verdict to a finding confidence value."""
    if verdict == "confirmed":
        return 0.95
    if verdict == "refuted":
        return 0.2
    if verdict in ("inconclusive", "exhausted", "open"):
        return 0.5
    return 0.5


def _format_retest_md(finding: dict[str, Any]) -> str:
    """One-line retest status for the Markdown report (never raises)."""
    status = str(finding.get("retest_status") or "")
    if not status:
        return "not retested"
    history = finding.get("retest_history") or []
    if isinstance(history, list) and history and isinstance(history[-1], dict):
        last = history[-1]
        evidence = str(last.get("evidence") or "")
        ts = str(last.get("timestamp") or "")
        suffix = f" @ {ts}" if ts else ""
        if evidence:
            return f"{status}{suffix} (evidence: {evidence})"
        return f"{status}{suffix}"
    return status


def _format_retest_html(finding: dict[str, Any]) -> str:
    """Escaped retest status line for the HTML report (never raises)."""
    status = str(finding.get("retest_status") or "")
    if not status:
        return _esc("not retested")
    parts = [_esc(status)]
    history = finding.get("retest_history") or []
    if isinstance(history, list) and history and isinstance(history[-1], dict):
        last = history[-1]
        ts = str(last.get("timestamp") or "")
        evidence = str(last.get("evidence") or "")
        if ts:
            parts.append(f" {_esc('@ ' + ts)}")
        if evidence:
            parts.append(f" (evidence: {_esc(evidence)})")
    return "".join(parts)


def _resolve_verdict(
    assessments: Mapping[str, Any] | None,
    target: str,
) -> str | None:
    """Resolve a hypothesis verdict for a target from an assessments mapping.

    Accepts either an ``OutcomeAssessment`` (duck-typed via
    ``hypothesis_status``) or a dict carrying ``hypothesis_status`` (enum or
    string). Returns the lowercased status string (e.g. ``"confirmed"``) or
    ``None`` when no assessment is present for the target.
    """
    if not assessments:
        return None
    entry = assessments.get(target)
    if entry is None:
        return None
    status = getattr(entry, "hypothesis_status", None)
    if status is None and isinstance(entry, Mapping):
        status = entry.get("hypothesis_status")
    if status is None:
        return None
    # Enum members expose ``.value``; bare strings do not.
    value = getattr(status, "value", status)
    return str(value).strip().lower() if value else None


def _service_field(service: Any, *names: str) -> str:
    """Read the first present field from a service dict (case-insensitive)."""
    if not isinstance(service, dict):
        return ""
    lower = {k.lower(): v for k, v in service.items()}
    for name in names:
        if name.lower() in lower:
            return str(lower[name.lower()] or "")
    return ""


def _bump_cia(value: str) -> str:
    """Raise a CIA metric toward High (N -> L -> H). Used when a vulnerable
    service version is detected."""
    rank = {"N": 0, "L": 1, "H": 2}
    current = rank.get(str(value).upper(), 0)
    if current >= 2:
        return "H"
    if current == 1:
        return "H"
    return "L"


def _service_indicates_vulnerable_version(services: list[dict]) -> bool:
    """Heuristic: does any exposed service banner hint at a known-vulnerable version?

    Looks for version substrings associated with high-profile CVEs (OpenSSH < 9.8,
    SMBv1, Redis unauthenticated, vsftpd 2.3.4, ProFTPD 1.3.3c, old Apache/IIS).
    Intentionally conservative — a true match only bumps C/I/A, never the score
    on its own.
    """
    for svc in services or []:
        product = _service_field(svc, "product", "service", "name").lower()
        version = _service_field(svc, "version", "banner").lower()
        blob = f"{product} {version}"
        if "openssh" in blob and any(v in blob for v in ("7.", "8.", "6.")):
            return True
        if "smbv1" in blob or ("microsoft-ds" in blob and "v1" in version):
            return True
        if "redis" in blob and "unauthorized" in blob:
            return True
        if "vsftpd" in blob and "2.3.4" in version:
            return True
        if "proftpd" in blob and "1.3.3c" in version:
            return True
        if "apache" in blob and any(v in version for v in ("2.2.", "2.4.49", "2.4.50")):
            return True
    return False


def _cvss_profile_from_services(services: list[dict]) -> tuple[str, str, str, str, str, str, str, str]:
    """Pick a (av, ac, pr, ui, c, i, a, scope) profile from exposed services.

    Used only as a fallback when the exploit name does not match a known
    branch. Recognizes SMB, SSH, Redis, LDAP, SQL, and HTTP/HTTPS surfaces;
    defaults to Network/Low/None/None with High C/I/A otherwise.
    """
    ports = set()
    products: list[str] = []
    for svc in services or []:
        port = _service_field(svc, "port", "id")
        if port:
            try:
                ports.add(int(str(port)))
            except (TypeError, ValueError):
                pass
        product = _service_field(svc, "product", "service", "name").lower()
        if product:
            products.append(product)
    blob = " ".join(products)

    if 445 in ports or "microsoft-ds" in blob or "smb" in blob:
        # SMB exposure -> remote code execution surface, scope changed.
        return ("N", "L", "N", "N", "H", "H", "H", "C")
    if 22 in ports or "ssh" in blob or "openssh" in blob:
        return ("N", "L", "N", "N", "H", "H", "H", "U")
    if 6379 in ports or "redis" in blob:
        return ("N", "L", "N", "N", "H", "H", "L", "U")
    if 389 in ports or 636 in ports or "ldap" in blob:
        return ("N", "L", "N", "N", "H", "L", "N", "U")
    if any(p in ports for p in (3306, 5432, 1433, 1521)) or any(
        k in blob for k in ("mysql", "postgres", "mssql", "oracle")
    ):
        return ("N", "L", "N", "N", "H", "L", "L", "U")
    if any(p in ports for p in (80, 443, 8080, 8443)) or "http" in blob:
        return ("N", "L", "N", "N", "L", "L", "N", "U")
    # Nothing recognized — keep the conservative default.
    return ("N", "L", "N", "N", "H", "H", "H", "U")


_HTML_CSS = """
body { margin: 0; font-family: -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif; color: #1f2328; background: #f6f8fa; }
.report { max-width: 1100px; margin: 2rem auto; padding: 2rem; background: #fff; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.08); }
.report-header h1 { margin: 0 0 0.5rem 0; font-size: 1.8rem; }
.report-header .meta { display: flex; flex-wrap: wrap; gap: 1.5rem; color: #57606a; font-size: 0.9rem; }
.section { margin: 2rem 0; padding-top: 1rem; border-top: 1px solid #d0d7de; }
.section h2 { font-size: 1.4rem; margin-top: 0; }
h3 { font-size: 1.15rem; margin: 1rem 0 0.4rem; }
h4 { font-size: 0.95rem; margin: 0.8rem 0 0.3rem; color: #57606a; text-transform: uppercase; letter-spacing: 0.04em; }
.prose { white-space: pre-wrap; font-family: inherit; font-size: 0.95rem; line-height: 1.5; margin: 0; }
.data-table { width: 100%; border-collapse: collapse; font-size: 0.88rem; }
.data-table th, .data-table td { padding: 0.45rem 0.6rem; border: 1px solid #d0d7de; text-align: left; }
.data-table th { background: #f6f8fa; }
.data-table td.ok { color: #1a7f37; font-weight: 600; }
.data-table td.fail { color: #cf222e; font-weight: 600; }
.chain { margin: 1rem 0; padding: 1rem; background: #f6f8fa; border-radius: 6px; }
.chain-id { color: #6e7781; font-weight: 400; font-size: 0.85rem; }
.chain-steps { margin: 0.5rem 0; padding-left: 1.4rem; }
.muted { color: #6e7781; }
.finding, .failure { margin: 1.2rem 0; padding: 1rem 1.2rem; border: 1px solid #d0d7de; border-radius: 6px; }
.finding-meta { display: flex; flex-wrap: wrap; gap: 1rem; font-size: 0.85rem; color: #57606a; margin-bottom: 0.5rem; }
.badge { display: inline-block; padding: 0.1rem 0.5rem; border-radius: 10px; font-size: 0.75rem; font-weight: 700; color: #fff; }
.badge.sev-critical { background: #82071e; }
.badge.sev-high { background: #cf222e; }
.badge.sev-medium { background: #bf8700; }
.badge.sev-low { background: #1a7f37; }
.badge.sev-none { background: #6e7781; }
.repro, .evidence-refs, .error-breakdown { margin: 0.3rem 0; padding-left: 1.4rem; }
.repro li, .evidence-refs li { margin: 0.2rem 0; font-size: 0.9rem; }
code { background: #f6f8fa; padding: 0.1rem 0.3rem; border-radius: 3px; font-size: 0.85rem; }
"""
