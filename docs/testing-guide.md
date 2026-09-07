# Testing Guide

## Run Tests

Run the full suite:

```bash
python -m pytest
```

Run a focused file:

```bash
python -m pytest tests/test_scope_gate.py
```

Run a specific test:

```bash
python -m pytest tests/test_attack_modules.py::TestModuleRegistry::test_list_modules_returns_all
```

Run smoke checks:

```bash
python main.py --doctor
python main.py --self-test
```

Coverage (matches CI; `pytest-cov` is not a dependency, so `pytest --cov` fails):

```bash
python -m coverage run -m pytest tests/
python -m coverage report
```

## What To Test By Change Type

The suite has **342** files (all mock subprocess/network — no live Nmap); this table covers the most common change types grouped by feature. When in doubt, grep `tests/` for the module name. Run `python -m pytest tests/ -v` for the full list; focused: `python -m pytest tests/test_scope_gate.py -v`.

| Change | Tests to consider |
| --- | --- |
| Mission schema/risk profile/goal engine | `tests/test_mission.py`, `tests/test_config_manager.py`, `tests/test_goal_engine.py`, `tests/test_fsm_planner.py` |
| Scope matching/rate limits/URL prefix | `tests/test_scope_gate.py`, `tests/test_scope_rate_limit.py`, `tests/test_scope_url_prefix.py`, `tests/test_target_lock_matrix.py`, `tests/test_domain_allowlist.py` |
| Risk budgets/approval | `tests/test_risk_controller.py` |
| Task lifecycle/planning/executor/observer | `tests/test_task_queue.py`, `tests/test_agent_loop.py`, `tests/test_attack_agent_integration.py`, `tests/test_executor.py`, `tests/test_observer.py`, `tests/test_phase_tracker.py`, `tests/test_runtime_context.py` |
| Hypothesis/outcome judgment/truth | `tests/test_outcome_judge.py`, `tests/test_cross_mission_wiring.py`, `tests/test_outcome_truth.py` |
| Evidence/finding/reporting/HITL/retest | `tests/test_evidence.py`, `tests/test_finding_verifier.py`, `tests/test_report_generator.py`, `tests/test_hitl.py`, `tests/test_retest.py`, `tests/test_reporting_phase_termination.py` |
| Recon pipeline/safety | `tests/test_recon_pipeline.py`, `tests/test_recon_first_session.py`, `tests/test_recon_safety.py` |
| MCP workspace/tool behavior/registry gate | `tests/test_mcp_workspace.py`, `tests/test_mcp_tool_registration.py`, `tests/test_mcp_tool_scope.py`, `tests/test_mcp_web_scan.py`, `tests/test_mcp_cracking.py`, `tests/test_mcp_runtime_skills.py`, `tests/test_mcp_injection_hardening.py`, `tests/test_registry_decorator_gate.py`, `tests/test_engine_mcp_server.py`, relevant safety tests |
| Browser agent (Playwright) | `tests/test_browser_playwright_backend.py` (mocked launcher), `tests/test_browser_manager_async.py` (funnel), `tests/test_browser_manager.py`, `tests/test_browser_mcp_tools.py` (registration/lock), `tests/test_browser_integration.py` (local HTTP app; `-m integration` needs SDK + Chromium), `tests/test_no_playwright_regression.py` (import guard), `tests/test_doctor_browser.py`, `tests/test_browser_backend_contract.py`, `tests/test_browser_capabilities.py`, `tests/test_browser_config_defaults.py`, `tests/test_browser_models.py`, `tests/test_browser_sandbox_family.py`, `tests/test_browser_shared_loop.py`, `tests/test_browser_audit_redaction.py`, `tests/test_api_capabilities_browser.py` |
| MCP transport / sessions | `tests/test_mcp_http_lifecycle.py`, `tests/test_mcp_http_hardening.py`, `tests/test_mcp_shared_helpers.py`, `tests/test_mcp_tool_registration.py` |
| Exploit modules/policy/action category | `tests/test_attack_modules.py`, `tests/test_attack_modules_api.py`, `tests/test_lateral_tools.py`, `tests/test_listeners_extended.py`, `tests/test_exploit_mutator.py`, `tests/test_exploit_permission.py`, `tests/test_exploit_scope_gate.py`, `tests/test_exploit_action_category.py`, `tests/test_exploit_engine_core.py`, `tests/test_policy_failclosed.py`, `tests/test_module_contract.py`, `tests/test_module_lint.py`, `tests/test_new_modules.py`, `tests/test_applicability_corpus.py` |
| Exploit agent retry/context | `tests/test_retry_logic.py`, `tests/test_ultrathink.py`, `tests/test_honest_retries.py`, `tests/test_context_compaction.py` |
| Swarm behavior/bridge contract | `tests/test_swarm.py`, `tests/test_swarm_integration.py`, `tests/test_swarm_observability.py`, `tests/test_swarm_parallel_phase3.py`, `tests/test_swarm_dynamic_composition.py`, `tests/test_swarm_history_bound.py`, `tests/test_swarm_negotiation.py`, `tests/test_blackboard_concurrency.py`, `tests/test_spawn_subagent.py`, `tests/test_swarm_bridge_contract.py` |
| Swarm bridge / parallel agents | `tests/test_swarm_mcp_bridge.py`, `tests/test_swarm_recon_fix.py`, `tests/test_phase4_bugfixes.py` |
| Interactive menu / attack UI / startup | `tests/test_interactive_menu.py`, `tests/test_cli_mission_id.py`, `tests/test_startup_noise.py`, `tests/test_main_fixes.py`, `tests/test_run_create_startup.py` |
| Config/doctor/self-test/validation/wiring | `tests/test_config_manager.py`, `tests/test_config_cli.py`, `tests/test_config_cli_domain.py`, `tests/test_agent_config_wiring.py`, `tests/test_doctor.py`, `tests/test_self_test.py`, `tests/test_validate_target.py`, `tests/test_sudo_pivot.py`, `tests/test_workspace_binary_write.py`, `tests/test_env_probe.py`, `tests/test_install_sh.py`, `tests/test_linux_support.py` |
| OPSEC / detection coverage | `tests/test_opsec_manager.py`, `tests/test_opsec_target_aware.py`, `tests/test_opsec_orchestrator_wiring.py`, `tests/test_opsec_ai_awareness.py`, `tests/test_detection_coverage.py`, `tests/test_detection_modules.py` |
| Plugins / Shodan / GitHub dorks / extensions | `tests/test_plugins.py`, `tests/test_plugin_wiring.py`, `tests/test_plugin_event_dispatcher.py`, `tests/test_plugin_load_cache.py`, `tests/test_plugins_shodan_github_dorks.py`, `tests/test_example_plugin.py`, `tests/test_bloodhound_ce.py`, `tests/test_sliver_plugin.py`, `tests/test_spiderfoot_plugin.py`, `tests/test_zap_scan.py`, `tests/test_browser_attack.py`, `tests/test_mobile_attack.py`, `tests/test_wireless_plugin.py`, `tests/test_snmp_plugin.py`, `tests/test_caldera_plugin.py`, `tests/test_firmware_plugin.py`, `tests/test_atomic_tests.py` |
| Domain targeting / subdomain | `tests/test_domain_allowlist.py`, `tests/test_domain_mcp_tools.py`, `tests/test_config_cli_domain.py`, `tests/test_subdomain_boundary.py`, `tests/test_recon_mcp_new_tools.py` |
| Active Directory / Kerberos / delegation | `tests/test_ad_mcp_tools.py`, `tests/test_ad_kerberos_modules.py`, `tests/test_ad_delegation_modules.py` |
| Supply chain / persistence / orchestrator phases | `tests/test_supply_chain_modules.py`, `tests/test_persistence_modules.py`, `tests/test_orchestrator_phase_modules.py`, `tests/test_orchestrator_semantic_memory.py`, `tests/test_orchestrator_failure_taxonomy.py` |
| Autonomous orchestrator / campaign | `tests/test_autonomous_phase_machine.py`, `tests/test_autonomous_persistence_checkpoint_replan.py`, `tests/test_autonomous_local_target.py`, `tests/test_autonomous_config.py`, `tests/test_autonomous_evidence_ranking.py`, `tests/test_campaign_checkpoint.py`, `tests/test_api_campaign_checkpoint.py` |
| Recon enrichers / OSINT / diff / extended | `tests/test_recon_enrichers.py`, `tests/test_recon_osint.py`, `tests/test_recon_spider_osint.py`, `tests/test_recon_diff.py`, `tests/test_recon_udp_tls_smtp_db.py`, `tests/test_recon_extended_enumerators.py`, `tests/test_recon_assessment_cve_queries.py`, `tests/test_recon_mcp_new_tools.py`, `tests/test_recon_pipeline.py`, `tests/test_recon_first_session.py`, `tests/test_recon_event_and_allowlist.py`, `tests/test_recon_spider_osint.py`, `tests/test_target_preflight.py`, `tests/test_socket_scan.py`, `tests/test_service_banner_parsing.py`, `tests/test_service_extraction.py`, `tests/test_nmap_priv.py` |
| Resume flow / learning loop / long session | `tests/test_resume_flow_a.py`, `tests/test_resume_mission.py`, `tests/test_learning_loop.py`, `tests/test_cross_mission_wiring.py`, `tests/test_long_session.py`, `tests/test_safety_reviewer.py` |
| Skill registry / embeddings / feedback / pipeline / CLI / selector | `tests/test_skill_registry.py`, `tests/test_skill_registry_cache.py`, `tests/test_skill_embeddings.py`, `tests/test_embeddings_provider.py`, `tests/test_skill_feedback.py`, `tests/test_skill_pipeline.py`, `tests/test_skill_reselection.py`, `tests/test_skills_cli.py`, `tests/test_skill_selector.py`, `tests/test_skill_selector_domain.py`, `tests/test_skill_author.py`, `tests/test_skills_api.py` |
| Model routing / telemetry / ultrathink / providers | `tests/test_model_router.py`, `tests/test_model_router_alias_and_spam.py`, `tests/test_model_telemetry.py`, `tests/test_ultrathink.py`, `tests/test_chatgpt_provider.py`, `tests/test_chatgpt_bootstrap.py`, `tests/test_opencode_go_provider.py`, `tests/test_ollama_models.py`, `tests/test_provider_registry.py`, `tests/test_provider_contract.py`, `tests/test_provider_alias_resolve.py`, `tests/test_provider_switching.py`, `tests/test_provider_tool_contract.py`, `tests/test_no_ollama_regression.py` |
| Peer consultation / multi-model | `tests/test_multi_model_consultation.py`, `tests/test_peer_consult_on_failure.py`, `tests/test_peer_outcome_judge.py` |
| Reasoning loop / reflection | `tests/test_reasoning_loop.py`, `tests/test_reflection_evidential_bridge.py`, `tests/test_capability_guidance_prompt.py`, `tests/test_key_handling_prompt.py` |
| Tool calls / parsing / outcome tracking / registry / LLM contract | `tests/test_tool_call_parse_split.py`, `tests/test_tool_outcome_tracker.py`, `tests/test_tool_router_approval.py`, `tests/test_outcome_classify.py`, `tests/test_outcome_judge_flow_a.py`, `tests/test_tool_catalog.py`, `tests/test_registry_complete.py`, `tests/test_llm_tool_contract.py`, `tests/test_llm_tool_recovery.py` |
| Validation / target / sudo pivot / workspace | `tests/test_validate_target.py`, `tests/test_sudo_pivot.py`, `tests/test_workspace_binary_write.py`, `tests/test_scanner_target_extraction.py` |
| CLI config / Wiring | `tests/test_config_cli.py`, `tests/test_cli_mission_id.py`, `tests/test_startup_noise.py`, `tests/test_api_cli_args.py`, `tests/test_github_token_bootstrap.py`, `tests/test_git_clone_preflight.py` |
| CVE / exploit synthesis / SSRF / cloud / web probes | `tests/test_cve_to_poc.py`, `tests/test_cve_lookup_concurrency.py`, `tests/test_cve_templates_phase4.py`, `tests/test_cve_lookup.py`, `tests/test_epss_kev.py`, `tests/test_msf_recipes.py`, `tests/test_metasploit_bridge.py`, `tests/test_version_aware_ranking.py`, `tests/test_weaponized_cloud_k8s_modules.py`, `tests/test_ssrf_xxe_lfi_modules.py`, `tests/test_tier4_correctness.py`, `tests/test_cloud_exploit.py`, `tests/test_web_probe_tools.py`, `tests/test_nuclei_interop.py`, `tests/test_command_analyzer.py`, `tests/test_python_egress_guard.py` |
| Cross-mission / research subsystem / intelligence | `tests/test_cross_mission_wiring.py`, `tests/test_research_subsystem.py`, `tests/test_research_assistant.py`, `tests/test_intelligence_adapter*.py`, `tests/test_intelligence_*.py`, `tests/test_discovered_provenance.py`, `tests/test_experience_ranking.py`, `tests/test_experience_action_suffix.py`, `tests/test_experience_db_switch.py`, `tests/test_semantic_memory.py` |
| Context compaction / attack memory / brute-force | `tests/test_context_compaction.py`, `tests/test_attack_memory.py`, `tests/test_intelligence_fingerprint.py`, `tests/test_intelligence_adapter_memory.py` |
| Rate limiting / reliability / recovery | `tests/test_rate_limiter.py`, `tests/test_reliability_bugs.py`, `tests/test_retry_logic.py`, `tests/test_campaign_checkpoint.py` |
| API / WebUI / runs / events / connections / users | `tests/test_api_auth.py`, `tests/test_api_runs.py`, `tests/test_api_events.py`, `tests/test_api_persistence.py`, `tests/test_api_memory.py`, `tests/test_api_webui.py`, `tests/test_api_webui_regression.py`, `tests/test_api_frontend.py`, `tests/test_run_manager.py`, `tests/test_run_log.py`, `tests/test_api_models.py`, `tests/test_graph_explorer_api.py`, `tests/test_graph_route.py`, `tests/test_api_reset.py`, `tests/test_api_cli_args.py`, `tests/test_api_isolation.py`, `tests/test_api_run_sandbox.py`, `tests/test_connections_api.py`, `tests/test_users.py` |
| Assessment state / capability / decision log | `tests/test_assessment_state_mcp_tools.py`, `tests/test_module_capability_metadata_a.py`, `tests/test_module_capability_metadata_b.py`, `tests/test_capability_guidance_prompt.py`, `tests/test_decision_log_hook.py`, `tests/test_task_graph_simulations.py` |
| Evidence / audit / credential / artifact graph | `tests/test_evidence.py`, `tests/test_evidence_bridge.py`, `tests/test_enhanced_reporting_evidence.py`, `tests/test_flow_a_enhanced_report.py`, `tests/test_credential_store.py`, `tests/test_audit_redaction.py`, `tests/test_audit_extra_redaction.py`, `tests/test_audit_chain.py`, `tests/test_audit_failure.py`, `tests/test_audit_memory_bound.py`, `tests/test_approval_denial_audit.py`, `tests/test_activity_log.py`, `tests/test_run_log.py`, `tests/test_artifact_graph.py` |
| ICS / IoT / MITRE / webhook / ticketing / target graph | `tests/test_ics_exploit.py`, `tests/test_ics_iot_modules.py`, `tests/test_mitre_export.py`, `tests/test_webhook_notify.py`, `tests/test_ticketing.py`, `tests/test_threat_intel.py`, `tests/test_target_graph.py` |
| Spinner / environment / logging / packaging / sync guards | `tests/test_spinner_release.py`, `tests/test_env_probe.py`, `tests/test_logging_setup.py`, `tests/test_summarizer.py`, `tests/test_demo_seed.py`, `tests/test_requirements_sync.py`, `tests/test_wheel_packaging.py`, `tests/test_wheel_cwd_regression.py`, `tests/test_fast_mode.py`, `tests/test_post_exploit.py`, `tests/test_ops_summary.py` |
| Capability upgrade / wiring / witness | `tests/test_witness_agent.py`, `tests/test_witness_wiring.py`, `tests/test_attack_modules_api.py`, `tests/test_bel_adversarial.py`, `tests/test_ctf_mode.py`, `tests/test_local_target.py` |
| Credential store / audit redaction / PoC verifier / oracle | `tests/test_credential_store.py`, `tests/test_audit_redaction.py`, `tests/test_audit_chain.py`, `tests/test_poc_verifier.py`, `tests/test_poe_verifier.py`, `tests/test_replay_simulator.py`, `tests/test_session_titler.py`, `tests/test_attack_oracles.py`, `tests/test_verify_oracle.py` |
| Benchmark suite / eval harness / live evals | `tests/test_benchmark_api.py`, `tests/test_benchmark_cli.py`, `tests/test_benchmark_metrics.py`, `tests/test_benchmark_requires_capabilities.py`, `tests/test_benchmark_runner.py`, `tests/test_benchmark_runner_extended.py`, `tests/test_benchmark_scoring.py`, `tests/test_benchmark_storage.py`, `tests/test_benchmark_xben.py`, `tests/test_eval_benchmark.py`, `tests/test_eval_cli.py`, `tests/test_eval_config.py`, `tests/test_eval_harness.py`, `tests/test_eval_suite.py`, `tests/test_live_evals.py` |
| Sandbox worker (Docker/native) | `tests/test_sandbox_backend.py`, `tests/test_sandbox_docker_lifecycle.py`, `tests/test_sandbox_family_audit.py`, `tests/test_sandbox_hardening.py`, `tests/test_sandbox_integration.py`, `tests/test_sandbox_manager.py`, `tests/test_sandbox_mcp_exec.py`, `tests/test_sandbox_models.py`, `tests/test_sandbox_native_fallback.py`, `tests/test_sandbox_network.py`, `tests/test_sandbox_policy.py`, `tests/test_sandbox_remediation.py` |
| Snapshots / kill-chain | `tests/test_snapshots.py`, `tests/test_killchain.py` |
| Security regressions | `tests/test_security_regressions.py` |

## Test Workspace Pattern

Many tests use temporary or dedicated workspaces. Keep this pattern:

- Use temporary directories for generated files.
- Avoid writing into real `reports/` or `exploit_workspace/` unless a test is explicitly checking that behavior.
- Use localhost or mocked command execution for network/security tests.
- Keep regression fixtures small and readable.

## External Dependencies

Some runtime features require tools that may not be present on every developer machine:

- `nmap`
- Ollama and configured models
- Metasploit
- `searchsploit`
- system package managers
- Unix session tooling

Unit tests should mock these where possible. `--doctor` and `--self-test` are the right place to validate local machine readiness.

## Outcome-Judgment Regressions

`tests/test_outcome_judge.py` is deterministic and requires no network tools or
model. It covers execution/evidence separation, matching and contradictory
structured evidence, single versus repeated inconclusive attempts, duplicate
check rejection, terminal-state planning guards, restart persistence, and
version-3 database migration. Existing scope, approval, target-lock, and risk
tests remain the safety regression suite; outcome judgment does not replace
those gates.

## Before Handoff

For small changes, run the focused tests that match the touched module.

For cross-cutting changes, run:

```bash
python -m pytest
python main.py --doctor
python main.py --self-test
```

If a command cannot run because a local external tool is missing, note that in the handoff and include the focused tests that did run.
