# System Source Map

Developer table mapping every major BreachPilot system to its primary
implementation files and documentation links. All implementation paths are
repo-relative (relative to the BreachPilot repo root). Documentation links are
relative to this file (`docs/reference/`).

### Path conventions

```bash
# Every implementation path below was verified to exist with ls/stat
# before this file was written. Paths never include machine prefixes.
ls main.py app.py cli.py db.py tools/api/routes tools/run_service
```

Rows marked with an Implementation note flag claims that rest on directory
layout and doc frontmatter rather than a full read of the implementation.

## Entrypoints and CLI dispatch

| System | Primary implementation | Documentation |
|---|---|---|
| WebUI daemon default launch, direct recon/attack runs, `--menu`, doctor, eval, benchmark flows | `main.py`, `app.py` | [architecture.md](../architecture.md), [runtime-flows.md](../runtime-flows.md), [cli-reference.md](../cli-reference.md) |
| Legacy research CLI (Flow B, frozen) | `cli.py`, `legacy/cli.py` | [components/root/cli.md](../components/root/cli.md), [runtime-flows.md](../runtime-flows.md) |
| Legacy agent loop shims (Flow B) | `agent_loop.py`, `legacy/agent_loop.py` | [components/flow-b/agent-loop.md](../components/flow-b/agent-loop.md) |
| CLI dispatch layer (config load, exploit settings, recon assessment, safety review, skills flags, interactive menu) | `tools/config_cli.py`, `tools/cli_exploit_settings.py`, `tools/recon_assessment_cli.py`, `tools/safety_review_cli.py`, `tools/skills_cli.py`, `tools/interactive_menu.py`, `tools/attack_ui.py` | [cli-reference.md](../cli-reference.md), [components/root/main.md](../components/root/main.md) |
| MCP session boot (`open_exploit_mcp_session`) | `tools/mcp_session.py` | [mcp/overview.md](../mcp/overview.md), [architecture.md](../architecture.md) |
| Single-target session wiring (ScopeGate + MCP session + agent) | `tools/exploit_session.py` | [exploit-agent.md](../exploit-agent.md), [runtime-flows.md](../runtime-flows.md) |

Implementation note: the exact flag-to-function mapping in `main.py`
(`async_main`) was not re-read line by line for this table; the entry roles
above follow `docs/architecture.md` and `CLAUDE.md`.

## Configuration

| System | Primary implementation | Documentation |
|---|---|---|
| Canonical config schema, validator, loader | `tools/config/schema.py`, `tools/config/validator.py`, `tools/config/loader.py`, `tools/config/__init__.py` | [configuration/overview.md](../configuration/overview.md), [config-reference.md](../config-reference.md) |
| Checked-in lab config and mission scope | `config.yaml`, `mission.yaml` | [configuration/environment.md](../configuration/environment.md), [configuration/secrets.md](../configuration/secrets.md) |
| Legacy config manager shim | `tools/config_manager.py` | [configuration/validation.md](../configuration/validation.md) |
| Mission model and risk profiles | `mission.py` | [components/flow-b/db-mission.md](../components/flow-b/db-mission.md), [safety-model.md](../safety-model.md) |

## API routes and run-service

| System | Primary implementation | Documentation |
|---|---|---|
| Run lifecycle endpoints | `tools/api/routes/runs.py`, `tools/api/routes/decisions.py`, `tools/api/routes/events.py` | [api/endpoints/runs.md](../api/endpoints/runs.md), [api/endpoints/decisions.md](../api/endpoints/decisions.md), [api/endpoints/events.md](../api/endpoints/events.md) |
| System, ops, users, connections, benchmarks endpoints | `tools/api/routes/system.py`, `tools/api/routes/ops.py`, `tools/api/routes/users.py`, `tools/api/routes/connections.py`, `tools/api/routes/benchmarks.py` | [api/endpoints/system.md](../api/endpoints/system.md), [api/overview.md](../api/overview.md) |
| Evidence graph endpoints | `tools/api/routes/graph.py`, `tools/api/routes/graph_explorer.py` | [api/endpoints/graph.md](../api/endpoints/graph.md) |
| Route package wiring | `tools/api/routes/__init__.py` | [api/overview.md](../api/overview.md) |
| Transport-neutral run engine (prepare + execute, typed models, providers, tasks) | `tools/run_service/service.py`, `tools/run_service/models.py`, `tools/run_service/providers.py`, `tools/run_service/tasks.py`, `tools/run_service/prepare.py`, `tools/run_service/execute.py`, `tools/run_service/warmup.py` | [run-service.md](../run-service.md), [api/run-manager.md](../api/run-manager.md) |
| API daemon auth, errors, session titling, graph service | `tools/api/auth.py`, `tools/api/errors.py`, `tools/api/session_titler.py`, `tools/api/graph_service.py`, `tools/api/graph_builder.py` | [api/auth.md](../api/auth.md), [api/overview.md](../api/overview.md) |

## MCP servers, registry, and tool families

| System | Primary implementation | Documentation |
|---|---|---|
| Defensive MCP server (scope-gated Nmap/intel) | `mcp_server.py` | [mcp/servers/defensive.md](../mcp/servers/defensive.md), [mcp/overview.md](../mcp/overview.md) |
| Exploit MCP server (permissive tool surface) | `mcp_exploit_server.py` | [mcp/servers/exploit.md](../mcp/servers/exploit.md), [mcp/overview.md](../mcp/overview.md) |
| Engine MCP server (read-only advisory) | `mcp_engine_server.py` | [mcp/servers/engine.md](../mcp/servers/engine.md) |
| Central tool wiring, audit decorator, allowlist gate | `tools/mcp_tools/registry.py` | [mcp/overview.md](../mcp/overview.md), [mcp/registration.md](../mcp/registration.md) |
| Shared transport hardening, workspace and redaction helpers | `tools/mcp_shared.py`, `tools/exceptions.py` | [mcp/overview.md](../mcp/overview.md), [mcp/security.md](../mcp/security.md) |
| Terminal execution and target-IP lock | `tools/mcp_tools/terminal/`, `tools/mcp_tools/sandbox_exec.py` | [mcp/tool-families/terminal.md](../mcp/tool-families/terminal.md) |
| Recon, web-scan, and research families | `tools/mcp_tools/recon.py`, `tools/mcp_tools/web_scan.py`, `tools/mcp_tools/research.py`, `tools/mcp_tools/domain.py` | [mcp/tool-families/recon.md](../mcp/tool-families/recon.md), [mcp/tool-families/web-scan.md](../mcp/tool-families/web-scan.md), [mcp/tool-families/research.md](../mcp/tool-families/research.md), [mcp/tool-families/domain.md](../mcp/tool-families/domain.md) |
| Attack-module, payload, Metasploit, and cracking families | `tools/mcp_tools/attack_modules.py`, `tools/mcp_tools/payloads.py`, `tools/mcp_tools/metasploit.py`, `tools/mcp_tools/cracking.py`, `tools/mcp_tools/poc_verifier.py` | [mcp/tool-families/attack-modules.md](../mcp/tool-families/attack-modules.md), [mcp/tool-families/payloads.md](../mcp/tool-families/payloads.md), [mcp/tool-families/metasploit.md](../mcp/tool-families/metasploit.md), [mcp/tool-families/cracking.md](../mcp/tool-families/cracking.md), [mcp/tool-families/poc-verifier.md](../mcp/tool-families/poc-verifier.md) |
| Sessions, credentials, workspace, and operator families | `tools/mcp_tools/sessions.py`, `tools/mcp_tools/credentials.py`, `tools/mcp_tools/workspace.py`, `tools/mcp_tools/operator_connection.py`, `tools/mcp_tools/ad.py` | [mcp/tool-families/sessions.md](../mcp/tool-families/sessions.md), [mcp/tool-families/credentials.md](../mcp/tool-families/credentials.md), [mcp/tool-families/workspace.md](../mcp/tool-families/workspace.md), [mcp/tool-families/ad.md](../mcp/tool-families/ad.md) |
| Agent-assist families (parallel agents, peer models, runtime skills, MITRE, replay) | `tools/mcp_tools/parallel_agents.py`, `tools/mcp_tools/peer_models.py`, `tools/mcp_tools/runtime_skills.py`, `tools/mcp_tools/mitre.py`, `tools/mcp_tools/replay_simulator.py` | [mcp/tool-families/parallel-agents.md](../mcp/tool-families/parallel-agents.md), [mcp/tool-families/peer-models.md](../mcp/tool-families/peer-models.md), [mcp/tool-families/runtime-skills.md](../mcp/tool-families/runtime-skills.md), [mcp/tool-families/mitre.md](../mcp/tool-families/mitre.md), [mcp/tool-families/replay-simulator.md](../mcp/tool-families/replay-simulator.md) |
| Verification-state families (propose/verify/retest, assessment state, snapshots, killchain) | `tools/mcp_tools/hitl.py`, `tools/mcp_tools/verify.py`, `tools/mcp_tools/retest.py`, `tools/mcp_tools/assessment_state.py`, `tools/mcp_tools/snapshots.py`, `tools/mcp_tools/killchain.py`, `tools/mcp_tools/browser.py`, `tools/mcp_tools/egress_guard.py` | [mcp/tool-families/verify.md](../mcp/tool-families/verify.md), [mcp/tool-families/retest.md](../mcp/tool-families/retest.md), [mcp/tool-families/assessment-state.md](../mcp/tool-families/assessment-state.md), [mcp/lifecycle.md](../mcp/lifecycle.md) |

## Attack modules and campaign

| System | Primary implementation | Documentation |
|---|---|---|
| Attack module base, ranking registry, module families | `tools/attack_modules/base.py`, `tools/attack_modules/registry.py`, `tools/attack_modules/modules/`, `tools/attack_modules/graph.py`, `tools/attack_modules/artifacts.py` | [attack-modules.md](../attack-modules.md), [components/tools/attack-modules/overview.md](../components/tools/attack-modules/overview.md), [components/tools/attack-modules/registry.md](../components/tools/attack-modules/registry.md) |
| Autonomous campaign engine (state, executor, phases, batch, preflight, persistence) | `tools/campaign/orchestrator.py`, `tools/campaign/state.py`, `tools/campaign/executor.py`, `tools/campaign/phases.py`, `tools/campaign/batch.py`, `tools/campaign/preflight.py`, `tools/campaign/state_store.py`, `tools/campaign/service_tasks.py`, `tools/autonomous_orchestrator.py` | [architecture.md](../architecture.md), [runtime-flows.md](../runtime-flows.md) |
| Attack planner, payload crafter, exploit mutator | `tools/attack_planner.py`, `tools/payload_crafter.py`, `tools/exploit_mutator.py`, `tools/exploit_search.py` | [attack-modules.md](../attack-modules.md) |

## Exploit agent runner, policy, and swarm

| System | Primary implementation | Documentation |
|---|---|---|
| Canonical agent loop | `tools/exploit_agent/runner/_impl.py`, `tools/exploit_agent/runner/loop.py`, `tools/exploit_agent/__init__.py` | [exploit-agent.md](../exploit-agent.md), [components/tools/exploit-agent/loop.md](../components/tools/exploit-agent/loop.md), [components/tools/exploit-agent/overview.md](../components/tools/exploit-agent/overview.md) |
| Agent policy (permission modes, audit chain) | `tools/exploit_agent/policy.py` | [components/tools/exploit-agent/policy.md](../components/tools/exploit-agent/policy.md), [safety-model.md](../safety-model.md) |
| Agent context, prompts, tool calls, reflection, skills | `tools/exploit_agent/context.py`, `tools/exploit_agent/prompt.py`, `tools/exploit_agent/prompts.md`, `tools/exploit_agent/tool_calls.py`, `tools/exploit_agent/tool_catalog.py`, `tools/exploit_agent/reflection.py`, `tools/exploit_agent/skills.py`, `tools/exploit_agent/model_client.py`, `tools/exploit_agent/runner/` | [components/tools/exploit-agent/context.md](../components/tools/exploit-agent/context.md), [components/tools/exploit-agent/prompts.md](../components/tools/exploit-agent/prompts.md) |
| Swarm orchestrator, blackboard, negotiation, milestones | `tools/swarm/orchestrator.py`, `tools/swarm/blackboard.py`, `tools/swarm/negotiation.py`, `tools/swarm/milestones.py`, `tools/swarm/state_store.py`, `tools/swarm/reflection_run.py`, `tools/swarm/base.py`, `tools/swarm_bridge.py` | [swarm.md](../swarm.md), [components/tools/swarm/overview.md](../components/tools/swarm/overview.md), [components/tools/swarm/agents.md](../components/tools/swarm/agents.md) |
| Specialist swarm agents | `tools/swarm/agents/` | [components/tools/swarm/agents.md](../components/tools/swarm/agents.md) |

## Skills pipeline, recon, and intelligence

| System | Primary implementation | Documentation |
|---|---|---|
| Skills pipeline (registry, selection, embeddings, injection, feedback) | `tools/skill_pipeline.py`, `tools/skill_registry.py`, `tools/skill_registry_cache.py`, `tools/skill_selector.py`, `tools/skill_embeddings.py`, `tools/skill_feedback.py`, `tools/skills_cli.py`, `tools/skill_author.py`, `skills/` | [skills.md](../skills.md), [skill-authoring.md](../skill-authoring.md) |
| Recon pipeline (scanner, enumerator, config) | `tools/recon/pipeline.py`, `tools/recon/scanner.py`, `tools/recon/enumerator.py`, `tools/recon/config.py`, `tools/recon_pipeline.py`, `tools/fast_recon.py`, `tools/recon_enrichers.py`, `tools/recon_osint.py` | [components/tools/recon/overview.md](../components/tools/recon/overview.md) |
| Intelligence layer (adapters, belief, evidence, fingerprint, graph, schemas) | `tools/intelligence/`, `tools/cve_lookup.py`, `tools/threat_intel.py`, `tools/web_researcher.py` | [components/tools/intelligence/overview.md](../components/tools/intelligence/overview.md) |

Implementation note: the recon/intelligence row file roles follow directory
layout and `docs/architecture.md`; per-module responsibilities were not
individually re-read for this table.

## Kernel, sandbox, and safety

| System | Primary implementation | Documentation |
|---|---|---|
| Kernel (audit chain, allowlist, orchestration vocabulary, workspace, config) | `tools/kernel/audit.py`, `tools/kernel/allowlist.py`, `tools/kernel/orchestration.py`, `tools/kernel/workspace.py`, `tools/kernel/config.py`, `tools/kernel/parse.py`, `tools/kernel/discovered.py` | [components/tools/kernel/overview.md](../components/tools/kernel/overview.md), [safety-model.md](../safety-model.md) |
| Sandbox (manager, Docker backend/lifecycle, network, policy) | `tools/sandbox/manager.py`, `tools/sandbox/docker_backend.py`, `tools/sandbox/docker_lifecycle.py`, `tools/sandbox/network.py`, `tools/sandbox/policy.py`, `tools/sandbox/mcp_bridge.py`, `tools/sandbox/models.py` | [sandbox.md](../sandbox.md), [safety-model.md](../safety-model.md) |
| Scope, safety review, killchain, snapshots, verification | `scope_gate.py`, `tools/safety_reviewer.py`, `tools/killchain/`, `tools/snapshots.py`, `tools/verification/`, `tools/command_analyzer.py`, `tools/validation_utils.py` | [safety-model.md](../safety-model.md) |

## Benchmark, providers, and plugins

| System | Primary implementation | Documentation |
|---|---|---|
| Benchmark service (runner, registry, metrics, replay, report, storage) | `tools/benchmark/runner.py`, `tools/benchmark/registry.py`, `tools/benchmark/service.py`, `tools/benchmark/metrics.py`, `tools/benchmark/replay.py`, `tools/benchmark/report.py`, `tools/benchmark/storage.py`, `tools/benchmark_cli.py`, `benchmarks/xben/` | [benchmarks.md](../benchmarks.md) |
| Graded eval harness | `tools/eval_harness.py`, `tools/eval_benchmark.py`, `tools/eval_checks.py`, `eval_targets/` | [evaluation.md](../evaluation.md) |
| Provider registry and model routing | `tools/providers/registry.py`, `tools/providers/base.py`, `tools/providers/types.py`, `tools/providers/ollama_provider.py`, `tools/providers/opencode_go_provider.py`, `tools/providers/chatgpt_provider.py`, `tools/model_router.py`, `tools/ollama_models.py` | [providers.md](../providers.md), [provider-development.md](../provider-development.md) |
| Plugin system and bundled plugins | `tools/plugins.py`, `plugins/` | [plugin-development.md](../plugin-development.md), [extension-guide.md](../extension-guide.md) |

## Operator connection and credential vault

| System | Primary implementation | Documentation |
|---|---|---|
| Operator connection (manager, implants) | `tools/operator_connection/manager.py`, `tools/operator_connection/implants.py`, `tools/mcp_tools/operator_connection.py` | [mcp/overview.md](../mcp/overview.md) |
| Encrypted credential vault and store-backed MCP tools | `tools/credential_store.py`, `tools/mcp_tools/credentials.py`, `tools/api_key_store.py` | [mcp/tool-families/credentials.md](../mcp/tool-families/credentials.md), [configuration/secrets.md](../configuration/secrets.md) |

Implementation note: the operator-connection doc link points at the MCP
overview because no dedicated operator-connection doc was found in `docs/`;
the implementation paths above were verified to exist.

## Logs, database, and persistence

| System | Primary implementation | Documentation |
|---|---|---|
| Decision log and run log | `tools/decision_log.py`, `tools/run_log.py`, `tools/activity_log.py` | [api/persistence.md](../api/persistence.md), [outcome-evidence.md](../outcome-evidence.md) |
| Flow B SQLite schema (missions, tasks, evidence, findings, audit) | `db.py`, `memory.py`, `evidence.py` | [database-mission.md](../database-mission.md), [components/flow-b/db-mission.md](../components/flow-b/db-mission.md), [components/flow-b/evidence-memory-graph.md](../components/flow-b/evidence-memory-graph.md) |
| API persistence, run manager, event and decision brokers | `tools/api/persistence.py`, `tools/api/run_manager.py`, `tools/api/event_broker.py`, `tools/api/decision_broker.py` | [api/persistence.md](../api/persistence.md), [api/event-broker.md](../api/event-broker.md), [api/run-manager.md](../api/run-manager.md) |
| Sessions, resume, goal and experience state | `tools/session_manager.py`, `tools/persistent_session_manager.py`, `tools/resume_state.py`, `tools/goal_engine.py`, `tools/experience_store.py`, `tools/semantic_memory.py`, `tools/attack_memory.py` | [api/persistence.md](../api/persistence.md) |

## WebUI

| System | Primary implementation | Documentation |
|---|---|---|
| Routes and pages | `webui/src/routes/`, `webui/src/App.tsx`, `webui/src/main.tsx` | [webui/overview.md](../webui/overview.md), [webui/pages/graph.md](../webui/pages/graph.md), [webui/pages/home.md](../webui/pages/home.md), [webui/pages/run.md](../webui/pages/run.md) |
| REST client, generated types, query hooks | `webui/src/api/client.ts`, `webui/src/api/types.ts`, `webui/src/api/hooks.ts`, `webui/src/api/queryClient.ts` | [webui/api-integration.md](../webui/api-integration.md), [webui.md](../webui.md) |
| Realtime (WebSocket, SSE, event buffer/store) | `webui/src/api/ws.ts`, `webui/src/api/sse.ts`, `webui/src/api/eventBuffer.ts`, `webui/src/api/eventStore.ts` | [api/websocket.md](../api/websocket.md), [api/event-broker.md](../api/event-broker.md), [webui/state.md](../webui/state.md) |
| Components and feature slices | `webui/src/components/`, `webui/src/features/` | [webui/components/graph.md](../webui/components/graph.md), [webui/components/run-create.md](../webui/components/run-create.md) |

Implementation note: the route-to-doc mapping follows the `webui/` doc tree;
individual `.tsx` page responsibilities were not re-read for this table.

## Tests, benchmarks, and evaluation

| System | Primary implementation | Documentation |
|---|---|---|
| Mocked pytest suite (scope, safety, recon, MCP, API, swarm, skills) | `tests/`, `conftest.py`, `tests/test_scope_gate.py` | [testing-guide.md](../testing-guide.md), [type-checking.md](../type-checking.md) |
| Oracle benchmark suites | `benchmarks/xben/`, `tools/benchmark/` | [benchmarks.md](../benchmarks.md) |
| Eval oracle targets and graded harness | `eval_targets/`, `tools/eval_harness.py` | [evaluation.md](../evaluation.md) |

## Related documentation

- [architecture.md](../architecture.md) — system shape, entry points, Flow A/B split
- [runtime-flows.md](../runtime-flows.md) — mission creation and agent loop flows
- [run-service.md](../run-service.md) — transport-neutral run engine and API layer
- [api/overview.md](../api/overview.md) — WebUI API lifecycle, auth, brokers
- [mcp/overview.md](../mcp/overview.md) — MCP server topology and security model
- [exploit-agent.md](../exploit-agent.md) — canonical agent loop reference
- [swarm.md](../swarm.md) — multi-agent execution engine
- [attack-modules.md](../attack-modules.md) — attack module system
- [skills.md](../skills.md) — runtime skills system
- [sandbox.md](../sandbox.md) — disposable execution boundary
- [safety-model.md](../safety-model.md) — permission model and safety boundaries
- [providers.md](../providers.md) — LLM provider abstraction
- [webui/overview.md](../webui/overview.md) — WebUI architecture
- [benchmarks.md](../benchmarks.md) — reproducible benchmark suites
- [evaluation.md](../evaluation.md) — graded eval harness
- [cli-reference.md](../cli-reference.md) — CLI flag reference
- [config-reference.md](../config-reference.md) — configuration reference
- [glossary.md](../glossary.md) — subsystem vocabulary
