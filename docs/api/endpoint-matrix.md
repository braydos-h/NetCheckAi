---
title: Endpoint Matrix — Method | Route | Handler | Request | Response | Auth | Frontend Consumer | Tests
sources:
  - tools/api/routes/system.py
  - tools/api/routes/runs.py
  - tools/api/routes/decisions.py
  - tools/api/routes/events.py
  - tools/api/routes/graph.py
  - tools/api/routes/graph_explorer.py
  - tools/api/routes/users.py
  - tools/api/routes/benchmarks.py
  - tools/api/routes/ops.py
  - app.py
tests:
  - tests/test_api_auth.py
  - tests/test_api_runs.py
  - tests/test_api_events.py
  - tests/test_api_frontend.py
  - tests/test_api_campaign_checkpoint.py
  - tests/test_api_persistence.py
  - tests/test_api_webui.py
  - tests/test_api_webui_regression.py
  - tests/test_api_cli_args.py
  - tests/test_api_reset.py
  - tests/test_api_memory.py
  - tests/test_benchmark_api.py
subsystem: api
status: maintained
---

# Endpoint Matrix

Generated from code — no invented routes. Handler names are the Python functions decorated with `@router.*` in each `tools/api/routes/*.py`. Auth column is the FastAPI dependency applied (bearer on every route except `GET /health`; WS uses first-message bearer). Frontend consumer is the WebUI hook/component that calls the endpoint (from `webui/src/api/*` and `webui/src/features/*`); when no dedicated consumer exists the cell is `—` (direct `fetch` still possible).

> Base prefix: `http://127.0.0.1:8765` (default `api.host` + `api.port`). All REST routes below are under `/api/v1` except `WS /ws/v1/runs/{run_id}` which is at `/ws/v1`.

## System — `tools/api/routes/system.py` (`APIRouter(prefix="/api/v1", tags=["system"])`) — `app.py:148`

| Method | Route | Handler | Request | Response | Auth | Frontend consumer | Tests |
|--------|-------|---------|---------|----------|------|-------------------|-------|
| `GET` | `/api/v1/health` | `health` (`system.py:56`) | — | `200 {version:"v1", ready:true}` | none | `webui/src/api/hooks.ts` — no auth check needed | `tests/test_api_auth.py:test_health_no_auth` |
| `GET` | `/api/v1/capabilities` | `capabilities` (`system.py:62`) | — | `200 {api_version:"v1", features:[], constraints:{max_concurrent_runs,loopback_only,manual_tool_calls}, run_options:{modes,kinds,flags}}` | bearer `system._require_auth` | `webui/src/api/hooks.ts:useCapabilities` | `tests/test_api_auth.py`, `tests/test_api_webui.py` |
| `GET` | `/api/v1/config` | `get_config` (`system.py:136`) | — | `200 <redacted config dict>` | bearer | `webui/src/api/hooks.ts:useConfig`, `SettingsPage` | `tests/test_api_auth.py:test_config_redacts_secrets` |
| `PATCH` | `/api/v1/config` | `patch_config` (`system.py:190`) | `dict` (partial config) | `200 {status:"ok", config:<sanitized>}` | bearer | `webui/src/api/hooks.ts:useUpdateConfig` | `tests/test_api_frontend.py` |
| `GET` | `/api/v1/secrets` | `get_secrets` (`system.py:205`) | — | `200 {keys:{ENV:"configured|missing"}}` | bearer | `webui/src/api/hooks.ts:useSecrets` | `tests/test_api_auth.py` |
| `PUT` | `/api/v1/secrets` | `put_secrets` (`system.py:227`) | `{secrets:{name:value}}` | `200 {status:"ok", written:[]}` | bearer | `webui/src/api/hooks.ts:usePutSecrets` | `tests/test_api_auth.py:test_secret_write_*` |
| `GET` | `/api/v1/models` | `list_models` (`system.py:261`) | — | `200 {provider, default_alias, registry, info, chatgpt?}` | bearer | `webui/src/api/hooks.ts:useModels` | `tests/test_api_frontend.py` |
| `POST` | `/api/v1/models` | `add_model` (`system.py:284`) | `{alias:str, model:str}` | `200 {status:"ok", alias, model, registry}` | bearer | — | — |
| `DELETE` | `/api/v1/models/{alias}` | `remove_model` (`system.py:302`) | — | `200 {status:"ok", alias, deleted:true}` | bearer | — | — |
| `POST` | `/api/v1/models/provider` | `set_model_provider` (`system.py:323`) | `{provider:"ollama|opencode_go|chatgpt"}` | `200 {status:"ok", provider}` | bearer | `webui/src/features/settings/SettingsPage.tsx` | — |
| `POST` | `/api/v1/models/refresh` | `refresh_models` (`system.py`) | — | `200 {ok, host, available_count, updates:{alias:{old,new}}, registry, persisted}` or `503 {ok:false, error}` / `400 invalid_provider` | bearer | `webui/src/api/hooks.ts:useSyncModels` | `tests/test_api_models.py:test_refresh_models_*` |
| `GET` | `/api/v1/system/info` | `get_system_info` (`system.py:338`) | — | `200 {hostname, platform, os, python, local_ips, public_ip}` | bearer | `webui/src/features/settings/SystemInfo` | — |
| `GET` | `/api/v1/system/telemetry` | `get_telemetry` (`system.py:380`) | — | `200 {summary, recent:[50]}` | bearer | `webui/src/routes/StatsPage.tsx` | — |
| `GET` | `/api/v1/system/memory` | `get_memory` (`system.py:520`) | — | `200 {lessons:[], confidence:[], attack_memory:[]}` | bearer | `webui/src/routes/MemoryPage.tsx` | `tests/test_api_memory.py` |
| `POST` | `/api/v1/system/reset` | `reset_system` (`system.py:526`) | — | `200 {status:"ok", runs_deleted, removed:[], research_cleared}` | bearer | `webui/src/features/settings/SettingsPage.tsx` | `tests/test_api_reset.py` |
| `GET` | `/api/v1/plugins` | `list_plugins` (`system.py:611`) | — | `200 {plugins:[]}` | bearer | `webui/src/api/hooks.ts:usePlugins` | — |
| `GET` | `/api/v1/skills` | `list_skills` (`system.py:622`) | — | `200 {skills:[{name,description,tags}]}` | bearer | `webui/src/api/hooks.ts:useSkills` | — |
| `GET` | `/api/v1/skills/search` | `search_skills` (`system.py:638`) | `?q` | `200 {results:[{name,description}][:20]}` | bearer | `webui/src/api/hooks.ts:useSkillSearch` | — |
| `POST` | `/api/v1/diagnostics/doctor` | `run_doctor` (`system.py:664`) | — | `200 {exit_code, output}` | bearer | `webui/src/features/settings/SettingsPage.tsx` | `tests/test_api_frontend.py:test_doctor_returns_output` |
| `POST` | `/api/v1/diagnostics/self-test` | `run_self_test` (`system.py:671`) | — | `200 {exit_code, output}` | bearer | `webui/src/features/settings/SettingsPage.tsx` | `tests/test_api_frontend.py:test_self_test_returns_output` |
| `GET` | `/api/v1/attack/modules` | `list_attack_modules` (`system.py:688`) | — | `200 {modules:[{name,description,family,target_services,target_ports,required_cves,destructive_ics}]}` | bearer | `webui/src/routes/AttackModulesPage.tsx` | — |
| `GET` | `/api/v1/goals` | `list_goals` (`system.py:713`) | — | `200 {goals:[{name,description,risk,compatible}]}` | bearer | `webui/src/routes/GoalsPage.tsx` | `tests/test_api_frontend.py:test_goals_list` |
| `GET` | `/api/v1/config/schema` | `get_config_schema` (`system.py:743`) | — | `200 {schema:CONFIG_SCHEMA}` | bearer | `webui/src/api/hooks.ts:useConfigSchema` | `tests/test_api_frontend.py:test_config_schema` |
| `GET` | `/api/v1/models/live` | `list_live_models` (`system.py:753`) | — | `200 {models:[], source:"ollama|chatgpt"}` or `503 {models, source:"registry", error}` | bearer | `webui/src/api/hooks.ts:useLiveModels` | `tests/test_api_frontend.py:test_models_live_*` |
| `GET` | `/api/v1/providers` | `get_providers` (`system.py:857`) | — | `200 {provider, chatgpt:{enabled,authenticated,proxy_running,host,port,default_model,we_started}}` | bearer | `webui/src/features/settings/SettingsPage.tsx` | — |
| `POST` | `/api/v1/providers/chatgpt/login` | `chatgpt_login` (`system.py:881`) | — | `200 {ok, url?, reason?}` | bearer | `webui/src/features/settings/SettingsPage.tsx` | — |
| `POST` | `/api/v1/providers/chatgpt/proxy/start` | `chatgpt_proxy_start` (`system.py:895`) | — | `200 {ok, base_url?, reason?}` | bearer | `webui/src/features/settings/SettingsPage.tsx` | — |
| `POST` | `/api/v1/providers/chatgpt/proxy/stop` | `chatgpt_proxy_stop` (`system.py:903`) | — | `200 {ok, stopped}` | bearer | `webui/src/features/settings/SettingsPage.tsx` | — |
| `GET` | `/api/v1/skills/{name}` | `get_skill` (`system.py:922`) | — | `200 {name,description,body,sections,tags,references,nist_csf,mitre_attack,domain,subdomain,version}` `404` | bearer | `webui/src/features/skills/SkillDetail` | `tests/test_api_frontend.py:test_skill_detail_not_found` |
| `POST` | `/api/v1/skills` | `install_skill` (`system.py:1023`) | `{name, markdown}` | `201 {name,description,tags}` `400|409` | bearer | — | — |
| `DELETE` | `/api/v1/skills/{name}` | `remove_skill` (`system.py:1101`) | — | `200 {name,deleted:true}` `400|404` | bearer | — | — |

## Runs — `tools/api/routes/runs.py` (`APIRouter(prefix="/api/v1", tags=["runs"])`) — `app.py:149`

| Method | Route | Handler | Request | Response | Auth | Frontend consumer | Tests |
|--------|-------|---------|---------|----------|------|-------------------|-------|
| `POST` | `/api/v1/runs` | `create_run` (`runs.py:184`) | `RunCreateRequest` | `201 {run_id, preview, state, decision?}` `409 conflict` | bearer | `webui/src/features/run-create/RunWizard.tsx` | `tests/test_api_runs.py:test_create_run_returns_preview` |
| `GET` | `/api/v1/runs` | `list_runs` (`runs.py:226`) | `?limit(1..200)&offset&sort(created_desc..)&q&state` | `200 {runs:[{id,state,created_at,target,mode,goal_name,target_ip,model_alias,title}], sort, total}` | bearer | `webui/src/api/hooks.ts:useRuns` | `tests/test_api_runs.py:test_list_runs`, `tests/test_api_frontend.py:test_list_runs_includes_target_and_mode` |
| `GET` | `/api/v1/runs/{run_id}` | `get_run` (`runs.py:265`) | — | `200 {id,state,created_at,updated_at,request,preview,result,error,title,cancelled_at,resumed_from,decisions}` `404` | bearer | `webui/src/api/hooks.ts:useRun` | `tests/test_api_runs.py` |
| `POST` | `/api/v1/runs/{run_id}/cancel` | `cancel_run` (`runs.py:290`) | — | `200 {run_id, state:"cancelled"}` `404|504` | bearer | `webui/src/api/hooks.ts:useCancelRun` | `tests/test_api_frontend.py:test_delete_run_after_cancel` |
| `POST` | `/api/v1/runs/{run_id}/resume` | `resume_run` (`runs.py:297`) | — | `200 {run_id,resumed_from,preview:{run_id,target_ip}}` `404|409` | bearer | `webui/src/routes/RunPage.tsx` | — |
| `POST` | `/api/v1/runs/{run_id}/title` | `set_run_title` (`runs.py:319`) | `TitleRequest{title?,regen}` | `200 {run_id,title,regenerated}` `404` | bearer | `webui/src/api/hooks.ts:useUpdateRunTitle` | — |
| `GET` | `/api/v1/runs/{run_id}/tools` | `get_tools` (`runs.py:358`) | — | `200 {tools:[schemas]}` | bearer | `webui/src/api/hooks.ts:useRunTools` | — |
| `POST` | `/api/v1/runs/{run_id}/tools/{tool_name}/calls` | `call_tool` (`runs.py:365`) | `ToolCallRequest{arguments:dict}` | `200 {tool,result}` `400|403|404|409|500` | bearer | `webui/src/features/run/ToolsPanel.tsx` | — |
| `GET` | `/api/v1/runs/{run_id}/artifacts` | `list_artifacts` (`runs.py:376`) | — | `200 {artifacts:[{name,bytes,exists}]}` | bearer | `webui/src/api/hooks.ts:useArtifacts` | `tests/test_api_frontend.py:test_list_artifacts_*` |
| `GET` | `/api/v1/runs/{run_id}/artifacts/{name:path}` | `get_artifact` (`runs.py:401`) | — | `200 <bytes contentType>` `404` | bearer | `webui/src/routes/ArtifactsPage.tsx` | `tests/test_api_frontend.py:test_get_artifact*` |
| `GET` | `/api/v1/runs/{run_id}/workspace` | `list_workspace` (`runs.py:432`) | — | `200 {files:[{path,bytes}]}` | bearer | `webui/src/api/hooks.ts:useWorkspace` | — |
| `GET` | `/api/v1/runs/{run_id}/workspace/{path:path}` | `get_workspace_file` (`runs.py:447`) | — | `200 <bytes>` `404` | bearer | — | — |
| `GET` | `/api/v1/runs/{run_id}/audit` | `get_audit` (`runs.py:465`) | — | `200 {records, chain_valid, chain_reason}` | bearer | `webui/src/api/hooks.ts:useAudit` | `tests/test_api_frontend.py:test_audit_*` |
| `GET` | `/api/v1/runs/{run_id}/witness` | `get_witness_flags` (`runs.py:513`) | — | `200 {flags:[]}` `404` | bearer | `webui/src/features/witness/WitnessPanel.tsx` | — |
| `GET` | `/api/v1/runs/{run_id}/swarm` | `get_swarm_state` (`runs.py:544`) | — | `200 {state:json}` `404` | bearer | `webui/src/api/hooks.ts:useSwarmState` | `tests/test_api_frontend.py:test_swarm_state_*` |
| `GET` | `/api/v1/runs/{run_id}/campaign` | `get_campaign_state` (`runs.py:551`) | — | `200 {state:json}` `404` | bearer | `webui/src/api/hooks.ts:useCampaignState` | `tests/test_api_frontend.py:test_campaign_state_*` |
| `GET` | `/api/v1/runs/{run_id}/logs/{name}` | `get_log` (`runs.py:563`) | `?tail(1..2000)&attempt_id&target_ip` | `200 {name,lines,total_lines_returned,total_lines_in_file}` `400|404` | bearer | `webui/src/api/hooks.ts:useLogs` | `tests/test_api_frontend.py:test_log_*` |
| `GET` | `/api/v1/runs/{run_id}/credentials` | `list_credentials` (`runs.py:640`) | — | `200 {credentials:[{username,target_host,password:"[REDACTED]",index}]}` | bearer | `webui/src/routes/LootPage.tsx` | `tests/test_api_frontend.py:test_credentials_redacted` |
| `POST` | `/api/v1/runs/{run_id}/credentials/{index}/reveal` | `reveal_credential` (`runs.py:667`) | — | `200 {index,username,target_host,password}` `404|500` audits `credential_access.jsonl` | bearer | `webui/src/routes/LootPage.tsx` | `tests/test_api_frontend.py:test_credential_reveal_*` |
| `POST` | `/api/v1/runs/{run_id}/credentials/{index}/confirm` | `confirm_credential` (`runs.py:712`) | — | `200 {index,username,target_host,confirmed}` `404|500` | bearer | — | — |
| `GET` | `/api/v1/runs/{run_id}/loot` | `list_loot` (`runs.py:770`) | — | `200 {loot:[to_json]}` | bearer | `webui/src/routes/LootPage.tsx` | `tests/test_api_frontend.py:test_loot_*` |
| `DELETE` | `/api/v1/runs/{run_id}` | `delete_run` (`runs.py:796`) | `?purge=true` | `200 {run_id,deleted:true,purged:bool}` `404|409` | bearer | `webui/src/api/hooks.ts:useDeleteRun` | `tests/test_api_frontend.py:test_delete_run_*` |

## Decisions — `tools/api/routes/decisions.py` (`APIRouter(prefix="/api/v1", tags=["decisions"])`) — `app.py:150`

| Method | Route | Handler | Request | Response | Auth | Frontend consumer | Tests |
|--------|-------|---------|---------|----------|------|-------------------|-------|
| `GET` | `/api/v1/runs/{run_id}/decisions` | `list_decisions` (`decisions.py:56`) | — | `200 {decisions:[{id,run_id,kind,prompt_text,required_text,options_json,status,answer,created_at,answered_at}]}` `404` | bearer | `webui/src/api/hooks.ts:useDecisions` | `tests/test_api_frontend.py:test_get_single_decision` (via single) |
| `GET` | `/api/v1/runs/{run_id}/decisions/{decision_id}` | `get_decision` (`decisions.py:63`) | — | `200 DecisionOut` `404` | bearer | `webui/src/api/hooks.ts:useDecision` | `tests/test_api_frontend.py:test_get_single_decision` |
| `POST` | `/api/v1/runs/{run_id}/decisions/{decision_id}` | `answer_decision` (`decisions.py:91`) | `{answer:str}` | `200 {decision_id,status:"answered"}` `400|404|409` | bearer | `webui/src/api/hooks.ts:useAnswerDecision` | `tests/test_api_campaign_checkpoint.py` |

## Events — `tools/api/routes/events.py` (`APIRouter(prefix="/api/v1", tags=["events"])`) — `app.py:151`

| Method | Route | Handler | Request | Response | Auth | Frontend consumer | Tests |
|--------|-------|---------|---------|----------|------|-------------------|-------|
| `GET` | `/api/v1/runs/{run_id}/events` | `get_events` (`events.py:66`) | `?after≥0&tail1..1000&before&limit1..1000` | `200 {run_id,events,oldest_sequence,latest_sequence,has_more_before,first_returned_sequence,last_returned_sequence,omitted_before,next_before}` `404|503` | bearer | `webui/src/api/ws.ts:seedEvents` + `EventViewer` | `tests/test_api_events.py` |
| `GET` | `/api/v1/runs/{run_id}/events/stream` | `stream_events` (`events.py:99`) | `?after≥0` | `200 StreamingResponse text/event-stream data: {json}\n\n` headers `no-cache,keep-alive,X-Accel-Buffering:no` | bearer header (never query) | `webui/src/api/sse.ts` fallback | — |
| `WS` | `/ws/v1/runs/{run_id}` | `ws_run_events` (`events.py:146`) | first JSON `{"auth":"<token>","after":int≥0}` 5 s | streams `EventOut` JSON, heartbeats every 30 s | first-message bearer + `Origin` loopback (`tools/api/auth.py:128`) | `webui/src/api/ws.ts:useRunEvents` | — |

## Graph legacy — `tools/api/routes/graph.py` (`APIRouter(prefix="/api/v1", tags=["graph"])`) — `app.py:152`

| Method | Route | Handler | Request | Response | Auth | Frontend consumer | Tests |
|--------|-------|---------|---------|----------|------|-------------------|-------|
| `GET` | `/api/v1/runs/{run_id}/graph` | `get_run_graph` (`graph.py:167`) | — | `200 {run_id,nodes:[{id,type,label,...}],edges:[{source,target,relation}]}` `404 run not found` / `404 graph_disabled` when `api.graph_route:false` | bearer | `webui/src/routes/GraphPage.tsx` (legacy) | — |

## Graph explorer — `tools/api/routes/graph_explorer.py` (`APIRouter(prefix="/api/v1/graph", tags=["graph-explorer"])`) — `app.py:153`

All below additionally gated `api.graph_route` → `404 graph_disabled` (`graph_explorer.py:61`); unknown node/run `404`; invalid enum filter silently ignored.

| Method | Route | Handler | Request | Response | Auth | Frontend consumer | Tests |
|--------|-------|---------|---------|----------|------|-------------------|-------|
| `GET` | `/api/v1/graph/runs/{run_id}` | `get_graph` (`graph_explorer.py:86`) | `?node_type=[...]&status=[...]&q&limit1..500 default300` | `200 {run_id,scope,nodes:[to_dict],edges:[to_dict],total_nodes,truncated}` | bearer | `webui/src/features/graph/AttackGraphPage.tsx` | — |
| `GET` | `/api/v1/graph/runs/{run_id}/summary` | `get_summary` (`graph_explorer.py:102`) | — | `200 {run_id,summary:{nodes,edges,total_nodes,total_edges},stats:{hosts,domains,ips,services,findings,hypotheses,evidence,observations,vulnerability_candidates,confirmed,likely,refuted,highest_degree_node,conflict_count}}` | bearer | same | — |
| `GET` | `/api/v1/graph/runs/{run_id}/conflicts` | `get_conflicts` (`graph_explorer.py:111`) | — | `200 {run_id,conflicts:[{node_value,reason,existing_confidence,proposed_confidence,node_id,scope,built_at}]}` | bearer | same | — |
| `GET` | `/api/v1/graph/runs/{run_id}/nodes/{node_id}` | `get_node` (`graph_explorer.py:120`) | — | `200 {run_id,node,edges,neighbors}` `404 node_not_found` | bearer | same | — |
| `GET` | `/api/v1/graph/runs/{run_id}/nodes/{node_id}/neighbors` | `get_neighbors` (`graph_explorer.py:133`) | `?max_hops1..4 default1&max_nodes1..200 default50` | `200 {run_id,start_node,nodes,edges}` `404` | bearer | same | — |
| `GET` | `/api/v1/graph/runs/{run_id}/paths` | `get_paths` (`graph_explorer.py:154`) | `?start&end&max_length1..8 default4&max_paths1..8 default5` | `200 {run_id,paths:[[[{distance,node,edge}]]]}` unknown endpoints `[]` | bearer | same | — |

## Benchmarks — `tools/api/routes/benchmarks.py` (`APIRouter(prefix="/api/v1/benchmarks", tags=["benchmarks"])`) — `app.py` (wired unconditionally; backed by `tools/benchmark/`)

| Method | Route | Handler | Request | Response | Auth | Frontend consumer | Tests |
|--------|-------|---------|---------|----------|------|-------------------|-------|
| `GET` | `/api/v1/benchmarks` | `benchmarks_overview` (`benchmarks.py:94`) | — | `200 {suites:[SuiteInfo],runs:[RunIndexRow],active:{run_id,state,error},baseline:BaselineMeta}` | bearer | `webui/src/features/benchmarks/api.ts:fetchOverview` | `tests/test_benchmark_api.py` |
| `GET` | `/api/v1/benchmarks/suites` | `list_suites_route` (`benchmarks.py:107`) | — | `200 {suites:[SuiteInfo]}` | bearer | same `fetchSuites` | same |
| `GET` | `/api/v1/benchmarks/suites/{suite_id}/scenarios` | `list_scenarios_route` (`benchmarks.py:120`) | — | `200 {suite,scenarios:[ScenarioInfo]}` `404 unknown suite` | bearer | same `fetchSuiteScenarios` | same |
| `GET` | `/api/v1/benchmarks/suites/{suite_id}/readiness` | `suite_readiness_route` (`benchmarks.py`) | — | `200 {suite,ready,lab_command,targets:[{scenario_id,target_type,target_host,target_ports,reachable,self_provisioned,detail}]}` `404 unknown suite` | bearer | same `fetchSuiteReadiness` (`RunBenchmarkPanel` lab warning) | `tests/test_benchmark_api.py` |
| `GET` | `/api/v1/benchmarks/runs` | `list_runs` (`benchmarks.py:137`) | `?suite&limit1..200 default50` | `200 {runs:[RunIndexRow]}` | bearer | same `fetchRuns` | same |
| `GET` | `/api/v1/benchmarks/runs/{run_id}` | `get_run` (`benchmarks.py:145`) | — | `200 RunDetail(+summary)` `404 run not found` | bearer | same `fetchRun` | same |
| `GET` | `/api/v1/benchmarks/runs/{run_id}/scenarios` | `get_run_scenarios` (`benchmarks.py:152`) | — | `200 {run_id,scenarios:[Trial]}` | bearer | same `fetchRunScenarios` | same |
| `GET` | `/api/v1/benchmarks/runs/{run_id}/events` | `get_run_events` (`benchmarks.py:170`) | `?after≥0&trial_id&limit1..5000` | `200 {run_id,events:[BenchmarkEvent],latest_sequence}` | bearer | same `fetchRunEvents` | same |
| `GET` | `/api/v1/benchmarks/runs/{run_id}/events/stream` | `stream_run_events` (`benchmarks.py:184`) | `?after≥0` | SSE `data: {event}` heartbeats, closes after ~60 s idle | bearer | — (polling used) | same |
| `POST` | `/api/v1/benchmarks/run` | `start_run` (`benchmarks.py:222`) | `BenchmarkRunRequest{suite,scenarios?,tags?,trials?,model?,reasoning?,sandbox_required?,timeout_seconds?,save_baseline?,check_regression?}` | `200 {run_id,state}` `409 conflict/invalid` | bearer | same `startBenchmarkRun` (`RunBenchmarkPanel`) | same |
| `POST` | `/api/v1/benchmarks/runs/{run_id}/cancel` | `cancel_run` (`benchmarks.py:230`) | — | `200 {run_id,cancelled}` `404 not active` | bearer | same `cancelBenchmarkRun` | same |
| `GET` | `/api/v1/benchmarks/baseline` | `get_baseline` (`benchmarks.py:254`) | — | `200 BaselineMeta` | bearer | same `fetchBaseline` | same |
| `POST` | `/api/v1/benchmarks/baseline` | `save_baseline_route` (`benchmarks.py:259`) | `{run_id}` | `200 {saved,path,run_id}` `404/409` | bearer | same `saveBaseline` | same |
| `GET` | `/api/v1/benchmarks/compare` | `compare_runs` (`benchmarks.py:276`) | `?run_a&run_b` | `200 RunComparison{run_a,run_b,comparison:{metrics,scenarios,categories}}` `404/409` | bearer | same `compareRuns` (`ComparisonView`) | same |

## Ops — `tools/api/routes/ops.py` (`APIRouter(prefix="/api/v1/ops", tags=["ops"])`) — `app.py` (wired unconditionally; read-only rollup)

| Method | Route | Handler | Request | Response | Auth | Frontend consumer | Tests |
|--------|-------|---------|---------|----------|------|-------------------|-------|
| `GET` | `/api/v1/ops/summary` | `ops_summary` (`ops.py`) | — | `200 {killchain:{enabled,goal_state,require_verification},snapshots:{enabled,provider,counterfactual},eval:{enabled,baseline_path,baseline_exists},browser:{enabled,backend},provider:{active}}` | bearer | `webui/src/routes/OpsPage.tsx` | `tests/test_ops_summary.py` |

## Users/annotations — `tools/api/routes/users.py` (`APIRouter(prefix="/api/v1", tags=["users"])`) — `app.py:154` only when `api.multi_operator:true`

| Method | Route | Handler | Request | Response | Auth | Frontend consumer | Tests |
|--------|-------|---------|---------|----------|------|-------------------|-------|
| `POST` | `/api/v1/users` | `create_user` (`users.py:98`) | `{username(1..64),password(1..256)}` | `201 {id,username,created_at,last_login}` `409 duplicate` | bearer | `webui/src/features/auth/MultiOperator.tsx` | — |
| `POST` | `/api/v1/users/login` | `login` (`users.py:116`) | `{username,password}` | `200 {id,username,created_at,last_login}` `401` | bearer | same | — |
| `GET` | `/api/v1/users` | `list_users` (`users.py:134`) | — | `200 [{id,username,created_at,last_login}]` (no hashes) | bearer | same | — |
| `POST` | `/api/v1/runs/{run_id}/annotations` | `add_annotation` (`users.py:149`) | `{body(1..4096),finding_ref≤256,user_id,username}` | `201 {id,run_id,user_id,username,body,finding_ref,created_at}` `404 run/user` | bearer | same | — |
| `GET` | `/api/v1/runs/{run_id}/annotations` | `list_annotations` (`users.py:176`) | — | `200 [{...Annotation}]` `404` | bearer | same | — |
| `DELETE` | `/api/v1/annotations/{annotation_id}` | `delete_annotation` (`users.py:184`) | — | `204` `404` | bearer | same | — |

## Non-API mounts

| Method | Route | Handler | Notes |
|--------|-------|---------|-------|
| `GET` | `/docs`, `/openapi.json`, `/redoc` | FastAPI built-ins | Not bearer-protected; filtered to hide webui routes when `api.serve_webui` (`app.py:214`) |
| `GET` | `/assets/*` + `/{full_path:path}` SPA fallback | `StaticFiles` + `FileResponse` (`app.py:172` `/_webui_spa`) | only when `api.serve_webui:true` and `webui/dist/index.html` exists |

## Coverage Notes

- Every `@router.*` decorator above was extracted via `Select-String -Pattern "@router\.(get|post|put|patch|delete|websocket)"` over the six route modules; no manual list was invented. `mcp_exploit_server.py` is not part of this daemon (separate MCP stdio server).
- `graph_explorer` paths are the six `APIRouter(prefix="/api/v1/graph")` routes verified above — not conflated with legacy `GET /api/v1/runs/{run_id}/graph`.
- `users` routes are conditional; CI exercises them only when `api.multi_operator:true` so absent-from-schema is expected in default tests.
