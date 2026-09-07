---
title: CLI Reference (Generated)
description: Complete matrix for every python main.py flag — flag, aliases, type, default, conflicts, runtime path, examples, config keys, exit behavior. Verified against main.py:parse_args.
source: [main.py]
generated_from: main.py:parse_args
verify: every flag exists in main.py:parse_args at time of generation (2026-09-07)
---

# CLI Reference (Generated)

> Verified against `main.py:parse_args` (`main.py:352-645`). No invented flags. Run `python main.py --help` to cross-check. Dispatch order is in `main()`.

- **Default no-args** → **WebUI daemon** (`--web`: build `webui/dist/` if needed, serve `http://127.0.0.1:8765/`, open a browser) via `main._run_daemon`. `--menu` forces the legacy interactive terminal menu instead.
- **API-key bootstrap** → `tools/config_cli.bootstrap_startup_api_keys` with `prompt = --menu` only.
- **Daemon guard** — `--demon/--daemon/--web` refuse `target/mode/goal/custom_goal/menu/doctor/demo/self_test/eval/benchmark/skills_list/list_plugins/setup_api_keys` → exit 2.
- **Dispatch** — `setup_api_keys` solo exit → daemon/web → `--doctor` → `--self-test` → `--eval-list` → `--save-baseline/--check-regression` gate → `--benchmark` → `--eval` (graded without `--target`, legacy with `--target`) → `--ctf` → `--demo` → `--skills-list` → `--list-plugins` → `--menu` → no-args web → `async_main`.

Exit codes: `0` success/clean abort, `1` run/config/auth failure (or `--check-regression` fail), `2` flag conflict / non-loopback bind / `--save-baseline/--check-regression` without `--eval/--benchmark`, `130` `KeyboardInterrupt`.

## Flag matrix

| Flag | Aliases | Type | Default | Conflicts | Runtime path | Examples | Config keys | Exit |
|------|---------|------|---------|-----------|--------------|----------|-------------|------|

| `--version` | — | `store version` | n/a | — | `main.py:374` `argparse version` | `python main.py --version` | — | 0 + print `BreachPilot <ver>` |
| `--target` | — | `str` | `""` | daemon/web | `main.py:377` core targeting; threaded via `mcp_session.py:255` → `EXPLOIT_TARGET*` env; `_allowed_target_list` union; persisted via `config_cli.add_target_to_allowlist` on interactive menu | `python main.py --target 10.0.0.50 --mode attack --goal backdoor`<br>`python main.py --target example.com --mode recon` | `exploit.allowed_targets` (union), `exploit.require_explicit_allowlist` | 1 if malformed (not IP/FQDN) |
| `--mode` | — | `choices: recon \| attack \| fast` | `""` → `recon` in `RunRequest` | — | `main.py:378` core | `python main.py --target 10.0.0.50 --mode recon --goal initial_access`<br>`--mode fast` = parallel recon preset then attack | `exploit.*`, `reasoning.*` budgets; recon always `READ_ONLY` via `cli_exploit_settings:157` | — |
| `--goal` | — | `str` | `""` | — | `main.py:384` core → `GoalEngine` | `python main.py --target 10.0.0.50 --goal backdoor` | — | 1 if preset unknown (via `GoalEngine`) |
| `--custom-goal` | — | `str` | `""` | — | `main.py:387` core | `python main.py --target 10.0.0.50 --custom-goal \"get domain admin\"` | — | — |
| `--config` | — | `Path` | `Path("config.yaml")` | — | `main.py:388` all config loads (`tools/kernel/config.load_config`, `ConfigValidator`, `load_validated_config`, `doctor`, `self_test`, `app.create_app`) | `python main.py --config ./my.yaml --target 10.0.0.50` | — (path to file) | 1 if non-mapping YAML |
| `--model` | — | `str` \| `None` | `None` → `models.default_alias` | — | `main.py:389` core; `run_service/service.py:349` model alias resolve | `python main.py --target 10.0.0.50 --model kimi` | `models.default_alias`, `models.registry` | — |
| `--model-strategy` | — | `choices: default \| round-robin \| random \| specific` | `"default"` | — | `main.py:392` core (passed to orchestrator campaign) | `python main.py --target 10.0.0.50 --model-strategy random` | — | — |
| `--mcp-transport` | — | `choices: stdio \| http` \| `None` | `None` | — | `main.py:398` core; **ignored on run path** — always forced to `http` so target-IP lock reaches server (`mcp_session.py`) | `python main.py --mcp-transport http --http-port 8001 --target 10.0.0.50` | `mcp.default_transport` (default `stdio`) | — |
| `--http-port` | — | `int` \| `None` | `None` | — | `main.py:404` core → `mcp_session` HTTP port | `python main.py --http-port 9001 --target 10.0.0.50` | `mcp.http_port` (default 8001) | — |
| `--reports-dir` | — | `Path` | `Path("reports")` | — | `main.py:405` core; `RunRequest.reports_dir` → `reports/<run_id>/` | `python main.py --reports-dir ./my_reports --target 10.0.0.50` | `reports_dir` (top-level override) | — |
| `--setup-api-keys` | — | `store_true` | `False` | daemon/web | `main.py:410` keys group → `bootstrap_startup_api_keys(force_prompt=True)` → `api_key_store.save_api_keys` | `python main.py --setup-api-keys --api-key-file secr.json` | `ollama.api_key_env`, `research.*`, `cve_lookup.*` (via `configured_api_key_env_names`) | 0 solo; prompts then saves `secr.json` `0o600` |
| `--api-key-file` | — | `Path` | `Path("secr.json")` (`DEFAULT_API_KEY_FILE`) | — | `main.py:413` keys group | `python main.py --api-key-file ./secrets.json --target 10.0.0.50` | — | — |
| `--no-api-key-prompt` | — | `store_true` | `False` | — | `main.py:416` keys group → suppresses `bootstrap_startup_api_keys(prompt=...)` | `python main.py --no-api-key-prompt --target 10.0.0.50` | — | — |
| `--plain` | — | `store_true` | `False` | — | `main.py:419` output → `ui.plain = plain or quiet or json` | `python main.py --plain --target 10.0.0.50` | — | — |
| `--menu` | — | `store_true` | `False` | daemon/web | `main.py:420` output → forces `interactive_menu` even with args; also flips `interactive_startup` for api-key prompt | `python main.py --menu` | — | — |
| `--json` | — | `store_true` | `False` | — | `main.py:421` output → machine-readable + forces plain | `python main.py --json --target 10.0.0.50 --mode recon` | — | — |
| `--quiet` | — | `store_true` | `False` | — | `main.py:422` output → warnings/errors only + forces plain | `python main.py --quiet --target 10.0.0.50` | — | — |
| `--debug` | — | `store_true` | `False` | — | `main.py:423` output → `os.environ["AI_NMAP_DEBUG"]=1` (`main.py:590`), verbose logging | `python main.py --debug --target 10.0.0.50` | — | — |
| `--swarm` | — | `store_true` | `False` | — | `main.py:426` swarm → `RunRequest.swarm` → `AgentLoop.run_autonomous_campaign` / `SwarmOrchestrator` | `python main.py --target 10.0.0.50 --mode attack --swarm` | `swarm.enabled` | — |
| `--parallel-swarm` | — | `store_true` | `False` | — | `main.py:434` swarm → flips `swarm.parallel_enabled` to true; gates `route_parallel` + `spawn_subagent` MCP tool | `python main.py --target 10.0.0.50 --swarm --parallel-swarm` | `swarm.parallel_enabled`, `swarm.per_phase_concurrency`, `swarm.exploit_parallel`, `swarm.subagent_timeout_seconds` | — |
| `--critic` | — | `store_true` | `False` | — (requires `--swarm` at run time; flag alone no-op) | `main.py:442` swarm | `python main.py --target 10.0.0.50 --swarm --critic` | `swarm.critic_enabled` (via `cli_exploit_settings`) | — |
| `--reflection` | — | `store_true` | `False` | — (requires `--swarm`) | `main.py:443` swarm | `python main.py --target 10.0.0.50 --swarm --reflection` | `swarm.reflection_enabled` | — |
| `--adaptive-exploits` | — | `store_true` | `False` | — | `main.py:444` swarm → `adaptive_exploits.enabled` | `python main.py --target 10.0.0.50 --adaptive-exploits` | `adaptive_exploits.enabled`, `max_mutations`, `mutation_strategies` | — |
| `--long-session` | — | `store_true` (`dest long_session`) | `False` | — | `main.py:447` swarm → raises `long_session.*` budgets (`cli_exploit_settings:43`, `_compute_swarm_timeout`) + `request_timeout_seconds` | `python main.py --target 10.0.0.50 --mode attack --long-session` | `long_session.enabled`, `request_timeout_seconds`, `attack_max_*`, `swarm_session_timeout_minutes`, `persist_messages` | — |
| `--multi-model-consult` | — | `store_true` (`dest multi_model_consult`, `default None`) | `None` → `multi_model.enabled` | mutually flips same dest with `--no-multi-model-consult` | `main.py:454` swarm → `RunRequest.multi_model_consult`; `main.py:607` default → `multi_model.enabled`; also injected as `AI_NMAP_MULTI_MODEL_ENABLED` | `python main.py --target 10.0.0.50 --multi-model-consult` | `multi_model.enabled`, `consult_aliases`, `max_consultations`, `max_question_chars` | — |
| `--no-multi-model-consult` | — | `store_false` (same dest) | `None` | same dest | `main.py:461` swarm | `python main.py --target 10.0.0.50 --no-multi-model-consult` | same | — |
| `--observer-mode` | — | `choices: heuristic \| llm \| hybrid` | `"hybrid"` | — | `main.py:467` swarm → `RunRequest.observer_mode` → `cli_exploit_settings` / `exploit_agent` | `python main.py --target 10.0.0.50 --observer-mode llm` | `reasoning.observer_mode` | — |
| `--recon-first` | — | `store_true` (`dest recon_first`, `default None`) | `None` | mutual with `--no-recon-first` | `main.py:473` swarm → `RunRequest.recon_first` → `async_main` / `run_service` goal suggestion | `python main.py --target 10.0.0.50 --recon-first` | — | — |
| `--no-recon-first` | — | `store_false` (same dest) | `None` | same | `main.py:479` swarm | `python main.py --target 10.0.0.50 --no-recon-first --goal backdoor` | — | — |
| `--ultrathink` | — | `store_true` | `False` | — | `main.py:485` swarm → `RunRequest.ultrathink` → `cli_exploit_settings.chain_of_thought` + `verbose_reasoning`; `main.py:594` banner | `python main.py --target 10.0.0.50 --ultrathink` | `reasoning.ultrathink`, `ultrathink_reflection_interval`, `llm_reflection` | — |
| `--doctor` | — | `store_true` | `False` | daemon/web | `main.py:492` ops → `tools/doctor.run_doctor(config_path)` → exits before exploit session | `python main.py --doctor` | `ollama.host`, `models.registry`, `nmap.path`, `mcp.http_port`, `api.host` | 0 all pass; 1 any fail |
| `--demo` | — | `store_true` | `False` | daemon/web | `main.py:493` ops → `tools/demo_mode.run_demo` (Docker DVWA or synthetic server) | `python main.py --demo` | — | — |
| `--resume` | — | `str` | `""` | — | `main.py:494` ops → `RunRequest.resume_source` → `tools/resume_state` + `RunPreview` | `python main.py --resume <run_id>` | `long_session.persist_messages` (`session_state.json`) | — |
| `--yes` | — | `store_true` | `False` | — | `main.py:495` ops → skips ready-to-begin confirmation gate (`main.py:1094`); destructive runs need matching confirmation text instead of `Y` | `python main.py --target 10.0.0.50 --mode attack --yes` | — | — (careful) |
| `--self-test` | — | `store_true` | `False` | daemon/web (also blocks auto ChatGPT runtime ensure) | `main.py:496` ops → `tools/self_test.run_self_test` (localhost-only, `read_only`, `check_os/quick_scan/search_cve_intel/list_workspace`) → `reports/self_test_<run_id>/` | `python main.py --self-test` | `exploit.permission` forced `read_only` | 0 pass; 1 fail; rejects non-127.0.0.1 |
| `--eval` | — | `nargs="*"` (`metavar TARGET`) | `None` (bare `--eval` = `[]` → all graded targets) | daemon/web | `main.py:500` eval group → `run_graded_eval` (no `--target`) or legacy `run_eval` (with `--target`) | `python main.py --eval`<br>`python main.py --eval dvwa juice_shop`<br>`python main.py --eval --target 10.0.0.50` (legacy single-target) | `eval.*` (output_dir, max_rounds, baseline_path) | graded 0 (1 on `--check-regression` fail); legacy writes `reports/eval/<run_id>/` |
| `--eval-list` | — | `store_true` (`dest eval_list`) | n/a | daemon/web | `main.py:509` | `python main.py --eval-list` | `eval_targets/*.oracle.json` | 0 + stdout |
| `--save-baseline` | — | `store_true` (`dest save_baseline`) | n/a | requires `--eval`/`--benchmark` → 2 | `main.py:515` | `python main.py --eval --save-baseline` | `eval.baseline_path` | 0 + writes baseline |
| `--check-regression` | — | `store_true` (`dest check_regression`) | n/a | requires `--eval`/`--benchmark` → 2 | `main.py:521` | `python main.py --eval --check-regression` | `eval.baseline_path`, `eval.regression_tolerance` | 1 on hard regression |
| `--benchmark` | — | `nargs="*"` (`metavar SUITE`) \| `None` | `None` | daemon/web | `main.py:528` | `python main.py --benchmark xben` | `benchmark.*` | via `run_benchmark_cli` |
| `--benchmark-list` | — | `store_true` (`dest benchmark_list`) | n/a | daemon/web | `main.py:536` | `python main.py --benchmark-list` | `benchmark.*` suites | 0 + stdout |
| `--scenario` | — | `append` (`metavar ID`, `default None`) | `None` | — (read only on `--benchmark` path) | `main.py:542` | `python main.py --benchmark xben --scenario S1 --scenario S2` | — | — |
| `--tag` | — | `append` (`metavar TAG`, `default None`) | `None` | — (read only on `--benchmark` path) | `main.py:549` | `python main.py --benchmark xben --tag web` | — | — |
| `--trials` | — | `int` \| `None` | `None` | — (read only on `--benchmark` path) | `main.py:556` | `python main.py --benchmark xben --trials 3` | `benchmark.trials` (1-20) | — |
| `--ctf` | — | `store_true` | `False` | — | `main.py:565` ctf → `tools/ctf_mode.run_ctf` target-locked via allowlist | `python main.py --target 10.0.0.50 --ctf --ctf-flag-path /root/flag.txt` | `exploit.allowed_targets` | — |
| `--ctf-flag-path` | — | `str` (`dest ctf_flag_path`) | `""` | — | `main.py:571` ctf | `python main.py --target 10.0.0.50 --ctf --ctf-flag-path /flag.txt` | — | — |
| `--ctf-root-shell` | — | `store_true` (`dest ctf_root_shell`) | `False` | — | `main.py:577` ctf → `default False` (uid=0 heuristic) | `python main.py --target 10.0.0.50 --ctf --ctf-root-shell` | — | — |
| `--ctf-port` | — | `int` (`dest ctf_port`) | `0` | — | `main.py:584` ctf | `python main.py --target 10.0.0.50 --ctf --ctf-port 80 --ctf-marker FLAG_` | — | — |
| `--ctf-marker` | — | `str` (`dest ctf_marker`) | `""` | — | `main.py:587` ctf | same | — | — |
| `--skills` | — | `choices: on \| off \| hints \| lookup` \| `None` | `None` (→ hints default) | — | `main.py:592` skills → `apply_skills_cli_overrides` mutates `config["skills"]` in-memory (handles `on/hints/lookup/off`) | `python main.py --target 10.0.0.50 --skills on`<br>`--skills off` disables | `skills.enabled`, `inject_startup_context`, `allow_model_lookup` | — |
| `--skills-list` | — | `store_true` | `False` | daemon/web | `main.py:599` skills → `print_skills_catalog` read-only then exit | `python main.py --skills-list` | `skills.*` (catalog) | 0 + stdout |
| `--skills-include` | — | `append` (`metavar NAME`, `default None`) | `None` | — | `main.py:602` skills → repeatable force-include | `python main.py --target 10.0.0.50 --skills-include my-skill --skills-include other` | `skills.exclude_names` inverse; sticky across re-selection | — |
| `--skills-exclude` | — | `append` | `None` | — | `main.py:609` skills | `python main.py --target 10.0.0.50 --skills-exclude noisy-skill` | `skills.exclude_names`, `include_tags` | — |
| `--no-skills-reselect` | — | `store_true` | `False` | — | `main.py:616` skills → disables `skills.reselect_mid_run` | `python main.py --target 10.0.0.50 --no-skills-reselect` | `skills.reselect_*` | — |
| `--list-plugins` | — | `store_true` (`dest list_plugins`) | `False` | daemon/web | `main.py:621` plugins → `plugins.print_plugin_catalog` or `tools/plugins` list then exit | `python main.py --list-plugins` | `plugins.enabled/disabled/search_paths/entry_points` | 0 |
| `--demon` / `--daemon` | `--daemon` alias (`dest daemon`) | `store_true` | `False` | `target/mode/goal/custom_goal/menu/doctor/demo/eval/self_test/skills_list/list_plugins/setup_api_keys` → 2 | `main.py:629` webui → `main._run_daemon` → `app.create_app` → `uvicorn.run` loopback-only | `python main.py --demon`<br>`python main.py --daemon --api-port 9000` | `api.host/port/token_file/allowed_origins/event_buffer_size/shutdown_timeout_seconds/serve_webui` | 2 on conflict; 1 if uvicorn missing |
| `--web` | — | `store_true` (`dest web`) | `False` | same as daemon + implies `api.serve_webui=True` in-memory; also builds `webui/dist/` | `main.py:636` webui → `_ensure_webui_build` (`npm install && npm run build`), sets `api.serve_webui` in-memory, `_run_daemon`, opens browser | `python main.py --web` | `api.serve_webui`, `webui/dist` build | — |
| `--api-host` | — | `str` \| `None` | `None` → `api.host` (default `127.0.0.1`) | daemon/web only (ignored otherwise) | `main.py:642` webui → `_run_daemon` validates loopback (`127.0.0.1/localhost/::1` else 2) | `python main.py --demon --api-host 127.0.0.1` | `api.host` (loopback-only) | 2 on non-loopback |
| `--api-port` | — | `int` \| `None` | `None` → `api.port` (default `8765`) | — | `main.py:643` webui | `python main.py --demon --api-port 8765` | `api.port` | — |

### Flow B legacy (`python cli.py`) — not `main.parse_args`, included for completeness

| Command | Args | Source |
|---------|------|--------|
| `init-mission --config <path>` | required config | `legacy/cli.py:521` |
| `add-scope --allow <pat> | --deny <pat> --notes <t>` | scope rule | `legacy/cli.py:526` |
| `list-scope [--mission-id]` | — | `legacy/cli.py:533` |
| `next-task [--mission-id]` | — | `legacy/cli.py:537` |
| `list-tasks [--mission-id]` | — | `legacy/cli.py:541` |
| `run-task [task_id] [--mission-id]` | executor | `legacy/cli.py:545` |
| `summarize-target --target <name> [--mission-id]` | graph | `legacy/cli.py:550` |
| `list-findings [--mission-id]` | — | `legacy/cli.py:555` |
| `validate-finding <finding_id> [--mission-id]` | verifier | `legacy/cli.py:559` |
| `generate-report <finding_id> [--mission-id]` | markdown | `legacy/cli.py:564` |
| `status [--mission-id]` | loop status | `legacy/cli.py:569` |

Exit: `0` success, `1` error/scope-or-risk block, `130` Ctrl-C. Data `research_workspace/research.db` (`RESEARCH_WORKSPACE` override).

## Examples (from `main.py:360` epilog and dispatch)

```powershell
python main.py                                          # WebUI daemon + browser (default)
python main.py --menu                                    # legacy interactive terminal menu
python main.py --target 10.0.0.50 --mode attack --goal backdoor
python main.py --target 10.0.0.50 --mode recon --goal initial_access
python main.py --target 10.0.0.50 --ctf --ctf-flag-path /root/flag.txt
python main.py --doctor                                  # env self-check
python main.py --self-test                                # safe localhost smoke test
python main.py --web                                     # WebUI + API daemon
python main.py --resume <run_id>                          # resume prior run
python main.py --target 10.0.0.50 --mode attack --swarm --critic --reflection --adaptive-exploits
python main.py --target 10.0.0.50 --mode attack --long-session
python main.py --target 10.0.0.50 --recon-first           # scan then suggest goals
python main.py --target 10.0.0.50 --mode attack --yes     # skip confirmation gate
python main.py --skills-list                              # catalog then exit
python main.py --list-plugins                             # plugin list then exit
python main.py --demon --api-port 8765                   # daemon only
python main.py --eval --target 10.0.0.50                  # eval harness (needs --target)
```

## Verify

```powershell
python main.py --help | Select-String \"\\-\\-target\"
python -m pytest tests/test_config_cli.py tests/test_cli_mission_id.py -v  # (if present)
python main.py --doctor
```

## Related

- `docs/configuration/overview.md` — config loading/precedence.
- `docs/configuration/config-reference-generated.md` — every `config.yaml` key.
- `docs/cli-reference.md` — narrative CLI reference (host of this generated matrix).
