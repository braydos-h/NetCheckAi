# Entrypoints

`main.py` (Flow A, active) and `legacy/cli.py` (Flow B, frozen) are the two
command-line entries. Root `cli.py`, `agent_loop.py`, `planner.py`,
`executor.py`, `observer.py`, `memory.py`, `mission.py`, and `evidence.py` are
`DeprecationWarning` shims over `legacy.*`. The installed `breachpilot`
command maps to `main:main`.

## Overview

| Entry | Flow | How to run |
|-------|------|------------|
| `main.py` | Flow A (active engine) | `python main.py`, `python main.py --menu`, `python main.py --target ...` |
| `breachpilot` | Flow A (console script) | `breachpilot --doctor` (same args as `main.py`) |
| `legacy/cli.py` | Flow B (frozen, SQLite) | `python legacy/cli.py init-mission --config mission.yaml` |
| `cli.py` (root) | Flow B shim | `python cli.py status` (warns, delegates to `legacy.cli`) |
| `app.py` | Flow A (not a CLI) | Imported by `main._run_daemon` via `create_app`; never run directly |

```bash
python main.py --doctor
python main.py --target 10.0.0.50 --mode recon --goal initial_access
breachpilot --daemon --api-port 9000
python legacy/cli.py init-mission --config mission.yaml
python legacy/cli.py status
```

## Flow A — `main.py`

Argument parser is `main.parse_args` (`main.py:352-645`). The `--version`
flag prints `BreachPilot <version>` and exits.

### Flag groups

Group names are the `argparse` argument groups in `parse_args`.

| Group | Flags |
|-------|-------|
| `targeting` | `--target`, `--mode {recon,attack,fast}`, `--goal`, `--custom-goal`, `--config`, `--model`, `--model-strategy`, `--mcp-transport`, `--http-port`, `--reports-dir` |
| `api keys` | `--setup-api-keys`, `--api-key-file`, `--no-api-key-prompt` |
| `output` | `--plain`, `--menu`, `--json`, `--quiet`, `--debug` |
| `swarm & reasoning` | `--swarm`, `--parallel-swarm`, `--critic`, `--reflection`, `--adaptive-exploits`, `--long-session`, `--multi-model-consult` / `--no-multi-model-consult`, `--observer-mode`, `--recon-first` / `--no-recon-first`, `--ultrathink` |
| `operational` | `--doctor`, `--demo`, `--resume`, `--yes`, `--self-test` |
| `eval & regression` | `--eval [TARGET ...]`, `--eval-list`, `--save-baseline`, `--check-regression` |
| `benchmark suite` | `--benchmark [SUITE ...]`, `--benchmark-list`, `--scenario`, `--tag`, `--trials` |
| `ctf autopilot` | `--ctf`, `--ctf-flag-path`, `--ctf-root-shell`, `--ctf-port`, `--ctf-marker` |
| `runtime skills` | `--skills {on,off,hints,lookup}`, `--skills-list`, `--skills-include`, `--skills-exclude`, `--no-skills-reselect` |
| `plugins` | `--list-plugins` |
| `webui` | `--demon` / `--daemon`, `--web`, `--api-host`, `--api-port` |

Notable defaults from `parse_args`: `--config` defaults to `config.yaml`;
`--eval` and `--benchmark` use `nargs="*"` with default `None` (bare
`--eval` is an empty list, meaning all oracle targets);
`--ctf-root-shell` is `store_true` with default `False`
(`main.py:577-583`); `--api-host` defaults to `None` (resolved to
`127.0.0.1` in `_run_daemon`); `--api-port` defaults to `None` (resolved to
`8765`).

### Dispatch order

Order of the gates in `main()` (`main.py:1307-1528`):

| Step | Gate | Action |
|------|------|--------|
| 1 | `parse_args` | Parse argv; set `ui.plain` from `--plain` / `--quiet` / `--json` |
| 2 | `bootstrap_startup_api_keys` | Load keys; interactive prompt only when `--menu` |
| 3 | `--setup-api-keys` alone | Save keys and exit `0` (`setup_only`) |
| 4 | ChatGPT runtime | `_ensure_chatgpt_runtime`; skipped for `--doctor` / `--self-test` / `--eval` / `--benchmark` / `--skills-list` / `--list-plugins` |
| 5 | `--daemon` / `--web` | Conflict check first (exit `2`), else `_run_daemon` |
| 6 | `--doctor` | `tools.doctor.run_doctor` and exit |
| 7 | `--self-test` | `tools.self_test.run_self_test` and exit |
| 8 | `--eval-list` | Print `eval_targets/*.oracle.json` ids and exit `0` |
| 9 | `--save-baseline` / `--check-regression` without `--eval` or `--benchmark` | Error and exit `2` |
| 10 | `--benchmark` / `--benchmark-list` | `tools.benchmark_cli.run_benchmark_cli` and exit |
| 11 | `--eval` with `--target` | Legacy single-target `tools.eval_harness.run_eval` |
| 12 | `--eval` without `--target` | Graded suite `run_graded_eval` over all (bare) or listed ids; optional `save_baseline` / `check_regression`; exit `0`, or `1` on regression |
| 13 | `--ctf` | `tools.ctf_mode.run_ctf` and exit |
| 14 | `--demo` | `tools.demo_mode.run_demo` and exit |
| 15 | `--skills-list` | `print_skills_catalog` and exit |
| 16 | `--list-plugins` | `list_discovered_plugins` and exit |
| 17 | `--menu` | `tools.interactive_menu.run_interactive_menu` and exit |
| 18 | No args and no `--target` | Default to WebUI daemon (`args.web = True`, `_run_daemon`) |
| 19 | Otherwise | `async_main(args)` (terminal run path) |

The graded `--eval` path (step 12) runs without `--target` and does not exit
`2`; exit `2` from `tools.eval_harness.run_eval` (`tools/eval_harness.py:382-387`)
belongs to the legacy single-target path, which `main()` only reaches when
`--target` is present.

```bash
python main.py --eval                       # graded suite, all oracle targets
python main.py --eval dvwa juice_shop --save-baseline
python main.py --eval --check-regression    # exit 1 on regression
python main.py --eval --target 10.0.0.50    # legacy single-target harness
```

### Exit codes

| Code | Meaning | Source |
|------|---------|--------|
| 0 | Success; `--setup-api-keys` only; `--eval-list`; daemon already running; graded eval pass | `main.main`, `main._run_daemon` |
| 1 | Run failure; missing `uvicorn`; `create_app` import failure; WebUI build failure; `check_regression` failure; `async_main` errors | `main.main`, `main._run_daemon`, `main.async_main` |
| 2 | Daemon combined with target/goal/menu/doctor/demo/eval/self-test/skills/plugins/setup flags; non-loopback `--api-host`; `--save-baseline` / `--check-regression` without `--eval` or `--benchmark` | `main.main`, `main._run_daemon` |
| 130 | `KeyboardInterrupt` | `main.main`, `main._run_daemon` |

`_run_daemon` (`main.py:955-1057`) refuses any `--api-host` outside
`127.0.0.1` / `localhost` / `::1` with exit `2`, builds `webui/dist/` for
`--web` via `_ensure_webui_build`, and serves `create_app` from `app.py`
with `uvicorn`.

### Console script

`pyproject.toml:65-66` registers the installed command:

```python
[project.scripts]
breachpilot = "main:main"
```

`breachpilot` takes the same flags as `python main.py`. `python main.py`
with no arguments starts the WebUI daemon (`--web`); `python main.py
--menu` forces the terminal menu.

## Flow B — `legacy/cli.py`

Parser is `legacy/cli.py:build_parser` (`legacy/cli.py:530-598`). Every
subcommand except `init-mission` accepts `--mission-id` after the subcommand
(resume/reattach a named mission instead of the latest `active` one). Mission
loading is `_load_mission` / `_require_mission`; the workspace root is
`_workspace_root` (`RESEARCH_WORKSPACE`, default `research_workspace`) with
the database at `research.db`.

### Mission subcommands

| Command | Flags / positionals | Function | Parser lines |
|---------|---------------------|----------|--------------|
| `init-mission` | `--config <path>` (required) | `cmd_init_mission` | `legacy/cli.py:547-549` |
| `add-scope` | `--allow`, `--deny`, `--notes` | `cmd_add_scope` | `legacy/cli.py:551-556` |
| `list-scope` | `--mission-id` | `cmd_list_scope` | `legacy/cli.py:558-560` |
| `next-task` | `--mission-id` | `cmd_next_task` | `legacy/cli.py:562-564` |
| `list-tasks` | `--mission-id` | `cmd_list_tasks` | `legacy/cli.py:566-568` |
| `run-task` | `[task_id]` (empty = next pending), `--mission-id` | `cmd_run_task` | `legacy/cli.py:570-573` |
| `summarize-target` | `--target`, `--mission-id` | `cmd_summarize_target` | `legacy/cli.py:575-578` |
| `list-findings` | `--mission-id` | `cmd_list_findings` | `legacy/cli.py:580-582` |
| `validate-finding` | `finding_id`, `--mission-id` | `cmd_validate_finding` | `legacy/cli.py:584-587` |
| `generate-report` | `finding_id`, `--mission-id` | `cmd_generate_report` | `legacy/cli.py:589-592` |
| `status` | `--mission-id` | `cmd_status` | `legacy/cli.py:594-596` |

```bash
python legacy/cli.py init-mission --config mission.yaml
python legacy/cli.py add-scope --allow "*.example.com" --notes "main scope"
python legacy/cli.py next-task --mission-id M-001
python legacy/cli.py run-task T-00001
python legacy/cli.py status
```

`run-task` gates through `ScopeGate.check_scope`, then `RiskController`,
and marks `needs_approval` without executing when either side requires human
approval (`legacy/cli.py:298-352`). Exit codes: `0` success, `1` error
(including scope/risk blocks), `130` on Ctrl-C, and `1` with help text when
no subcommand is given (`legacy/cli.py:604-622`).

## Flow B compatibility shims

Root files are one-release proxies that warn and re-export `legacy.*`
(see `legacy/README.md`). Each follows this shape:

```python
import importlib
import sys
import warnings

warnings.warn("cli is legacy; use legacy.cli", DeprecationWarning, stacklevel=2)
_mod = importlib.import_module("legacy.cli")
sys.modules[__name__] = _mod
```

| Root shim | Canonical module | Warning |
|-----------|------------------|---------|
| `cli.py` | `legacy.cli` | `cli is legacy; use legacy.cli` |
| `agent_loop.py` | `legacy.agent_loop` | `agent_loop is legacy; use legacy.agent_loop` |
| `planner.py` | `legacy.planner` | `planner is legacy; use legacy.planner` |
| `executor.py` | `legacy.executor` | `executor is legacy; use legacy.executor` |
| `observer.py` | `legacy.observer` | `observer is legacy; use legacy.observer` |
| `memory.py` | `legacy.memory` | `memory is legacy; use legacy.memory` |
| `mission.py` | `legacy.mission` | `mission is legacy; use legacy.mission` |
| `evidence.py` | `legacy.evidence` | `evidence is legacy; use legacy.evidence` |

New code must import from `legacy.*` (Flow B) or `tools.*` (Flow A), never
from the root shims.

## Mission config — `mission.yaml` vs `--config`

`mission.yaml` is the example Flow B mission file consumed by
`legacy/cli.py init-mission --config mission.yaml`. `main.py --config`
is a different flag: it points at `config.yaml` (provider, model, MCP, and
run settings), not at `mission.yaml`.

```yaml
program_name: "Example Authorized Program"
objective: "Find valid, in-scope, non-destructive, reproducible vulnerabilities with evidence."
risk_profile: "high_authorized_testing"
allowed_assets:
  - "example.com"
  - "*.example.com"
disallowed_assets:
  - "payments.example.com"
forbidden_actions:
  - "denial_of_service"
rate_limits:
  default_requests_per_second: 2
  max_concurrent_requests: 3
testing_modes:
  - "recon"
  - "analysis"
accounts: []
notes: |
  Operator rules and program context.
```

| `mission.yaml` key | Purpose |
|--------------------|---------|
| `program_name` | Mission / program label stored on the mission row |
| `objective` | Engagement objective (defaults to `DEFAULT_OBJECTIVE` in `legacy/mission.py`) |
| `risk_profile` | One of `low_noise_non_destructive`, `standard_authorized`, `high_authorized_testing`; selects testing modes, command/task budgets, and exploit/pivot allowance |
| `allowed_assets` | In-scope domains, IPs, CIDRs, `*.wildcards` |
| `disallowed_assets` | Explicit exclusions, including `disallowed_assets` that overlap the allow list |
| `forbidden_actions` | Augments the profile `forbidden_by_default` set (union, never replaces) |
| `rate_limits` | Per-target rate limits (`default_requests_per_second`, `max_concurrent_requests`, `search_rate_limit_per_minute`) |
| `testing_modes` | Permitted phases (`recon`, `analysis`, `test`, `validate`, `exploit`, `report`); defaults from the risk profile when empty |
| `accounts` | Optional test credentials for authenticated testing |
| `notes` | Free-text program rules and context |

| Flag | Default / required | Points at |
|------|--------------------|-----------|
| `main.py --config` (`targeting` group) | Defaults to `config.yaml` | Flow A run config (models, MCP, exploit, API); loaded by `load_config` |
| `legacy/cli.py init-mission --config` | Required | Flow B mission YAML (`mission.yaml` shape); loaded by `cmd_init_mission` via `yaml.safe_load` |

Implementation note: `legacy/mission.py` also accepts `id`, `target_assets`,
and `notes` keys in `_MISSION_KEYS`; `max_commands_per_session` and
`max_tasks_active` are derived from the risk profile, not set directly in
`mission.yaml`.

## Related documentation

- [CLI Reference](./cli-reference.md)
- [Getting Started](./getting-started.md)
- [Architecture](./architecture.md)
- [Runtime Flows](./runtime-flows.md)
- [Configuration Reference](./config-reference.md)
- [Legacy Flow B](../legacy/README.md)

## Source map

- `main.py`
- `legacy/cli.py`
- `cli.py`
- `agent_loop.py`
- `planner.py`
- `executor.py`
- `observer.py`
- `memory.py`
- `mission.py`
- `evidence.py`
- `mission.yaml`
- `legacy/mission.py`
- `legacy/README.md`
- `pyproject.toml`
- `tools/eval_harness.py`
- `docs/cli-reference.md`
