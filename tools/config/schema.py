"""Configuration validator and manager for config.yaml.

Provides:
- Validation of required keys and types
- Sensible defaults for missing values
- Warning about unknown keys
- Save updated config back to disk
"""
# BreachPilot by @braydos-h — https://github.com/braydos-h/BreachPilot

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)

# ── Expected schema with defaults ──────────────────────────────────────────

CONFIG_SCHEMA: dict[str, Any] = {
    "ollama": {
        # ponytail: cloud-only by default. Chat/generate go to Ollama Cloud
        # (https://api.ollama.com); the ollama Python client auto-attaches
        # ``Authorization: Bearer $OLLAMA_API_KEY``. Override ``host`` to use
        # a local daemon. ``embed_host`` keeps embeddings on local Ollama
        # (nomic-embed-text is small + cheap to self-host) and falls back to
        # ``host`` when absent — see config.yaml for the full rationale.
        "host": "https://api.ollama.com",
        "model": "glm-5.2:cloud",
        "api_key_env": "OLLAMA_API_KEY",
        "embed_host": "http://localhost:11434",
    },
    "models": {
        # ponytail: chat/generate provider selector. ``ollama`` (default) is
        # the unchanged per-alias registry path. ``chatgpt`` routes through
        # the local openai-oauth proxy (see the ``chatgpt`` block below).
        # Absent key = ``ollama`` so first-run behavior is unchanged.
        "provider": "ollama",
        "registry": {
            "kimi": "kimi-k2.6:cloud",
            "deepseek": "deepseek-v4-pro:cloud",
            "deepseek_flash": "deepseek-v4-flash:cloud",
            "glm": "glm-5.2:cloud",
            "minimax": "minimax-m3:cloud",
        },
        "default_alias": "glm",
        # Auto-update the registry against the live Ollama API (GET /api/tags):
        # on daemon boot (main._run_daemon) each alias is bumped to the newest
        # same-family version the host lists (e.g. glm-5.2:cloud ->
        # glm-5.3:cloud). No pulls are issued — for Ollama Cloud a pull only
        # registers a pointer (see tools/doctor.py), and the registry stores
        # ids, so rewriting the id IS the update. models.info labels/context
        # windows are operator-managed and deliberately not auto-edited. Also
        # on demand via POST /api/v1/models/refresh (tools/ollama_models.py).
        "auto_update": True,
        # Per-model metadata. The ``context_window`` value is the SOURCE OF
        # TRUTH for the adaptive context compactor in ``tools.exploit_agent``
        # -- keep in sync with config.yaml's ``models.info`` block. Mirrored
        # here so a missing config.yaml still yields the correct window per
        # alias (GLM-5.2 default = 976K); exploit_agent.py has no in-code
        # ``glm`` profile, so without this it would fall back to 128K.
        # Model-role routing. Each role maps to a model alias; an empty
        # string means "use models.default_alias" (so first-run behavior is
        # unchanged). Consumed by tools/model_router.py::get_client_for_role.
        "roles": {
            "planner": "",
            "executor": "",
            "interpreter": "",
            "code_generator": "",
            "critic": "",
            "summarizer": "",
        },
        "info": {
            "kimi": {
                "label": "Kimi K2.6",
                "context_window": 256000,
                "description": "Moonshot Kimi K2.6 — strong long-form reasoning, 256K context.",
            },
            "deepseek": {
                "label": "DeepSeek V4 Pro",
                "context_window": 1000000,
                "description": "DeepSeek V4 Pro — 1M token context, deep code reasoning.",
            },
            "deepseek_flash": {
                "label": "DeepSeek V4 Flash",
                "context_window": 1000000,
                "description": "DeepSeek V4 Flash - 1M token context, fast DeepSeek option for lower-latency work.",
            },
            "glm": {
                "label": "GLM-5.2",
                "context_window": 976000,
                "description": "Zhipu GLM-5.2 — 976K context, the smartest/newest GLM for deep reasoning + coding.",
            },
            "minimax": {
                "label": "Minimax M3",
                "context_window": 512000,
                "description": "Minimax M3 (cloud) — 512K context, balanced coding + reasoning.",
            },
        },
    },
    # ChatGPT provider (openai-oauth). Opt-in: ``enabled: false`` by default so
    # first-run behavior is unchanged. When ``models.provider: chatgpt`` the
    # chat/generate path routes through the local openai-oauth proxy at
    # ``base_url`` (loopback-only by default). OAuth credentials stay in
    # openai-oauth's ``~/.codex/auth.json`` — they are NEVER copied into this
    # config or read by BreachPilot (only their existence is checked). See
    # tools/providers/chatgpt_provider.py and docs/providers.md.
    "chatgpt": {
        "enabled": False,
        "host": "127.0.0.1",
        "port": 10531,
        "base_url": "http://127.0.0.1:10531/v1",
        "auto_start": True,
        "local_repo": "./oauth",
        "runtime": "auto",
        "request_timeout_seconds": 300,
        "default_model": "gpt-5.2",
        "models": [],
        "context_window": 128000,
        "login_timeout_seconds": 300,
        "start_timeout_seconds": 30,
        "discover_cache_seconds": 300,
        "oauth_file": "",
    },
    # OpenCode Go provider (Responses API). Opt-in: ``enabled: false`` by
    # default so first-run behavior is unchanged. When ``models.provider:
    # opencode_go`` the chat/generate path routes through the hosted
    # ``https://opencode.ai/zen/go/v1/responses`` endpoint (OpenAI Responses
    # API). The API key is read from ``OPENCODE_GO_API_KEY`` (or the env var
    # named by ``api_key_env``) and never copied into config or logs. See
    # tools/providers/opencode_go_provider.py and docs/providers.md.
    "opencode_go": {
        "enabled": False,
        "base_url": "https://opencode.ai/zen/go/v1",
        "api_key_env": "OPENCODE_GO_API_KEY",
        "request_timeout_seconds": 300,
        "default_model": "muse-spark-1.2-contributor",
        "models": [],
        "context_window": 128000,
        "discover_cache_seconds": 300,
    },
    "mcp": {
        "default_transport": "stdio",
        "http_host": "127.0.0.1",
        "http_port": 8001,
    },
    # Provider architecture (docs/provider-development.md). Per-provider
    # config blocks under ``providers.<id>`` are the modern layout; legacy
    # top-level blocks (``ollama`` / ``chatgpt`` / ``opencode_go``) remain
    # supported and are normalized in ONE place,
    # ``tools.config.loader.get_provider_config``. Default: empty — every
    # built-in provider keeps reading its legacy block, byte-compatible.
    "providers": {},
    # Embedding provider selection (semantic memory / skills embeddings).
    # ``ollama`` (default) = legacy behavior (local Ollama embeddings at
    # ``ollama.embed_host``). ``none`` disables embeddings entirely —
    # semantic memory falls back to keyword storage and NO request (not
    # even a health probe) is made to any Ollama endpoint.
    "embeddings": {
        "provider": "ollama",
        "host": "",
        "model": "",
        "api_key_env": "OLLAMA_API_KEY",
        "timeout_seconds": 30,
    },
    # Engine advisory MCP server (``mcp_engine_server.py``): read-only skill
    # search / CVE lookup / run history for foreign AI assistants. Defaults
    # for the CLI entrypoint; HTTP transport is loopback-only via
    # ``tools.mcp_shared``.
    # ponytail: engine_mcp is CLI-driven (mcp_engine_server.py --port); schema kept for compat, not consumed via load_config
    "engine_mcp": {
        "enabled": True,
        "host": "127.0.0.1",
        "port": 8002,
    },
    # Linux-friendly nmap invocation. ``path`` overrides the binary when nmap
    # is not on PATH; ``sudo`` runs nmap via `sudo -n` so root-only scans
    # (-O OS detection, -sS SYN) work from a non-root shell; ``priv_fallback``
    # auto-downgrades those root-requiring flags instead of failing when the
    # host is unprivileged and sudo is off. No-op on Windows (no root concept).
    "nmap": {
        "path": "nmap",
        "sudo": False,
        "priv_fallback": True,
    },
    "exploit": {
        "enabled": True,
        "mode": "standalone",
        # LAB BUILD: defaults grant live exploitation. Full access auto-
        # approves every action; the only remaining gate is the target-IP lock
        # (require_explicit_allowlist unions the runtime --target via
        # EXPLOIT_TARGET env). Set permission to read_only for propose-only
        # recon. See CLAUDE.md "Permission Model". Only run against lab systems
        # you own.
        "permission": "full_access",
        "attack_mode": True,
        "terminal": "visible",
        "command_timeout_seconds": 300,
        "max_commands_per_session": 9999,
        "max_rounds": 200,
        "attack_max_commands": 150,
        "attack_max_rounds": 50,
        "attack_max_duration_minutes": 360,
        "context_summarize_every": 10,
        "auto_post_exploit": True,
        "max_pivot_depth": 2,
        "workspace_dir": "exploit_workspace",
        "loot_workspace": "exploit_workspace/loot",
        "attacker_os": "auto",
        "searchsploit_path": "searchsploit",
        # Linux: the shell used by `run_exploit_terminal` (default bash). No
        # effect on Windows (cmd.exe is used). ``msfconsole_path`` overrides
        # the Metasploit console binary when it's not on PATH.
        "shell": "bash",
        "msfconsole_path": "msfconsole",
        "web_search": True,
        "max_query_chars": 200,
        "cache_ttl_seconds": 3600,
        "cache_max_entries": 50,
        # Target-IP lock. Interactive Start New Session saves entered IPs in
        # allowed_targets; the runtime --target is also injected via
        # EXPLOIT_TARGET (see mcp_session.py) and unioned at check time
        # (mcp_shared._check_allowlist). Add hosts here to authorize them in
        # addition to the runtime target.
        "require_explicit_allowlist": True,
        "allowed_targets": [],
        "disallowed_assets": [],
        "forbidden_actions": [],
        # Active Directory / Kerberos post-exploit suite (Phase 1). Opt-in:
        # the master ``enabled`` plus a per-tool flag must BOTH be true, or the
        # tool short-circuits with ``BLOCKED: ... disabled`` before the allowlist.
        # ``smb_signing_check`` is detection-only and defaults ON. Every tool is
        # target-IP-locked (@require_allowlist + check_targets_allowlist for DC).
        "ad_kerberos": {
            "enabled": False,
            "asrep_roast": False,
            "pass_the_hash": False,
            "adcs_enum": False,
            "bloodhound": False,
            "responder_relay": False,
            "golden_ticket": False,
            "smb_signing_check": True,
        },
        # Phase 3: MSF recipe dispatch + handler orchestration. Opt-in: when
        # ``recipes_enabled`` is false the ``msf_run_recipe`` MCP tool returns
        # BLOCKED before any dispatch. ``auto_local_exploit_suggester`` adds an
        # advisory LocalExploitSuggester task to the orchestrator privesc phase
        # (only surfaces the suggestion; Path B has no MSF session id, so it
        # never fabricates one).
        "msf": {
            "recipes_enabled": False,
            "auto_local_exploit_suggester": False,
        },
        # Phase 3: extended C2 listener types for ``start_listener``. Each is
        # opt-in (default OFF); the legacy netcat/socat/http types stay ungated.
        # ``socks_pivot`` upstream is allowlist-gated at the tool layer (pivot
        # lock).
        "listeners": {
            "tls": False,
            "dns": False,
            "https_beacon": False,
            "socks_pivot": False,
        },
    },
    # ponytail: stealth is inert/UI-only legacy; canonical is opsec (tools/opsec.py). Kept for compat.
    "stealth": {
        "rotate_ua": False,
        "dns_over_https": False,
        "doh_provider": "cloudflare",
    },
    "cve_lookup": {
        "enabled": True,
        "max_results": 5,
        "rate_limit_seconds": 6.0,
        "timeout_seconds": 30,
        "cache_ttl_seconds": 3600,
        "cache_max_entries": 100,
        "api_key_env": "NVD_API_KEY",
        # Tier 1.2: NVD circuit-breaker tuning (see CVESearchSettings).
        "circuit_failure_threshold": 5,
        "circuit_recovery_timeout": 60.0,
        # Tier 1.8: process-wide shared NVD rate budget (per minute); 0 disables.
        "search_rate_limit_per_minute": 10,
        # Phase 2: EPSS + KEV vuln-intel enrichment (lab build: ON by default
        # so enrichment is live out-of-the-box). EPSS adds exploit-likelihood
        # scoring; KEV flags CISA-known-exploited CVEs. Set false to disable.
        "epss_enabled": True,
        "kev_enabled": True,
        "kev_cache_ttl_seconds": 86400,
        "kev_cache_path": "",
        # Gap 6: GitHub Search API token for cve_to_poc (CVE->verified-PoC URL
        # resolution). OPTIONAL -- absent = unauthenticated 60/hr rate limit;
        # cve_to_poc still works (falls through to searchsploit/NVD on rate-limit).
        # Mirrored into env at boot via api_key_store alongside NVD_API_KEY.
        "github": {
            "token_env": "GITHUB_TOKEN",
        },
    },
    # Threat-intel feed (OSV.dev + GitHub Security Advisories + CISA KEV).
    # Advisory-only, never touches the target. Lab build: ON by default so the
    # feed is live out-of-the-box. Reuses cve_lookup's KEV catalog (shared
    # disk cache). GHSA needs GITHUB_TOKEN (shared with
    # cve_lookup.github.token_env); when absent, ghsa is silently dropped and
    # osv+kev still answer.
    "threat_intel": {
        "enabled": True,
        "cache_dir": "exploit_workspace/.threat_intel",
        "cache_ttl_seconds": 86400,
        "sources": {
            "osv": True,
            "ghsa": True,
            "kev": True,
            "exploitdb_rss": False,
        },
        "max_results": 20,
        "github_token_env": "GITHUB_TOKEN",
        "timeout_seconds": 30,
    },
    "research": {
        "enabled": True,
        "provider": "ollama",
        "fallback_provider": "serpapi",
        "timeout_seconds": 15,
        "max_results": 8,
        "max_fetch_depth": 5,
        "max_content_chars": 12000,
        "cache_ttl_seconds": 1800,
        "cache_max_entries": 250,
        "min_source_quality": "medium",
        "require_api_key_for_mcp_tools": True,
        "allow_local_fetch": False,
        "ollama": {
            "api_key_env": "OLLAMA_API_KEY",
            "max_results": 8,
            "use_web_search": True,
            "use_web_fetch": True,
        },
        "serpapi": {
            "api_key_env": "SERPAPI_API_KEY",
            "endpoint": "https://serpapi.com/search.json",
            "engine": "duckduckgo",
            "region": "us-en",
        },
        "assistant": {
            "enabled": True,
            "model_alias": "",
            "automatic": True,
            "failure_trigger": 2,
            "max_auto_consultations": 4,
            "max_tool_calls_per_consultation": 5,
            "max_model_rounds": 3,
            "max_advisory_chars": 4000,
            "timeout_seconds": 90,
            "save_advisories": True,
        },
    },
    "swarm": {
        "enabled": True,
        "agents": ["recon", "vuln", "exploit", "post_exploit", "critic", "reflection"],
        "max_parallel_agents": 3,
        # Phase 3/4: parallel sub-agents. ``parallel_enabled`` gates BOTH
        # route_parallel (the swarm's batched same-phase dispatch) AND the
        # spawn_subagent MCP tool (the main AI's delegation surface). Off by
        # default per the recon-first rollout — opt in via config or
        # ``--parallel-swarm``. ``per_phase_concurrency`` is the semaphore
        # size for route_parallel (3 = up to 3 concurrent same-phase agents).
        # ``exploit_parallel`` defaults False (exploit/post_exploit stay
        # sequential in route_parallel unless flipped); flip to True once
        # you've validated parallel recon is stable on your targets.
        "parallel_enabled": False,
        "per_phase_concurrency": 3,
        "exploit_parallel": False,
        # Phase 4: the spawn_subagent/await_subagent/list_subagents MCP tools
        # are gated on ``parallel_enabled`` (above) at registration time.
        # ``subagent_timeout_seconds`` is the ceiling for await_subagent so
        # a stuck sub-agent can't wedge the main AI's loop.
        "subagent_timeout_seconds": 600,
        # Bounded critic↔exploit negotiation rounds. 0 (default) = legacy
        # one-shot: the critic's ``modify`` is applied once and the task runs.
        # N>0 = after a ``modify``, the modified task is re-reviewed by the
        # critic up to N times until ``approve``/``deny``, a scope-expanding
        # modification is proposed (rejected), or the same modification
        # repeats (deadlock break). The negotiation is about HOW to execute a
        # planned action (risk level, tool swap, mutation, rate limiting),
        # never WHAT target/scope to hit — the allowlist lock is untouched.
        "negotiation_rounds": 0,
    },
    # Witness agent — advisory real-time audit-stream watcher (agent-on-agent
    # safety). Library default is OFF (conservative for downstream re-use);
    # the checked-in config.yaml flips it ON for the lab runtime. Wiring: when
    # ``enabled`` is true, the transport-neutral run lifecycle
    # (tools/run_service/execute.py) spawns a WitnessAgent side task per run
    # that polls the run's audit trails (reports/<run_id>/activity.jsonl plus
    # the per-attempt exploit_audit.jsonl once the session exposes its path)
    # and flags anomalies (allowlist breach, PoC escape, permission escalation,
    # prompt-injection pattern, DoS drift) to ``log_path`` (process-global —
    # the API GET /runs/{id}/witness route reads it verbatim) +, when
    # ``escalate_to_event_broker`` is true, 'witness_flag' events through the
    # transport's event sink. It is advisory ONLY: it flags, it never blocks /
    # modifies / kills a run, and its failure never propagates into the run.
    # See tools/swarm/agents/witness_agent.py.
    "witness": {
        "enabled": False,
        "log_path": "reports/witness.jsonl",
        "poll_interval_seconds": 5,
        "escalate_to_event_broker": True,
        "max_flags_per_signal_per_minute": 10,
        "dos_failure_window_seconds": 60.0,
        "dos_failure_threshold": 8,
    },
    # Autonomous orchestrator Phase 2 capabilities (opt-in). All keys default
    # OFF / 0 so default behavior is unchanged -- the new attack-path
    # capabilities must be explicitly enabled per the CLAUDE.md opt-in rule.
    "autonomous": {
        "persistence_phase": False,  # Phase 2.2: run PERSISTENCE phase after access achieved
        "checkpoint_every": 0,  # Phase 2.3: save attack_states.json every N completed targets (0 = off)
        "adaptive_replan": False,  # Phase 2.4: per-target multi-round replan + vuln-chaining
        "max_cycles": 100,  # round cap when adaptive_replan is on
        "max_pivot_depth": 0,  # already consumed by the orchestrator (single-IP lock default)
    },
    # FSM / planner-executor split (tools/attack_planner.py). Opt-in
    # (default OFF): when enabled, campaign code may route plan execution
    # through the FSM phase guard + memoryless step executor instead of the
    # LLM-does-everything loop. First-run behavior is unchanged.
    "fsm": {
        "enabled": False,
        "max_retries_per_step": 3,
    },
    # D1: cross-mission semantic-memory consumer for the autonomous
    # orchestrator. When true, the orchestrator builds a
    # SemanticMemoryManager and calls store_lesson on confirmed module wins.
    # Advisory-only (read-only memory store consumer, no execution authority
    # change). Lab default ON — matches ``memory.semantic_enabled: true``;
    # the orchestrator is the missing campaign-level consumer of an
    # already-on capability, not a new attack-path opt-in.
    "orchestrator": {
        "semantic_memory": True,
    },
    # Recon coverage & depth (Phase 3). These gate the additive enumerators
    # (TLS/SSL cert parse, SMTP/DB banner parse, web spider, passive OSINT +
    # IPv6 AAAA lookup) and the UDP top-ports scan added in Phase 3. The TCP
    # ``scan_host`` path is unchanged regardless of these settings. IPv6 stays
    # PASSIVE-ONLY (AAAA lookup) -- the target-IP allowlist lock is untouched.
    "recon": {
        "extended_enumerators": True,  # enable TLS/SMTP/DB/spider/OSINT additive enumerators
        "udp_top_ports": 100,  # nmap -sU --top-ports N for run_udp_recon / recon_udp
        # Optional Shodan API key for passive OSINT. Empty = Shodan disabled
        # (run_osint returns {"enabled": False, ...}). Falls back to the
        # SHODAN_API_KEY env var at ReconConfig.from_config time.
        "shodan_api_key": "",
        # Extended depth enumerators (Phase 2). Each is independently gated and
        # default OFF; when False the coroutine never runs (no network, no
        # regressions to the legacy nine enumerators). All network I/O is
        # injectable for tests.
        "subdomain_enum": False,
        "vhost_discovery": False,
        "waf_fingerprint": False,
        "asn_whois": False,
        "cloud_metadata_probe": False,
        "snmp_enum": False,
        "dns_zone_transfer": False,
    },
    # OPSEC / detection-evasion (Phase 6.2). This is the agent's OWN operational
    # hardening (pacing/jitter/UA-rotation/DNS-over-HTTPS/quiet-commands) so an
    # authorized assessment can simulate a low-noise adversary, plus detection-
    # coverage testing (canary probes + read-only footprint summary). It is NOT
    # active evasion of the target's defenses: no log-clearing, timestomping, or
    # EDR/SIEM defeat; the append-only tamper-evident audit chain is untouched.
    # Defaults OFF per the CLAUDE.md opt-in rule -- first-run behavior is
    # unchanged. When enabled, AggressionLevel.STEALTH becomes load-bearing
    # (max jitter + min-gap + UA rotation + quiet-command denylist).
    "opsec": {
        "enabled": False,
        "ua_rotation": False,  # rotate User-Agent across HTTP egress
        "doh": False,  # resolve via DNS-over-HTTPS (cloudflare/google)
        "doh_provider": "cloudflare",  # "cloudflare" | "google"
        "min_gap_seconds": 0.0,  # base pacing gap between actions
        "jitter_seconds": 0.0,  # +/- random jitter on the gap
        "rate_per_minute": 0,  # 0 = no token-bucket cap
        "quiet_command_patterns": [],  # substrings to refuse when enabled (e.g. ["masscan", "nuclei"])
        "noise_budget": 0,  # max noisy commands allowed (0 = unlimited)
        # Target-aware OPSEC: when the target IP is private/local (RFC1918,
        # loopback, link-local, reserved, ULA, or any local_cidrs entry) the
        # effective profile is forced OFF -- the operator owns the box and the
        # AI moves freely with no pacing/UA-rotation/quiet-blocking. A public-
        # routable target keeps the configured posture (OPSEC ON) and the AI
        # retains full attack autonomy (public_autonomy). Default true so the
        # local-off/public-on behavior is the out-of-the-box rule.
        "local_targets_off": True,
        "local_cidrs": [],  # extra CIDRs/IPs treated as local (e.g. ["10.99.0.0/16"])
        "public_autonomy": True,  # for public targets the AI chooses its own attacks (documentary)
    },
    # Eval/benchmark harness config. The --eval CLI flag still works when
    # ``enabled`` is false, but this block gates the defaults used by the
    # eval runner (output location, round budget, report formats).
    "eval": {
        "enabled": True,  # eval/benchmark harness enable (the --eval flag still works when false, but the config gates defaults)
        "output_dir": "reports/eval",  # where reports/eval/<run_id>/ trees are written
        "max_rounds": 30,  # attack_max_rounds for an eval run
        "write_markdown": True,  # emit eval_report.md alongside the JSON
        "write_html": True,  # emit eval_report.html alongside the JSON
        "regression_tolerance": 0.05,  # graded eval: a target regresses when score < baseline score minus this
        "baseline_path": "reports/eval/baseline.json",  # graded eval: baseline file written by --save-baseline
    },
    # Benchmark suite (tools/benchmark/, docs/benchmarks.md). Providers (XBEN
    # is one) -> scenario definitions -> sandboxed agent execution ->
    # independent oracle verification -> metrics -> reports/benchmarks/ +
    # WebUI. Verified success ALWAYS comes from the independent verifier; the
    # agent's claimed success is stored separately for false-positive rates.
    "benchmark": {
        "enabled": True,  # benchmark CLI/API enable
        "output_dir": "reports/benchmarks",  # reports/benchmarks/<suite>/<run_id>/ trees
        "trials": 3,  # default repeated trials per scenario (1 = single-shot; repeated trials give confidence intervals)
        "timeout_seconds": 1800,  # per-trial mission timeout
        "sandbox_required": True,  # when true, runs without sandbox.enabled are INFRASTRUCTURE_ERROR (no host-execution fallback)
        "baseline_path": "reports/benchmarks/baseline.json",  # --save-baseline / --check-regression target
        "regression": {
            "enabled": True,  # regression checks available (CLI exit code honors hard findings)
            "success_rate_tolerance": 0.02,  # verified-success-rate drop beyond this is a HARD regression
            "false_positive_tolerance": 0.01,  # false-positive-rate rise beyond this is a HARD regression
            "median_time_tolerance": 0.20,  # relative median-solve-time rise beyond this is a warning
            "tool_actions_tolerance": 0.30,  # relative median-action rise beyond this is a warning
            "cost_tolerance": 0.30,  # relative estimated-cost rise beyond this is a warning
        },
        "telemetry": {
            "events": True,  # structured mission events (events.jsonl)
            "token_usage": True,  # per-trial token/model-call accounting
            "cost": True,  # estimated cost when computable (else recorded as unknown)
        },
    },
    # Kill-chain state machine (opt-in, default off). When enabled, the exploit
    # MCP server registers the killchain_* tools and the autonomous
    # orchestrator prefers verified kill-chain edges over free-form module
    # planning. Transitions commit ONLY after independent verification —
    # require_verification toggles reporting verbosity, never enforcement
    # (there is no unverified-transition code path).
    "killchain": {
        "enabled": False,
        "goal_state": "shell_as_root",  # BFS goal for killchain_plan / the orchestrator edge path
        "require_verification": True,  # reporting verbosity only — verification is always enforced
        "graph_db": "",  # kill-chain graph store path; "" = <workspace>/killchain_graph.db
    },
    # Browser-native web agent (Playwright backend, default OFF).
    # ``enabled: false`` + ``backend: "none"`` = zero behavior change: no
    # browser code runs and every browser.* capability reports unavailable
    # (tools/browser/capabilities.py). Enable with ``enabled: true`` +
    # ``backend: playwright`` (requires the optional ``browser`` extra for
    # host-side dev, or the sandbox browser worker for contained runs — see
    # docs/browser-agent-design.md). ``allow_mutating_actions`` gates
    # browser_execute_js + the Phase-2 replay/submit surface (default OFF:
    # read-only browsing only). Bounds keep huge pages out of model prompts.
    "browser": {
        "enabled": False,
        "backend": "none",  # none | playwright (requires a BACKEND_REGISTRY entry — declared ≠ available)
        "headless": True,
        "max_sessions": 2,
        "session_timeout_seconds": 300,
        "navigation_timeout_seconds": 30,
        "capture_screenshots": True,
        "capture_network": True,
        "capture_console": False,
        "persist_storage": False,  # storage harvest goes to the credential store, never plaintext logs
        "allow_mutating_actions": False,  # browser_execute_js + replay/submit (Phase 2); default read-only
        "console_max_events": 200,
        "network_max_events": 500,
        "body_sample_max_bytes": 4096,
        "dom_summary_max_chars": 8000,
        "artifact_dir": "",  # screenshot/artifact dir; "" = <workspace>/browser/<session>/
        "executable_path": "",  # explicit Chromium binary override; "" = Playwright default
        "worker_image": "",  # sandbox browser-worker image override; "" = breachpilot-sandbox:browser
    },
    # Long-session mode (opt-in). Absent/false = current behavior; the keys here
    # are the defaults applied when --long-session is passed or enabled: true.
    "long_session": {
        "enabled": False,
        "request_timeout_seconds": 600,
        "swarm_session_timeout_minutes": 30,
        "attack_max_rounds": 200,
        "attack_max_commands": 1000,
        "attack_max_duration_minutes": 720,
        "persist_messages": True,
    },
    "reasoning": {
        "chain_of_thought": True,
        "reflection_every_n_actions": 10,
        "critic_enabled": True,
        "observer_mode": "hybrid",
        "ultrathink": False,
        "ultrathink_reflection_interval": 3,
        "llm_reflection": False,
        "peer_consult_on_failure_threshold": 3,
    },
    "memory": {
        "semantic_enabled": True,
        "embedding_model": "nomic-embed-text",
        "cross_mission_learning": True,
        "attack_memory_enabled": True,
        "attack_memory_max_context_chars": 6000,
        # Tier 1.1: ExperienceStore soundness gates (see config.yaml memory).
        "experience_min_samples": 3,
        "experience_time_decay_days": 90,
    },
    "outcome_judgment": {
        # Only materially different checks count. A minimum of two ensures one
        # failed command cannot exhaust a hypothesis.
        "max_inconclusive_attempts": 3,
        "confirmation_threshold": 0.75,
        "refutation_threshold": 0.75,
        "min_evidence_references": 1,
        # Phase 1.2: wire OutcomeJudge into Flow A (exploit engine). Default OFF
        # per the CLAUDE.md opt-in rule -- first-run behavior is unchanged. When
        # true, the exploit loop runs classify_exploit_result + OutcomeJudge.judge
        # to produce an evidence-grounded verdict that overrides the shallow
        # ``exit_code == 0`` success flag.
        "flow_a": False,
        # D3: peer-model outcome judging. Advisory-only: one alias plans, a
        # different alias grades the evidence. Deterministic judge stays the
        # authority. Default OFF.
        "peer_review": False,
    },
    # D1: self-healing PoC verification (Killer Feature #3). When enabled,
    # ``cve_to_exploit_synth`` syntax-checks its synthesized PoC inline
    # (``py_compile``, no exec) and the ``verify_poc`` MCP tool compile-tests
    # the PoC inside a fully-isolated Docker container
    # (``--network=none --read-only --memory=256m``). The PoC is NEVER executed
    # on the operator box. Default OFF.
    "poc_verification": {
        "enabled": False,
        "docker_image": "python:3.11-slim",
        "compile_timeout_seconds": 30,
        "max_retries": 3,
        "docker_network": "none",
        "docker_read_only": True,
        "docker_memory": "256m",
    },
    # D2: replay simulator. When enabled, registers the ``replay_simulate``
    # MCP tool -- a local-only ``@audit_tool`` that dry-runs an attack plan
    # against a saved ReconAssessment JSON for pre-commit critique. Zero
    # target touch. Default OFF. ``counterfactual`` (design §snapshots) is
    # NOT a plan-critic flag: it toggles the loop's auto-revert + one-variant
    # re-run behavior after a snapshot-backed tool failure (bounded: ONE
    # variant-B retry per failed action; both outcomes recorded).
    "replay_simulator": {
        "enabled": False,
        "counterfactual": False,
    },
    # Proxy-backed HITL evidence loop (Flow A): agents propose candidate
    # findings (PROPOSED), a human Approves/Rejects them in the WebUI
    # Evidence tab (or hitl_decide / POST /runs/{id}/decide). Default ON —
    # the gate is additive (undecided findings render with their PROPOSED
    # badge; only APPROVED surface via approved_findings). No new DB/infra.
    "hitl": {
        "enabled": True,
    },
    # Snapshot + rollback (design §snapshots). Opt-in (default OFF): when
    # enabled, the snapshot_* MCP tools register and the loop may take an
    # automatic snapshot before destructive tool calls. Provider credentials
    # live in env vars only (PROXMOX_API_TOKEN etc.) — never in config.
    "snapshots": {
        "enabled": False,
        "provider": "docker",
        "auto_before_destructive": True,
        "max_snapshots_per_target": 3,
        "vm_map": {},  # target -> snapshottable vm_id (container name / VM id)
        "providers": {
            "docker": {"compose_file": "eval_targets/docker-compose.yml"},
            "hyperv": {"powershell_command": "powershell"},
            "vmware": {"vmrun_path": "vmrun"},
            "proxmox": {"host": "", "node": ""},
            "libvirt": {"virsh_path": "virsh"},
        },
    },
    "adaptive_exploits": {
        "enabled": True,
        "max_mutations": 5,
        "mutation_strategies": [
            "parameter_tweak",
            "encoding_change",
            "delivery_swap",
            "context_aware",
        ],
    },
    "multi_model": {
        "enabled": False,
        "consult_aliases": ["kimi", "deepseek", "deepseek_flash", "glm", "minimax"],
        "max_consultations": 10,
        "max_question_chars": 4000,
        "max_answer_chars": 8000,
    },
    "skills": {
        "enabled": True,
        "roots": ["skills"],
        "default_enabled": [
            "scanning-network-with-nmap-advanced",
            "conducting-network-penetration-test",
            "executing-red-team-engagement-planning",
            "auditing-mcp-servers-for-tool-poisoning",
            "securing-agentic-ai-tool-invocation",
        ],
        "include_tags": [],
        "exclude_names": [],
        "maybe_enabled": False,
        "allow_model_lookup": True,
        "inject_startup_context": False,
        "max_active_skills": 6,
        "max_chars_per_skill": 2500,
        "max_total_chars": 9000,
        "min_contextual_skills": 3,
        "default_skill_weight": 12,
        "context_skill_weight": 24,
        "reselect_mid_run": True,
        "reselect_max_per_run": 3,
        "reselect_min_interval_actions": 5,
        "reselect_sticky_defaults": True,
        "swarm_inject": True,
        "swarm_phase_hints_only": True,
        "feedback_enabled": True,
        "feedback_skill_weight": 8,
        "feedback_min_observations": 3,
        "semantic_matching": True,
        "semantic_skill_weight": 16,
        "semantic_min_similarity": 0.35,
        "semantic_model": "nomic-embed-text",
        "diversity_penalty": 12,
        "include_metadata": False,
        "allow_reference_listing": True,
    },
    # Plugin/extension ecosystem (opt-in; defaults OFF). Plugins are trusted
    # Python with full operator-box privileges (lab build, same as built-ins).
    # ``enabled`` explicitly loads the named plugins; ``disabled`` hard-blocks
    # them regardless of manifest enablement; ``search_paths`` are the
    # filesystem dirs scanned for plugin.yaml manifests; ``entry_points`` gates
    # importlib entry-point discovery in the ``breachpilot.plugins`` group.
    "plugins": {
        "enabled": [],
        "disabled": [],
        "search_paths": ["plugins"],
        "entry_points": True,
    },
    # Outbound-only Slack/Discord run-status notifications (webhook_notify
    # plugin). The plugin is OFF by default; enable here AND in
    # ``plugins.enabled``. ``url`` is a secret — never logged in plaintext.
    # ``events`` is the event-type filter list (e.g. ["finding","state"]).
    # Lab build: enabled true (no-op without a url — logs once then drops).
    "webhook_notify": {
        "enabled": True,
        "url": "",
        "events": ["finding", "state"],
        "timeout_seconds": 5,
        "max_retries": 3,
        "backoff_seconds": 2.0,
        "max_payload_chars": 8192,
    },
    # MITRE ATT&CK Navigator export (mitre-attack-export). Maps the run's
    # exploit_audit.jsonl → ATT&CK technique IDs → Navigator layer JSON the
    # blue team opens in ATT&CK Navigator. Lab build: enabled true.
    "mitre": {
        "enabled": True,
        "technique_map": "tools/mitre_technique_map.json",
        "navigator_output_dir": "reports/mitre",
        "include_skill_tags": True,
    },
    # Remediation ticket generation (remediation-tickets). Outbound-only
    # Jira/GitHub ticket creation from confirmed findings. The token is read
    # from the named env var — never copied into config or logs. Lab build:
    # enabled true (no-op without provider/base_url/token — logs once).
    "ticketing": {
        "enabled": True,
        "provider": "",
        "base_url": "",
        "token_env": "TICKETING_TOKEN",
        "project_key": "",
        "max_retries": 3,
        "backoff_seconds": 2.0,
    },
    # Local WebUI API daemon (``--daemon`` (legacy alias: ``--demon``)). V1 is loopback-only;
    # there is no public-bind override. The bearer token is generated into
    # ``token_file`` (gitignored) on first boot, or overridden via
    # ``BREACHPILOT_API_TOKEN``. ``allowed_origins`` are extra loopback origins
    # permitted for CORS/WS (in addition to localhost/127.0.0.1); ``null`` and
    # non-loopback origins are always rejected.
    "api": {
        "enabled": True,
        "host": "127.0.0.1",
        "port": 8765,
        "token_file": ".webui_secret_key",
        "allowed_origins": [],
        "event_buffer_size": 256,
        "shutdown_timeout_seconds": 15,
        "serve_webui": False,
        # D3: attack-path DAG API route. Lab build: enabled true.
        "graph_route": True,
    },
    # Capability-upgrade agent block (design §23). Toggles + budgets for the
    # task graph, capability discovery, AI-facing state tools, planner hints,
    # structured decision logging, reflection, and retry/repair budgets.
    # Defaults preserve today's behavior: every toggle that gates a new
    # surface defaults to True so the schema advertises the capability, but
    # the consumers read defensively (config_cli.load_config merges NO
    # defaults, so each consumer does cfg.get("agent", {}).get(key, default)).
    # ``max_actions: 0`` is the legacy-budget sentinel — consumption sites
    # treat 0 as "use the existing exploit budgets" (max_commands_per_session
    # etc.) rather than a hard zero cap.
    "agent": {
        "task_graph_enabled": True,
        "capability_discovery_enabled": True,
        "state_tools_enabled": True,
        "planner_hints_enabled": True,
        "decision_log_enabled": True,
        "reflection_enabled": True,
        "max_retries_per_task": 2,
        "max_actions": 0,
        "generated_code_repair_attempts": 3,
    },
    "caldera": {
        "enabled": False,
        "url": "",
        "api_key_env": "CALDERA_API_KEY",
    },
    "ics": {
        "allow_write": False,
        "destructive_ics": False,
    },
    # Operator-box -> victim persistent RCE channel (new, Phase 7). Advisory
    # defaults: the channel is opt-in only when an implant is actually
    # deployed (establish_persistence). auto_start_listener creates the
    # operator-side beacon listener automatically so the operator does not need
    # a manual start_listener call. default_callback_* are fallbacks when the
    # caller does not pass callback_host/port; they are allowlist-checked at
    # the tool layer (same pivot lock as generate_payload LHOST).
    "operator_connection": {
        "enabled": True,
        "auto_start_listener": True,
        "default_callback_port": 4444,
        "default_listener_type": "netcat",
        "beacon_interval_seconds": 300,
        "health_check_interval_seconds": 60,
        "workspace_dir": "exploit_workspace",
    },
    # Disposable execution sandbox (tools/sandbox/): every attack command runs
    # inside a hardened, per-run Docker worker instead of on the operator host.
    # The worker is cap-dropped (NET_RAW at most, never NET_ADMIN), non-root,
    # no-new-privileges, resource-bounded, and gets a default-DROP netns
    # firewall authorizing ONLY the effective target allowlist. ANY sandbox
    # failure DURING a session blocks offensive execution (fail closed -- host
    # execution is never a per-command fallback). The one sanctioned fallback
    # is the boot-time decision: when the Docker probe fails at server boot
    # and ``fallback_native`` is true (explicit opt-in), the whole server process
    # degrades to the legacy uncontained host-execution mode with a warning;
    # ``fallback_native: false`` (default) fails closed instead. ``enabled: false`` is
    # the explicit opt-out that always uses the legacy mode. See
    # docs/sandbox.md and docs/safety-model.md.
    "sandbox": {
        "enabled": True,
        "backend": "docker",
        "image": "breachpilot-sandbox:latest",
        "user": "sandbox",
        "read_only_rootfs": True,
        # Degrade to the legacy host-execution mode when the boot-time Docker
        # probe (CLI / daemon / worker image) fails, instead of blocking every
        # execution. Explicit opt-in only (default false = fail closed). The
        # WebUI home screen surfaces the degraded state.
        "fallback_native": False,
        # When true, a sandbox session may start Docker if it is stopped and
        # stop it on exit only when BP started it and no containers remain.
        # Linux uses sudo -n so a background server never hangs for a password.
        "auto_manage_docker": False,
        "docker_start_timeout_seconds": 60,
        "docker_stop_timeout_seconds": 30,
        # Host env vars the worker MAY receive (allowlist; never the whole env).
        "env_passthrough": [],
        "resources": {
            "memory_mb": 4096,
            "cpus": 2,
            "pids": 512,
            "timeout_seconds": 300,
            "output_max_bytes": 2000000,
            # /tmp tmpfs size (MB) for the disposable worker; invalid/low values fall back to 256/64MB floor, never host exec.
            "tmpfs_size_mb": 256,
        },
        "network": {
            "enforce": True,
            "fail_closed": True,
            # "controlled": in-container DNS only reaches host-side-validated
            # resolutions; "none": port 53 blocked entirely (no DNS bypass).
            "allow_dns": "controlled",
            # Explicit dev-only mapping of sandbox loopback to the host gateway.
            # NEVER enable for production attack runs.
            "map_host_loopback": False,
            # Extra operator-authorized CIDRs (e.g. a lab supernet).
            "extra_allow_cidrs": [],
            # Allow the Docker bridge gateway (host-published services). Keep
            # false: the gateway is also the path to the Docker daemon.
            "allow_gateway": False,
            # Pinned exploit-research egress (github.com etc., host-resolved).
            "allow_research_hosts": True,
        },
        "cleanup": {
            "remove_on_exit": True,
            "remove_stale_on_startup": True,
        },
        # NET_RAW for raw-packet scanning (nmap -sS). Minimum-capability grant;
        # set false for strictly connect-scanning missions.
        "multi_net_raw": True,
    },
}

# Known top-level keys
KNOWN_TOP_KEYS = set(CONFIG_SCHEMA.keys())

# Alias for the schema-with-defaults dict, used by tests and downstream code
# that refers to it as the default config.
DEFAULT_CONFIG = CONFIG_SCHEMA
