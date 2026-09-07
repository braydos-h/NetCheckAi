---
title: Ops Endpoints — Operations Summary Rollup
sources:
  - tools/api/routes/ops.py
tests:
  - tests/test_ops_summary.py
subsystem: api
---

# Ops Endpoints

`tools/api/routes/ops.py:1` — `APIRouter(prefix="/api/v1/ops", tags=["ops"])`. Built by `create_router(auth, config)` (`ops.py:19`) and wired unconditionally in `app.py:170` / `app.py:184`. One read-only rollup for backends that previously had settings toggles but no operational surface: killchain, snapshots (+ counterfactual), eval baseline, browser, and the active chat provider. Read-only by design — enabling stays in `PATCH /api/v1/config` (Settings page); this route only reports. Config sections are read defensively (non-dict values treated as `{}`).

## `GET /api/v1/ops/summary` — `ops_summary`

- Purpose: single status snapshot of dormant backends — killchain, snapshots/counterfactual, eval baseline, browser, active provider.
- Authentication: bearer via `_require_auth` (`ops.py:23`, `Authorization: Bearer <token>` header).
- Params/body: none.
- Response fields (`ops.py:37`):

| Section | Field | Type | Source | Default |
|---------|-------|------|--------|---------|
| `killchain` | `enabled` | bool | `killchain.enabled` | `false` |
| `killchain` | `goal_state` | str | `killchain.goal_state` | `"shell_as_root"` |
| `killchain` | `require_verification` | bool | `killchain.require_verification` | `true` |
| `snapshots` | `enabled` | bool | `snapshots.enabled` | `false` |
| `snapshots` | `provider` | str | `snapshots.provider` | `"docker"` |
| `snapshots` | `counterfactual` | bool | `replay_simulator.counterfactual` | `false` |
| `eval` | `enabled` | bool | `eval.enabled` | `true` |
| `eval` | `baseline_path` | str | `eval.baseline_path` | `"reports/eval/baseline.json"` |
| `eval` | `baseline_exists` | bool | `Path(baseline_path).exists()` (server filesystem) | — |
| `browser` | `enabled` | bool | `browser.enabled` | `false` |
| `browser` | `backend` | str | `browser.backend` | `"none"` |
| `provider` | `active` | str | `models.provider` | `"ollama"` |

- Status codes: `200` with the rollup; `401` missing/invalid token.
- Error conditions: none beyond auth — missing config keys fall back to the defaults above; no path params so no `404`.
- Example request:

```bash
curl -H "Authorization: Bearer $BREACHPILOT_API_TOKEN" \
  http://127.0.0.1:8765/api/v1/ops/summary
```

- Example response:

```json
{
  "killchain": { "enabled": false, "goal_state": "shell_as_root", "require_verification": true },
  "snapshots": { "enabled": false, "provider": "docker", "counterfactual": false },
  "eval": { "enabled": true, "baseline_path": "reports/eval/baseline.json", "baseline_exists": false },
  "browser": { "enabled": false, "backend": "none" },
  "provider": { "active": "ollama" }
}
```

- Related events: none — pure config/filesystem read, emits nothing.
- WebUI usage: `OpsPage` (`webui/src/routes/OpsPage.tsx:30`) via `apiFetch("/ops/summary")` (react-query key `["ops","summary"]`, `staleTime` 15 s) — renders Killchain / Snapshots / Eval baseline / Browser+provider cards and links to `/system` Settings for toggling. No other consumer; enabling stays in `PATCH /api/v1/config`.
- Source file: `tools/api/routes/ops.py:27`.

## Related documentation

- [Endpoint matrix](../endpoint-matrix.md) — method/route/handler table for every family
- [System endpoints](./system.md) — `GET/PATCH /api/v1/config`, the write path for everything this rollup reports
- [Runs endpoints](./runs.md) — run lifecycle (`provider.active` selects the model client)
- [Benchmarks endpoints](./benchmarks.md) — benchmark baselines (compare with the `eval.baseline_path` graded-harness baseline here)

## Source map

- `tools/api/routes/ops.py` — the single `ops_summary` handler
- `app.py` — unconditional router wiring
- `webui/src/routes/OpsPage.tsx` — Operations page consumer
