---
title: New Run Wizard — Guided Run Creation
sources:
  - webui/src/App.tsx
  - webui/src/routes/NewRunPage.tsx
  - webui/src/components/run-create/RunWizard.tsx
  - webui/src/components/run-create/RunStepper.tsx
  - webui/src/components/run-create/ModeSelector.tsx
  - webui/src/components/run-create/GoalSelector.tsx
  - webui/src/components/run-create/ModelSelector.tsx
  - webui/src/components/run-create/ExecutionProfile.tsx
  - webui/src/components/run-create/profile.ts
  - webui/src/components/run-create/TargetField.tsx
  - webui/src/components/run-create/RunReview.tsx
  - webui/src/components/run-create/RunSummary.tsx
  - webui/src/components/run-create/RunStartupProgress.tsx
  - webui/src/lib/targetValidation.ts
  - webui/src/api/hooks.ts
  - webui/src/api/types.ts
tests:
  - webui/src/components/run-create/RunWizard.test.tsx
subsystem: webui
---

# New Run Wizard (`/runs/new`)

Route wrapper `NewRunPage` renders `RunWizard`; `onCreated` navigates to `/runs/<id>`. Component internals (props, preset tables, request-builder field mapping) live in `../components/run-create.md` — this file covers the page-level flow: step order, navigation gating, validation, and the launch gate.

```tsx
// webui/src/App.tsx:55 — route registration (lazy)
<Route path="/runs/new" element={<NewRunPage />} />

// webui/src/routes/NewRunPage.tsx:4-9 — thin wrapper
export function NewRunPage() {
  const navigate = useNavigate();
  return (
    <RunWizard onCreated={(runId) => navigate(`/runs/${runId}`)} />
  );
}
```

## Steps and navigation

`STEPS` (`RunStepper.tsx:4`): `["opsec", "settings", "target", "review"]`. The stepper shows `OPSEC → Configure → Target → Review & launch` (`STEP_META`). `RunSummary` renders as a sticky rail on desktop and a compact card below content on mobile; it is display-only.

| Step | Content | Component |
|------|---------|-----------|
| `opsec` | OPSEC posture editor, advisory only | `OpsecSettings` |
| `settings` | Mode, goal, model, execution profile, advanced, skip-confirm | `ModeSelector`, `GoalSelector`, `ModelSelector`, `ExecutionProfile`, `AdvancedExecutionSettings`, `SkillsSettings` |
| `target` | Single target input | `TargetField` |
| `review` | Summary, launch button, startup panel, ready-to-begin gate | `RunReview`, `RunStartupProgress` |

Navigation gating (`RunWizard.tsx:278-295`):

```ts
const stepIndex = STEPS.indexOf(step);
const canGoNext = step === "opsec" || step === "settings"
  || (step === "target" && isValidTarget(target));
const canVisit = Object.fromEntries(
  STEPS.map((s, i) => [s, i <= stepIndex ? i !== stepIndex : i === stepIndex + 1 && canGoNext]),
) as Record<Step, boolean>;
```

Backward steps are always clickable; only the immediate next step is clickable and only when validation allows. `review` is reachable solely from a valid target. `goBack` at the first step calls `navigate(-1)`. Next/Back buttons hide on `review` (launch owns that step) and disable while `launching`.

## Settings step

### Mode (`ModeSelector.tsx`)

Radiogroup `recon | attack | fast` (`MODE_OPTIONS` with `ScanSearch` / `Swords` / `Zap` icons). `?path=` preselects the mode (`attack` / `fast`, else `recon`). `handleModeChange` (`RunWizard.tsx:164`) applies fast per-run defaults once — `reconFirst = true`, `observerMode = "hybrid"`, all `powerUps` off — without forcing the profile id; manual edits afterwards stay editable in Advanced.

### Goal (`GoalSelector.tsx`)

`goalMode: "preset" | "custom"` via `SegmentedControl`. Preset mode shows a searchable `Popover` grouped by risk (`safe` / `gated` / `high` via `goalGroups`); incompatible presets render an `Unavailable` badge but remain selectable in the list. Custom mode shows a saved-goals `Select` (populated from `custom_goals`) that fills the free-text `Textarea` without linking it. `?goal=<name>` preselects only when the preset exists and is `compatible`; `?customGoal=` (or `?custom_goal=`) resolves a custom-goal id to its objective and flips to custom mode. Recon mode ignores the goal (`GoalSelector.tsx:258`).

### Model (`ModelSelector.tsx`)

Provider-aware picker fed by `useModelOptions` with `useLiveModels` + `useSyncModels` + `useProviderStatus`. Empty `modelAlias` is seeded from `useDefaultModel`. The status row collapses to one line: `Connected` / `Checking…` / `Registry fallback` (Ollama only) / `Authentication required` / `Offline`. The refresh button refetches live models, and on Ollama also syncs the registry (`POST /models/refresh`, Ollama-only). A current value missing from new options is preserved rather than cleared (provider switch).

### Execution profile (`profile.ts`, `ExecutionProfile.tsx`)

UI-only presets mapping onto existing fields (power-ups + observer + skills); never a new backend parameter. `profileFieldValues(id, flags)` resolves against capability flags so unsupported flags stay off; `custom` returns `null` (no mapping). Any manual edit to a controlled field flips the profile to `custom` via `touch()`, suppressed during batch apply by `applyingRef`.

| Profile | Power-ups | Observer | Skills |
|---------|-----------|----------|--------|
| `standard` | all off | `hybrid` | `off` |
| `fast` | all off | `heuristic` | `off` |
| `deep` | on where `flags.includes(key)` | `llm` | `on` |
| `custom` | — (manual) | — | — |

Advanced settings (`AdvancedExecutionSettings`, `SkillsSettings`) sit in a collapsible panel: power-up `Switch` rows filtered to `visiblePowerUps` (`swarm`, `parallel_swarm`, `critic`, `reflection`, `adaptive_exploits`, `long_session`, `multi_model_consult`, `ultrathink`), `critic` / `parallel_swarm` / `reflection` disabled unless `swarm` is on; `observerMode` (`heuristic` / `hybrid` / `llm`); `reconFirst` tri-state (`On` / `Off` / `Auto`); skills mode (`off` / `on` / `hints` / `lookup`) with include / exclude multi-selects. The skip-confirm `Checkbox id skip-confirm` maps to `yes` in the request. Implementation note: `RunWizard.test.tsx` coverage of the swarm-critic gate and preselect rules was read second-hand via `run-create.md`; re-verify against the test file before citing line numbers.

## Target step (`TargetField.tsx`)

Single `Input` validated by `isValidTarget` (`lib/targetValidation.ts:80`): strict IPv4 (`STRICT_IPV4`, four octets 0–255), IPv6 (`isValidIPv6` — normal, compressed `::`, IPv4-embedded, `%zone` stripped, matching Python `ipaddress.ip_address`), or FQDN (dot-separated labels, TLD ≥ 2 alpha). Empty stays neutral; valid shows green; invalid shows amber until blur (`touched`), then red with `role="alert"` and `aria-invalid`. The value is trimmed only at request build; `canGoNext` blocks `review` until valid.

## Review and launch (`RunReview.tsx`)

Review rows (Target / Mode / Goal / Model / Execution / Skills / Observer / Recon first) each carry an `Edit` link jumping back via `onEdit(step)`. The launch button label follows the mode (`Launch Fast Run` / `Launch Attack` / `Start Recon`); attack and fast runs show their respective notice banners. `launchDisabled = isCreating || !!startup`; duplicate clicks are locked out by `submitLockRef` (released only on failure).

```ts
// webui/src/components/run-create/RunWizard.tsx:179-200 — request shape
const buildRequest = (): RunCreateRequest => ({
  target: target.trim(),
  mode,
  goal: goalMode === "preset" ? goal : "",
  custom_goal: goalMode === "custom" ? customGoal.trim() : "",
  recon_first: reconFirst,
  model: modelAlias || undefined,
  swarm: !!powerUps.swarm,
  parallel_swarm: !!powerUps.parallel_swarm,
  critic: !!powerUps.swarm && !!powerUps.critic,
  reflection: !!powerUps.swarm && !!powerUps.reflection,
  adaptive_exploits: !!powerUps.adaptive_exploits,
  long_session: !!powerUps.long_session,
  multi_model_consult: powerUps.multi_model_consult ?? null,
  observer_mode: observerMode,
  ultrathink: !!powerUps.ultrathink,
  skills: skillsMode === "off" ? null : skillsMode,
  skills_include: skillsInclude,
  skills_exclude: skillsExclude,
  kind: "agent",
  yes,
});
```

`createTheRun` (`RunWizard.tsx:202`) posts via `useCreateRun` (`POST /runs`). If the response is already `queued` / `running` (e.g. `yes: true`), `onCreated` navigates immediately. Otherwise the wizard holds the run: `useRun(createdRunId)` polls the transition (`preparing` at 1s) and `useRunEvents` feeds the latest `preparing`-type payload into `RunStartupProgress` (`sending` → `preparing` with backend stage + message). A `failed` transition releases the lock and surfaces `runError` with retry; `queued` / `running` navigates once via `navigatedRef`.

### Destructive confirm gate

The server remains the authority: after preparation, a pending `start_confirm` decision in `runDetail.decisions` renders the gate (`RunReview.tsx:112-118`).

| Case | Gate UI | Answer |
|------|---------|--------|
| `preview.destructive === true` | Destructive form: exact `required_text` (or `preview.required_confirmation_text`) shown in `<code>`, `Input` must match exactly before submit enables | `useAnswerDecision(runId)` → `POST /runs/<id>/decisions/<decId> {answer: confirmText}` |
| Non-destructive | Single `Proceed` button | Same mutation with `{answer: "yes"}` |

On success `onCreated(runDetail.id, "running")` navigates to the live run. `createError` (an `ApiError` message) renders with a `Retry` button that re-invokes `createTheRun`.

## API calls

| Hook | Method and URL | Used for |
|------|----------------|----------|
| `useCreateRun` | `POST /runs` | create from `buildRequest()` |
| `useRun` | `GET /runs/<id>` | poll `preparing` → `queued` / `running` / `failed` |
| `useRunEvents` | WS/SSE run stream | `preparing` stage payloads for the startup panel |
| `useAnswerDecision` | `POST /runs/<id>/decisions/<decId> {answer}` | `start_confirm` gate |
| `useCapabilities` | `GET /capabilities` | `run_options.flags` → `visiblePowerUps` |
| `useGoals` | `GET /goals` | presets + `custom_goals` (`staleTime Infinity`) |
| `useSkills` | `GET /skills` | include / exclude options |
| `useConfig` / `usePatchConfig` | `GET /config` / `PATCH /config {opsec: …}` | OPSEC step draft + save |
| `useLiveModels` / `useSyncModels` | `GET /models/live` / `POST /models/refresh` (Ollama-only) | model picker + refresh |
| `useDefaultModel` | Implementation note: provider hook in `ProviderSetup.tsx`; endpoint not enumerated here | default alias seed |

## Related documentation

- [Run-create components](../components/run-create.md) — wizard state, step components, and helper reference
- [Run pages](./run.md) — Sessions table and the Live Run surface reached after `onCreated`
- [List pages](./lists.md) — Goals catalog deep links (`?goal=`, `?customGoal=`)
- [Other pages](./other.md) — Skills catalog and attack-module registry backing wizard options
- [API integration](../api-integration.md) — hooks, query keys, and polling conventions
- [WebUI state](../state.md) — run-event streaming and invalidation

## Source map

- webui/src/routes/NewRunPage.tsx
- webui/src/components/run-create/RunWizard.tsx
- webui/src/components/run-create/RunStepper.tsx
- webui/src/components/run-create/ModeSelector.tsx
- webui/src/components/run-create/GoalSelector.tsx
- webui/src/components/run-create/ModelSelector.tsx
- webui/src/components/run-create/ExecutionProfile.tsx
- webui/src/components/run-create/profile.ts
- webui/src/components/run-create/AdvancedExecutionSettings.tsx
- webui/src/components/run-create/SkillsSettings.tsx
- webui/src/components/run-create/OpsecSettings.tsx
- webui/src/components/run-create/TargetField.tsx
- webui/src/components/run-create/RunReview.tsx
- webui/src/components/run-create/RunSummary.tsx
- webui/src/components/run-create/RunStartupProgress.tsx
- webui/src/lib/targetValidation.ts
- webui/src/api/hooks.ts
- webui/src/api/types.ts
