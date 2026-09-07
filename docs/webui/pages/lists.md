---
title: List Pages — Home, Sessions, Stats, Memory, Skills, Goals, Modules
sources:
  - webui/src/App.tsx
  - webui/src/routes/HomePage.tsx
  - webui/src/routes/RunListPage.tsx
  - webui/src/routes/StatsPage.tsx
  - webui/src/routes/MemoryPage.tsx
  - webui/src/routes/SkillsPage.tsx
  - webui/src/routes/GoalsPage.tsx
  - webui/src/routes/AttackModulesPage.tsx
  - webui/src/api/hooks.ts
  - webui/src/api/types.ts
tests: []
subsystem: webui
---

# List Pages

Purpose, data dependencies, and API calls for the seven list / catalog / dashboard pages. This file is an index only — full component breakdowns live in `other.md`, `home.md`, and `run.md` (linked per section).

```tsx
// webui/src/App.tsx:53-64 — route registration (all lazy except HomePage)
<Route path="/" element={<HomePage />} />
<Route path="/sessions" element={<RunListPage />} />
<Route path="/stats" element={<StatsPage />} />
<Route path="/memory" element={<MemoryPage />} />
<Route path="/skills" element={<SkillsPage />} />
<Route path="/goals" element={<GoalsPage />} />
<Route path="/modules" element={<AttackModulesPage />} />
```

| Route | Component | Detail doc |
|-------|-----------|------------|
| `/` | `HomePage` (`routes/HomePage.tsx:552`) | `./home.md` |
| `/sessions` | `RunListPage` (`routes/RunListPage.tsx:66`) | `./run.md` |
| `/stats` | `StatsPage` (`routes/StatsPage.tsx:219`) | `./other.md#stats` |
| `/memory` | `MemoryPage` (`routes/MemoryPage.tsx:226`) | `./other.md#memory` |
| `/skills` | `SkillsPage` (`routes/SkillsPage.tsx:223`) | `./other.md#skills` |
| `/goals` | `GoalsPage` (`routes/GoalsPage.tsx:94`) | `./other.md#goals` |
| `/modules` | `AttackModulesPage` (`routes/AttackModulesPage.tsx:29`) | `./other.md#attack-modules` |

## Home (`/`)

Purpose: landing dashboard — hero, stats strip, sandbox posture, active-run banner, two action cards (`/runs/new?path=recon`, `/runs/new?path=attack`), recent sessions, safety footer. Full layout: `./home.md`.

Data dependencies:

| Hook | Call site | Use |
|------|-----------|-----|
| `useRuns(50, 0)` | `HomePage.tsx:553` | `rows`, `activeRun` (`rows.find(isActiveState)`), `recent` (`rows.slice(0, 5)`), `doneCount` (`filter(isTerminalState)`), `failedCount` (`filter(s === "failed")`) |
| `useSandboxStatus` + `useSandboxFixPlan` / `useSandboxFix` / `useSandboxFixStatus` | `SandboxBanner` (`HomePage.tsx:448`), `SandboxFixDialog` (`HomePage.tsx:94`) | boot-time sandbox posture (`contained` / `disabled` / `native_fallback` / `blocked`) |

API calls:

| Hook | Method and URL |
|------|----------------|
| `useRuns` | `GET /runs?limit=50&offset=0&sort=created_desc` (`api/hooks.ts:690`) |

Implementation note: sandbox endpoint paths are not enumerated here; see `SandboxBanner` and the sandbox hooks in `api/hooks.ts`.

## Sessions (`/sessions`)

Purpose: searchable, filterable, sortable table of all runs with per-row Open / Regen title / Resume / Delete actions and an active-runs banner. Full controls table: `./run.md#run-list-sessions`.

Data dependencies:

```tsx
// webui/src/routes/RunListPage.tsx:72
const runs = useRuns(PAGE_SIZE, page * PAGE_SIZE, sortKey, debouncedQ, stateFilter);
```

| Item | Source | Note |
|------|--------|------|
| `PAGE_SIZE = 50`, `SORT_KEY_STORAGE = "breachpilot.runSort"` | `RunListPage.tsx:39-40` | sort persisted to `localStorage` |
| `STATE_FILTER_OPTIONS` | `RunListPage.tsx:42` | `""` + 11 `RunState` values |
| `RUN_SORT_OPTIONS`, `RunSortKey`, `RunState` | `api/types.ts` | sort select options |
| `isActiveState`, `isTerminalState`, `isDemoRun` | `api/types.ts` | banner, delete/resume gating, demo highlight |
| `maxConcurrent` | `useCapabilities().data.constraints.max_concurrent_runs` | gates `New run` button |

API calls:

| Hook | Method and URL |
|------|----------------|
| `useRuns` | `GET /runs?limit&offset&sort&q&state` (search debounced 300ms, adaptive poll 5s active / 60s idle) |
| `useCapabilities` | `GET /capabilities` |
| `useResumeRun` | `POST /runs/<id>/resume` (terminal rows only, navigates to new id) |
| `useRetitleRun` | `POST /runs/<id>/title {regen: true}` |
| `useDeleteRun` | `DELETE /runs/<id>?purge=true` (disabled while `isActiveState`, confirm `Dialog`) |
| `useRestoreDemo` | `POST /runs/demo/restore` (empty-state action) |

## Stats (`/stats`)

Purpose: operational KPIs, run-activity charts, recent-runs list, and LLM telemetry overview. Full section breakdown: `./other.md#stats`.

Data dependencies:

```tsx
// webui/src/routes/StatsPage.tsx:220-227
const runs = useRuns(RUN_LIMIT, 0); // RUN_LIMIT = 200
const telemetry = useTelemetry();
const runDays = aggregateRunsByDay(days, rows);       // DAYS = 14
const tokenDays = aggregateTokensByDay(days, recentTelemetry);
```

| Helper | Source | Output |
|--------|--------|--------|
| `aggregateRunsByDay` | `StatsPage.tsx:178` | `RunDay {date, total, completed, failed, other}` |
| `aggregateTokensByDay` | `StatsPage.tsx:192` | `TokenDay {date, total, prompt, completion, unattributed, calls}` |
| `STATE_META`, `STATE_ORDER` | `StatsPage.tsx:80-105` | bar colors + distribution order |
| `KpiOverview`, `StatCard` | `StatsPage.tsx:387-532` | 6 KPI cards |
| `RunsChart`, `StateDistribution`, `RecentRuns` | `StatsPage.tsx:534-986` | run analytics (`RECENT_RUN_COUNT = 8`) |
| `TokenUsageChart`, `TelemetryOverview` | `StatsPage.tsx:586-865` | LLM charts + metrics |

API calls:

| Hook | Method and URL |
|------|----------------|
| `useRuns` | `GET /runs?limit=200&offset=0` |
| `useTelemetry` | `GET /system/telemetry` (`api/hooks.ts:307`, `staleTime 15s`, poll 8s) |

## Memory (`/memory`)

Purpose: cross-run knowledge dashboard — skill confidence table, cross-mission lessons, attack-memory explorer — with overview cards and per-tab search / filter / sort. Full card breakdown: `./other.md#memory`.

Data dependencies:

```tsx
// webui/src/routes/MemoryPage.tsx:227-230
const memory = useMemory();
const rawConfidence = memory.data?.confidence ?? [];
const rawLessons = memory.data?.lessons ?? [];
const rawAttack = memory.data?.attack_memory ?? [];
```

| Helper | Source | Role |
|--------|--------|------|
| `deriveMemoryOverview` | `MemoryPage.tsx:79` | 6 overview counts + avg confidence |
| `filterAndSortConfidence` | `MemoryPage.tsx:106` | query + min-obs + 5 sorts |
| `filterAndSortLessons` | `MemoryPage.tsx:137` | query + outcome filter + 3 sorts |
| `filterAndSortAttackMemory` | `MemoryPage.tsx:176` | query + target/category/result + 4 sorts |
| `ConfidenceTable`, `LessonsList`, `AttackMemoryList` | `MemoryPage.tsx:983-1174` | tab bodies |
| `MemoryOverviewCards`, `MemoryStat` | `MemoryPage.tsx:774-907` | overview strip |

API calls:

| Hook | Method and URL |
|------|----------------|
| `useMemory` | `GET /system/memory` (`api/hooks.ts:318`, `staleTime 15s`) → `MemoryResponse {lessons, confidence, attack_memory}` |

## Skills (`/skills`)

Purpose: skill catalog with enable / auto / block states, detail viewer, add-from-markdown dialog, and delete flow. Full layout breakdown: `./other.md#skills`.

Data dependencies:

| Item | Source | Note |
|------|--------|------|
| `readSkillsConfig`, `SkillsConfig`, `skillState`, `STATE_META` | `SkillsPage.tsx:82-116` | `enabled` / `blocked` / `auto` from `default_enabled` + `exclude_names` |
| `topTags`, `filtered` | `SkillsPage.tsx:254-285` | 20 most frequent tags; search + tag + status + sort |
| `SKILL_TEMPLATE` | `SkillsPage.tsx:127` | new-skill starter markdown |
| `SkillMarkdown` | `SkillsPage.tsx:159` | `ReactMarkdown + remarkGfm` renderer |
| `SkillDetailView`, `SkillRowActions`, `HeaderStat` | `SkillsPage.tsx:977-1274` | detail pane, state popover, stat strip |

API calls:

| Hook | Method and URL |
|------|----------------|
| `useSkills` | `GET /skills` |
| `useSkillSearch` | `GET /skills/search?q=` (debounced 250ms) |
| `useSkillDetail` | `GET /skills/<name>` |
| `useInstallSkill` | `POST /skills {name, markdown}` (name validated `/^[a-z0-9][a-z0-9-]{1,63}$/`) |
| `useRemoveSkill` | `DELETE /skills/<name>` |
| `useConfig` | `GET /config` (skills block via `readSkillsConfig`) |
| `usePatchConfig` | `PATCH /config {skills: …}` (enable / auto / block, master switch, lookup/inject) |

## Goals (`/goals`)

Purpose: preset + custom goal catalog with risk filtering and deep links into the New Run wizard. Full card breakdown: `./other.md#goals`.

Data dependencies:

| Item | Source | Note |
|------|--------|------|
| `RISK_META` | `GoalsPage.tsx:50` | `safe` / `gated` / `high` labels, icons, requirements |
| `FILTERS`, `RiskFilter` | `GoalsPage.tsx:39-83` | `all` / `safe` / `gated` / `high` / `custom` |
| `GoalStats`, `RiskFilterButton`, `RiskLegend` | `GoalsPage.tsx:345-430` | counts, pills, legend |
| `GoalCard`, `CustomGoalCard` | `GoalsPage.tsx:432-564` | preset vs custom cards |
| `startPreset` | `GoalsPage.tsx:149` | `navigate(/runs/new?path=<recon if safe else attack>&goal=<name>)` |
| `startCustom` | `GoalsPage.tsx:153` | `navigate(/runs/new?path=attack&customGoal=<id>)` |

API calls:

| Hook | Method and URL |
|------|----------------|
| `useGoals` | `GET /goals` (`api/hooks.ts:564`, `staleTime Infinity`) → `{goals: GoalPreset[], custom_goals: CustomGoal[]}` |
| `useCreateGoal` | `POST /goals {name, objective}` (`CustomGoalDialog`) |
| `useUpdateGoal` | `PATCH /goals/<id> {name, objective}` |
| `useDeleteGoal` | `DELETE /goals/<id>` (confirm `Dialog`) |

## Modules (`/modules`)

Purpose: read-only registry of pre-packaged exploit recipes with family + text filtering. Full row breakdown: `./other.md#attack-modules`.

```tsx
// webui/src/routes/AttackModulesPage.tsx:34-48
const modules = useAttackModules();
const list = (modules.data?.modules ?? []).filter(/* family + query */);
const families = [...new Set(modules.map(m => m.family))].sort();
```

| Item | Source | Note |
|------|--------|------|
| `FAMILY_LABELS` | `AttackModulesPage.tsx:11` | 15 families (`web` → `Web`, `network_smb` → `SMB / Network`, …) |
| `FamilyChip` | `AttackModulesPage.tsx:95` | pill filter with per-family counts |
| `ModuleRow` | `AttackModulesPage.tsx:112` | mono name + family `Badge` + `destructive_ics` danger `Badge` + services / ports / CVEs |

API calls:

| Hook | Method and URL |
|------|----------------|
| `useAttackModules` | `GET /attack/modules` (`api/hooks.ts:555`, `staleTime 60s`) → `AttackModulesResponse {modules: AttackModuleSummary[]}` |

## Related documentation

- [Other pages](./other.md) — full component breakdowns for Stats, Memory, Skills, Goals, and Modules
- [Home page](./home.md) — hero, stats strip, and recent sessions detail
- [Run pages](./run.md) — Sessions table controls and Live Run surface
- [Run-create components](../components/run-create.md) — New Run wizard internals
- [API integration](../api-integration.md) — hooks, query keys, and polling conventions
- [WebUI state](../state.md) — queries, WebSocket events, and invalidation

## Source map

- webui/src/App.tsx
- webui/src/routes/HomePage.tsx
- webui/src/routes/RunListPage.tsx
- webui/src/routes/StatsPage.tsx
- webui/src/routes/MemoryPage.tsx
- webui/src/routes/SkillsPage.tsx
- webui/src/routes/GoalsPage.tsx
- webui/src/routes/AttackModulesPage.tsx
- webui/src/api/hooks.ts
- webui/src/api/types.ts
