---
title: Operations Page — Killchain, Snapshots, Eval, Browser, Provider
sources:
  - webui/src/App.tsx
  - webui/src/routes/OpsPage.tsx
tests: []
subsystem: webui
---

# Operations (`/ops`)

Read-only rollup for backends that previously had settings toggles but no operational surface: killchain, snapshots, eval baseline, browser, and provider. Route: `webui/src/App.tsx:69` → `webui/src/routes/OpsPage.tsx:30` (`OpsPage`). Enabling stays in Settings (`PATCH /config`); this page only reports status.

## Data

Single query, no polling beyond the stale window:

```tsx
const query = useQuery({
  queryKey: ["ops", "summary"],
  queryFn: () => apiFetch<OpsSummary>("/ops/summary"),
  staleTime: 15_000,
});
```

`apiFetch` prefixes `/api/v1` (paths already starting with `/api/` pass through), so the wire call is `GET /api/v1/ops/summary`. States: loading skeletons (`Skeleton h-8 w-64` + `h-32 w-full`) while `isLoading && !data`; `ErrorState` ("Could not load operations summary." + Retry via `query.refetch()`) on `isError || !data`.

## `OpsSummary` shape (`OpsPage.tsx:13`)

```ts
interface OpsSummary {
  killchain: { enabled: boolean; goal_state: string; require_verification: boolean };
  snapshots: { enabled: boolean; provider: string; counterfactual: boolean };
  eval: { enabled: boolean; baseline_path: string; baseline_exists: boolean };
  browser: { enabled: boolean; backend: string };
  provider: { active: string };
}
```

## Cards

Header is an `h1` with the `ShieldAlert` icon plus a muted subline linking to `/system` ("Toggle in Settings"). Four `Card`s in a `grid md:grid-cols-2`, each row rendered by the local `Row` helper (`OpsPage.tsx:21`: label in `text-muted-foreground`, value in `font-mono`):

| Card | Description | Rows |
|------|-------------|------|
| Killchain | "Evidence-verified stage machine (opt-in)" | Enabled (`String(...)`), Goal (`goal_state`), Require verification (`String(...)`) |
| Snapshots | "Pre-destructive rollback + counterfactual retry" | Enabled, Provider, Counterfactual |
| Eval baseline | "Graded harness regression gate" | Enabled, Baseline (`baseline_exists ? "present" : "missing"`), Path (`baseline_path`) |
| Browser + provider | "Sandboxed agent + active model provider" | Browser (`` `${backend} (${enabled})` ``), Provider (`provider.active`) |

## Related documentation

- [Settings page](settings.md)
- [Benchmarks pages](benchmarks.md)
- [Other pages](other.md)

## Source map

- `webui/src/App.tsx`
- `webui/src/routes/OpsPage.tsx`
