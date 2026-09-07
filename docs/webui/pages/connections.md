---
title: Connections Page — Operator Access Channels
sources:
  - webui/src/App.tsx
  - webui/src/routes/ConnectionsPage.tsx
  - webui/src/api/hooks.ts
  - webui/src/api/types.ts
  - webui/src/api/client.ts
tests:
  - webui/src/routes/ConnectionsPage.test.tsx
  - webui/src/api/connections.test.ts
subsystem: webui
---

# Connections (`/connections`)

Persisted operator access channels created during authorized runs. Header copy states it plainly: creations are automatic after successful persistence — there is no manual setup. Route: `webui/src/App.tsx:70` → `webui/src/routes/ConnectionsPage.tsx:184` (`ConnectionsPage`).

## Hooks and endpoints

All hooks come from `@/api/hooks` (`hooks.ts:1097-1186`); `apiFetch` prefixes `/api/v1`, so the wire paths are `/api/v1/connections*`. `useConnections` also feeds the sidebar badge (`components/Layout.tsx:74`).

| Hook | Call | Invalidates / notes |
|------|------|---------------------|
| `useConnections(params?: { status?: string; target?: string })` | `GET /connections[?status=&target=]` → `ConnectionsListResponse` | `staleTime: 8_000`, `refetchOnWindowFocus: false`. Adaptive `refetchInterval`: 12 s with no data yet or any `active` row, 15 s if only `stale`, else 30 s |
| `useConnection(connectionId, enabled = true)` | `GET /connections/<id>` → `OperatorConnection` | Enabled only when `!!connectionId && enabled`. Interval: 10 s with no data or `active`/`stale`, `false` once `removed`, else 30 s |
| `useConnectionListener(connectionId, enabled = true)` | `GET /connections/<id>/listener` → `ConnectionListenerResponse` | `staleTime: 2_000`, `refetchInterval: enabled ? 3_000 : false`; 404s do not retry (`ApiError.isNotFound`) |
| `useCheckConnection()` | `POST /connections/<id>/check` body `{}` → `OperatorConnection` | `onSuccess` writes the connection cache and invalidates `connections` + `connection(id)` + `connectionListener(id)` |
| `useRemoveConnection()` | `POST /connections/<id>/remove` body `{}` → `RemoveConnectionResponse` | `onSuccess` writes `data.connection` into the cache and invalidates `connections` + `connection(id)` |

## Status model

`ConnectionStatus` (`@/api/types`) has four values, ranked for the default sort and styled via `STATUS_META` (`ConnectionsPage.tsx:66-81`):

| Status | Rank | Badge variant | Dot | Icon |
|--------|------|---------------|-----|------|
| `error` | 0 | `danger` (`ERROR`) | `bg-red-500` | `AlertTriangle` |
| `stale` | 1 | `warn` (`STALE`) | `bg-amber-500` | `Clock3` |
| `active` | 2 | `success` (`ACTIVE`) | `bg-emerald-500` | `CheckCircle2` |
| `removed` | 3 | `muted` (`REMOVED`) | `bg-zinc-400` | `Archive` |

`ConnectionStatusBadge` (`ConnectionsPage.tsx:150`) falls back to a muted uppercase badge for unknown values. The table's beacon dot is separate (`beaconDotClass`, `ConnectionsPage.tsx:138`): emerald under 90 s, amber under an hour, zinc otherwise — forced red for `error`, zinc for `removed`/never. `humanizeMethod` title-cases `snake_case` (`ConnectionsPage.tsx:58`); time helpers are `formatBeacon` ("just now" / `Ns ago` / `Nm ago` / `Nh Mm ago` / `Nd ago` / "Never"), `formatAge` (no "ago" suffix), `formatLastCheck`, and `formatIsoOrRelative` (prefers the ISO string, falls back to epoch).

## KPIs, filters, table

Stat strip mirrors the Skills/Goals pattern (`grid grid-cols-2 sm:grid-cols-4`, `HeaderStat` `ConnectionsPage.tsx:744`): Active (emerald), Stale (amber), Error (red), Total. Counts come from the list response (`{ total, active, stale, removed, error }`); before it lands they are computed from the rows, with `Skeleton` values while loading.

Toolbar:

- Status pills (`FILTER_OPTIONS`, `ConnectionsPage.tsx:176`): All / Active / Stale / Removed / Error, each with its status icon and live count, `role="tablist"` / `role="tab"` with `aria-selected`.
- Search (`Input`, 250 ms debounce) across `target_ip`, `connection_id`, `method`, `listener_name`, `os_family`, `mitre_technique`, `notes`, `callback_host`, with a clear (`X`) button.
- Sort: header buttons on desktop (`SortTh`, `ConnectionsPage.tsx:710`, `ArrowUp` / `ArrowDown` / `ArrowUpDown`), a `select` on small screens. Keys `status | target | created | beacon | method`, each toggling `asc | desc`; ties break on newest `created_at`.
- A "Showing X of Y connections · filtered to … · search …" footer with `Clear filters` appears whenever filters are active or the list is narrowed.

States and layouts:

- Loading → `ConnectionsSkeleton` (`ConnectionsPage.tsx:778`): table skeleton on desktop, three card skeletons on mobile.
- Error → destructive banner with `ApiError.message` (or "Failed to load connections.") + Retry.
- Empty (`raw.length === 0`) → dashed `Card` with the `Radio` icon: "No persisted connections", a note pointing at sessions, and a `View sessions` button (`Link to="/sessions"`).
- Filtered-to-zero → dashed "No connections match your filters" + `Clear filters`.
- Results → desktop table (`hidden md:block`: Target / Method / Status / Callback / Listener / Last beacon / Age + `View` button with the `Eye` icon; rows are keyboard-operable, `Enter`/`Space` opens the drawer) and mobile cards (`md:hidden`: beacon dot + target, humanized method + OS + MITRE, callback/listener grid, beacon + age footer). `Refresh` button top-right spins (`RefreshCw animate-spin`) while `isFetching`.

## Details drawer (`ConnectionDetailsDrawer`, `ConnectionsPage.tsx:821`)

A right-side `Dialog` (`md:w-[520px]`, full-height) opened per `connection_id`; closing clears the selection. Data: `useConnection(open ? connectionId : null, open)` plus `useConnectionListener` gated on `open && status !== "removed"`. A status-toned guidance banner sits under the header (emerald "Healthy — recent beacon" under 120 s, amber nudges for aging beacons/`stale`, red for `error`, muted audit note for `removed`).

| Section | Content |
|---------|---------|
| Identity | Target, Connection, Method (+ raw `sub`), OS, MITRE Technique, Implant Path, Notes when present — `DetailRow` (`ConnectionsPage.tsx:1220`) with `CopyButton` on mono values |
| Network | Callback (`host:port`), Listener — both copyable |
| Timeline | Created, Last Beacon, Last Health Check (ISO preferred, relative `sub`), plus the `check_output` `<pre>` when present |
| Health Check | Explains the probe updates status to `active`/`stale` without exposing new credentials; `Check connection` button (`ShieldAlert`, `Loader2` "Checking…" while pending, disabled when `removed`) with "Last checked …" and inline `ApiError` text; success toasts "Health check complete" |
| Listener Output | `Live` pulse while fetching an `active` connection; Refresh; loading spinner; error + Retry; `not_found` / `LOG_NOT_FOUND` renders a dashed "Listener unavailable or stopped" (`Wifi`); otherwise a `zinc-950` `<pre>` with autoscroll (`outputRef`, `handleScroll`, 40 px near-bottom threshold, "Resume autoscroll") and a "Listener running/stopped · updated …" footer |
| Danger Zone | Destructive `Remove connection` (`Trash2`, disabled when pending or already `removed`); opens a "Remove connection?" confirm dialog (target/listener/ID recap, Cancel/Remove) explaining the record is retained for audit and listener cleanup is attempted; success toasts "Connection removed" and closes the drawer |

## Related documentation

- [Run page](run.md)
- [Other pages](other.md)
- [Operations page](ops.md)

## Source map

- `webui/src/App.tsx`
- `webui/src/routes/ConnectionsPage.tsx`
- `webui/src/api/hooks.ts`
- `webui/src/api/types.ts`
- `webui/src/api/client.ts`
