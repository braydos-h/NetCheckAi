import { useCallback, useEffect, useRef, useState } from "react";
import { useQueryClient, type QueryClient } from "@tanstack/react-query";
import { apiFetch, expireSession, getStoredToken } from "@/api/client";
import { queryKeys } from "@/api/hooks";
import { eventStore } from "@/api/eventStore";
import { MAX_EVENTS_PER_RUN, appendBounded } from "@/api/eventBuffer";
import { streamSSE, type SseHandle } from "@/api/sse";
import { isTerminalState, type EventReplayResponse, type RunDetail, type RunEvent, type RunState } from "@/api/types";

export type WsStatus = "idle" | "connecting" | "open" | "reconnecting" | "closed" | "error";

interface UseRunEventsOptions {
  after?: number;
  enabled?: boolean;
}

const WS_CLOSE_AUTH = 4401;
const WS_CLOSE_ORIGIN = 4403;
const WS_CLOSE_CURSOR = 4400;
const WS_CLOSE_NOT_FOUND = 4404;
const MAX_BACKOFF = 10_000;
const SSE_FALLBACK_THRESHOLD = 3;

// The API daemon emits a heartbeat after 30s of quiet on both transports
// (tools/api/event_broker.py). 45s of silence marks the stream stale; 90s
// (three missed heartbeats) force-reconnects a socket the OS has silently
// dropped (laptop sleep, NAT expiry) — those never produce onclose.
const STALE_AFTER_MS = 45_000;
const WATCHDOG_TIMEOUT_MS = 90_000;
const WATCHDOG_TICK_MS = 10_000;

// Event types that must reach the UI immediately (terminal state, decisions,
// errors, and title updates) rather than waiting for the next animation frame.
const IMMEDIATE_EVENT_TYPES = new Set(["state", "approval", "error", "title"]);

function backoffMs(attempt: number): number {
  return Math.min(MAX_BACKOFF, 1000 * 2 ** attempt);
}

function useSafeQueryClient(): QueryClient {
  return useQueryClient();
}

// Runs-list queries carry a params object (["runs", { limit, offset, … }]);
// run-scoped queries carry the run id string. Scoping invalidations to the
// list keeps this run's detail/decisions/artifacts caches untouched.
function isRunListQuery(query: { queryKey: readonly unknown[] }): boolean {
  const key = query.queryKey;
  return key.length > 1 && key[0] === "runs" && typeof key[1] === "object" && key[1] !== null;
}

export function useRunEvents(runId: string | null | undefined, options: UseRunEventsOptions = {}) {
  const { after: initialAfter = 0, enabled = true } = options;
  const [events, setEvents] = useState<RunEvent[]>([]);
  const [status, setStatusState] = useState<WsStatus>("idle");
  const [stale, setStale] = useState(false);
  const [authError, setAuthError] = useState<string>("");
  const [transport, setTransport] = useState<"websocket" | "sse" | "none">("none");
  const [dropped, setDropped] = useState<number>(0);

  const lastSeqRef = useRef<number>(initialAfter);
  // Mirror of `events` so bounded appends can be computed without reading
  // stale state inside a setState updater (kept pure and StrictMode-safe).
  const eventsRef = useRef<RunEvent[]>([]);
  const droppedRef = useRef<number>(0);
  const wsRef = useRef<WebSocket | null>(null);
  const sseHandleRef = useRef<SseHandle | null>(null);
  const sseAbortRef = useRef<AbortController | null>(null);
  const attemptRef = useRef<number>(0);
  const reconnectTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const closedByUnmountRef = useRef(false);
  const wsFailureCountRef = useRef(0);
  const runIdRef = useRef<string | null>(null);
  const pendingRef = useRef<RunEvent[]>([]);
  const rafRef = useRef<number | null>(null);
  // Silence watchdog state: last frame of any kind (heartbeats count), a
  // statusRef mirror so the tick interval doesn't need to be recreated on
  // every status change, and a flag so a watchdog-forced close skips the
  // failure counters (a NAT drop is not a WebSocket defect).
  const lastFrameAtRef = useRef<number>(0);
  const statusRef = useRef<WsStatus>("idle");

  const setStreamStatus = useCallback((next: WsStatus) => {
    statusRef.current = next;
    setStatusState(next);
  }, []);

  const queryClient = useSafeQueryClient();

  const patchCaches = useCallback(
    (event: RunEvent) => {
      if (!queryClient) return;
      const id = runIdRef.current;
      if (!id) return;
      try {
        if (event.type === "state") {
          const state = event.payload?.state;
          if (typeof state === "string") {
            queryClient.setQueryData<RunDetail>(queryKeys.run(id), (prev) => {
              if (!prev) return prev;
              const next: RunDetail = { ...prev, state: state as RunState };
              if (event.payload?.result !== undefined) {
                next.result = event.payload.result as RunDetail["result"];
              }
              return next;
            });
            // The detail cache is patched above; only terminal transitions
            // change the runs list (active → terminal), so only they refetch
            // it. Invalidating ["runs"] unprefixed would also refetch this
            // run's detail/decisions/artifacts on every state event.
            if (isTerminalState(state as RunState)) {
              void queryClient.invalidateQueries({ queryKey: ["runs"], predicate: isRunListQuery });
            }
          }
        } else if (event.type === "approval") {
          void queryClient.invalidateQueries({ queryKey: queryKeys.runDecisions(id) });
        } else if (event.type === "artifact") {
          void queryClient.invalidateQueries({ queryKey: queryKeys.runArtifacts(id) });
          // The attack graph is rebuilt from audit/report artifacts; a new
          // artifact can change it, so invalidate the explorer queries too
          // (lightweight refetch — the backend rebuilds lazily).
          void queryClient.invalidateQueries({ queryKey: ["graphExplorer", id] });
        }
      } catch {
        // Cache patching is best-effort; never let it break the event stream.
      }
    },
    [queryClient],
  );

  const flushPending = useCallback(() => {
    rafRef.current = null;
    const batch = pendingRef.current;
    if (batch.length === 0) return;
    pendingRef.current = [];
    const result = appendBounded(eventsRef.current, batch);
    eventsRef.current = result.events;
    droppedRef.current += result.dropped;
    setEvents(result.events);
    setDropped(droppedRef.current);
  }, []);

  const scheduleFlush = useCallback(() => {
    if (rafRef.current !== null) return;
    rafRef.current = requestAnimationFrame(flushPending);
  }, [flushPending]);

  const handleEvent = useCallback(
    (event: RunEvent) => {
      // Every frame of any kind refreshes the silence watchdog — heartbeats
      // included (they early-return below but are still proof of life).
      lastFrameAtRef.current = Date.now();
      setStale(false);
      if (event.type === "heartbeat") {
        if (typeof event.sequence === "number" && event.sequence > lastSeqRef.current) {
          lastSeqRef.current = event.sequence;
        }
        return;
      }
      if (typeof event.sequence === "number") {
        if (event.sequence <= lastSeqRef.current) return; // dedupe (sequence is the stable ID)
        lastSeqRef.current = event.sequence;
      }
      const id = runIdRef.current ?? event.run_id;
      if (id) eventStore.append(id, event);
      patchCaches(event);
      if (IMMEDIATE_EVENT_TYPES.has(event.type)) {
        if (rafRef.current !== null) {
          cancelAnimationFrame(rafRef.current);
          rafRef.current = null;
        }
        const pending = pendingRef.current;
        pendingRef.current = [];
        const result = appendBounded(eventsRef.current, [...pending, event]);
        eventsRef.current = result.events;
        droppedRef.current += result.dropped;
        setEvents(result.events);
        setDropped(droppedRef.current);
      } else {
        pendingRef.current.push(event);
        scheduleFlush();
      }
    },
    [patchCaches, scheduleFlush],
  );

  const closeSse = useCallback(() => {
    sseHandleRef.current?.close();
    sseHandleRef.current = null;
    if (sseAbortRef.current) {
      sseAbortRef.current.abort();
      sseAbortRef.current = null;
    }
  }, []);

  const connectSse = useCallback(
    (id: string) => {
      closeSse();
      // Cancel any pending WS reconnect timer — the SSE fallback takes over
      // the stream, and a timer left running would open a new WebSocket on
      // top of the live SSE connection.
      if (reconnectTimerRef.current) {
        clearTimeout(reconnectTimerRef.current);
        reconnectTimerRef.current = null;
      }
      const token = getStoredToken();
      const loc = window.location;
      const controller = new AbortController();
      sseAbortRef.current = controller;
      setTransport("sse");
      const handle = streamSSE({
        // Reconnect re-invokes the factory with the freshest cursor.
        url: () =>
          `${loc.origin}/api/v1/runs/${encodeURIComponent(id)}/events/stream` +
          `?after=${lastSeqRef.current}`,
        token,
        signal: controller.signal,
        onEvent: (msg) => {
          try {
            const event: RunEvent = JSON.parse(msg.data ?? "");
            handleEvent(event);
          } catch {
            // Ignore malformed frames; keep the stream alive.
          }
        },
        onStatus: (state) => {
          if (state === "open") {
            lastFrameAtRef.current = Date.now();
            setStreamStatus("open");
          } else if (state === "connecting") setStreamStatus("connecting");
          else if (state === "reconnecting") setStreamStatus("reconnecting");
          else setStreamStatus("closed");
        },
        // Transport-level read activity: SSE keepalives are `:` comments the
        // parser drops, so this — not onEvent — proves the stream is alive.
        onActivity: () => {
          lastFrameAtRef.current = Date.now();
          setStale(false);
        },
        onFatal: (error) => {
          if (error.authError) {
            setAuthError("Authentication failed. Token rejected by the API.");
            // Routed through the shared funnel so the token gate actually
            // appears (clearStoredToken alone doesn't re-render it).
            expireSession("Your session token was rejected by the API.");
          } else {
            setAuthError(error.message);
          }
          setStreamStatus("error");
        },
      });
      sseHandleRef.current = handle;
    },
    [handleEvent, closeSse],
  );

  const seedEvents = useCallback(
    async (id: string, isCancelled?: () => boolean) => {
      try {
        const res = await apiFetch<EventReplayResponse>(
          `/runs/${encodeURIComponent(id)}/events?tail=${MAX_EVENTS_PER_RUN}`,
        );
        if (isCancelled?.()) return;
        const seeded = res.events ?? [];
        const latest = typeof res.latest_sequence === "number" ? res.latest_sequence : 0;
        // The backend now reports omitted_before explicitly; use it directly.
        // Fall back to the legacy has_more_before derivation only for
        // compatibility with older servers.
        const older =
          typeof res.omitted_before === "number"
            ? res.omitted_before
            : res.has_more_before && typeof res.oldest_sequence === "number"
              ? res.oldest_sequence - 1
              : 0;
        // `latest` remains the cursor for live reconnects — the tail window
        // may have omitted thousands of older events, but new arrivals are
        // always > latest and will be replayed via the WS `after` cursor.
        lastSeqRef.current = latest;
        eventStore.set(id, seeded, latest, older);
        eventsRef.current = seeded;
        droppedRef.current = older;
        setEvents(seeded);
        setDropped(older);
      } catch {
        // Seed failed (run not found / network). Connect from the current
        // cursor anyway; the WS/SSE path surfaces auth/404 errors.
      }
    },
    [],
  );

  const connectWs = useCallback(
    (id: string) => {
      if (wsRef.current) {
        wsRef.current.close();
        wsRef.current = null;
      }
      const token = getStoredToken();
      const loc = window.location;
      const scheme = loc.protocol === "https:" ? "wss" : "ws";
      const url = `${scheme}://${loc.host}/api/v1/ws/v1/runs/${encodeURIComponent(id)}`;
      let socket: WebSocket;
      try {
        socket = new WebSocket(url);
      } catch {
        setStreamStatus("error");
        return;
      }
      wsRef.current = socket;
      setTransport("websocket");
      setStreamStatus("connecting");

      socket.onopen = () => {
        attemptRef.current = 0;
        lastFrameAtRef.current = Date.now();
        setStreamStatus("open");
        try {
          socket.send(JSON.stringify({ auth: token, after: lastSeqRef.current }));
        } catch {
          socket.close();
        }
      };

      socket.onmessage = (message) => {
        try {
          const event: RunEvent = JSON.parse(message.data);
          handleEvent(event);
        } catch {
          // Ignore malformed frames.
        }
      };

      socket.onerror = () => {
        setStreamStatus("error");
      };

      socket.onclose = (event) => {
        // Only clear the ref if this socket is still the active one: a
        // watchdog/wake-triggered reconnect may already have opened a
        // replacement, and clobbering it here would orphan the live socket.
        if (wsRef.current === socket) {
          wsRef.current = null;
        }
        setStreamStatus("closed");
        if (closedByUnmountRef.current) return;
        if (wsRef.current) return; // a newer socket already owns the stream
        if (event.code === WS_CLOSE_AUTH) {
          setAuthError("Authentication failed. Token rejected by the API.");
          // Shared funnel: clears the token AND signals the token gate, which
          // a bare clearStoredToken() never re-renders.
          expireSession("Your session token was rejected by the API.");
          setStreamStatus("error");
          return;
        }
        if (event.code === WS_CLOSE_ORIGIN) {
          setAuthError("Origin rejected by the API.");
          setStreamStatus("error");
          return;
        }
        if (event.code === WS_CLOSE_CURSOR) {
          lastSeqRef.current = 0;
          eventsRef.current = [];
          droppedRef.current = 0;
          setEvents([]);
          setDropped(0);
          eventStore.clear(id);
          void seedEvents(id);
        }
        if (event.code === WS_CLOSE_NOT_FOUND) {
          setAuthError("Run not found.");
          setStreamStatus("error");
          return;
        }
        wsFailureCountRef.current += 1;
        if (wsFailureCountRef.current >= SSE_FALLBACK_THRESHOLD) {
          wsFailureCountRef.current = 0;
          connectSse(id);
          return;
        }
        attemptRef.current += 1;
        reconnectTimerRef.current = setTimeout(() => {
          if (runIdRef.current === id && !closedByUnmountRef.current) connectWs(id);
        }, backoffMs(attemptRef.current));
      };
    },
    [handleEvent, connectSse, seedEvents],
  );

  const reconnect = useCallback(() => {
    if (!runIdRef.current || closedByUnmountRef.current) return;
    attemptRef.current = 0;
    wsFailureCountRef.current = 0;
    closeSse();
    if (wsRef.current) {
      wsRef.current.close();
      wsRef.current = null;
    }
    connectWs(runIdRef.current);
  }, [closeSse, connectWs]);

  useEffect(() => {
    runIdRef.current = runId ?? null;
    if (!runId || !enabled) {
      setStreamStatus("idle");
      return;
    }
    closedByUnmountRef.current = false;
    setAuthError("");
    attemptRef.current = 0;
    wsFailureCountRef.current = 0;
    lastFrameAtRef.current = Date.now();

    let cancelled = false;

    const cached = eventStore.get(runId);
    if (cached) {
      // Reuse the in-memory cursor + events instead of replaying from zero.
      lastSeqRef.current = cached.cursor;
      eventsRef.current = cached.events;
      droppedRef.current = cached.dropped;
      setEvents(cached.events);
      setDropped(cached.dropped);
      connectWs(runId);
    } else {
      lastSeqRef.current = initialAfter;
      eventsRef.current = [];
      droppedRef.current = 0;
      setEvents([]);
      setDropped(0);
      void (async () => {
        await seedEvents(runId, () => cancelled);
        if (cancelled) return;
        connectWs(runId);
      })();
    }

    // Silence watchdog. The server heartbeats every 30s while a stream is
    // open, so a silent-but-"open" socket means the connection died without
    // a TCP close (laptop sleep, NAT expiry). Force it through the normal
    // close path, which already handles backoff and the SSE fallback.
    const watchdog = setInterval(() => {
      if (closedByUnmountRef.current || !runIdRef.current) return;
      const silence = Date.now() - lastFrameAtRef.current;
      setStale(statusRef.current === "open" && silence > STALE_AFTER_MS);
      if (silence <= WATCHDOG_TIMEOUT_MS) return;
      if (statusRef.current !== "open") return;
      lastFrameAtRef.current = Date.now();
      attemptRef.current = 0;
      if (wsRef.current) {
        wsRef.current.close(); // onclose drives the normal reconnect path
      } else {
        sseHandleRef.current?.restart();
      }
    }, WATCHDOG_TICK_MS);

    // Wake-up paths: a resumed laptop or restored tab would otherwise wait out
    // the exponential backoff. Give a grace period first so throttled
    // background timers don't trip an immediate false watchdog.
    const wake = () => {
      if (closedByUnmountRef.current || !runIdRef.current) return;
      lastFrameAtRef.current = Date.now();
      attemptRef.current = 0;
      if (statusRef.current === "open") return;
      setStale(false);
      reconnect();
    };
    const onVisible = () => {
      if (document.visibilityState === "visible") wake();
    };
    const onOnline = () => wake();
    document.addEventListener("visibilitychange", onVisible);
    window.addEventListener("online", onOnline);

    return () => {
      cancelled = true;
      closedByUnmountRef.current = true;
      document.removeEventListener("visibilitychange", onVisible);
      window.removeEventListener("online", onOnline);
      clearInterval(watchdog);
      if (reconnectTimerRef.current) {
        clearTimeout(reconnectTimerRef.current);
        reconnectTimerRef.current = null;
      }
      if (rafRef.current !== null) {
        cancelAnimationFrame(rafRef.current);
        rafRef.current = null;
      }
      closeSse();
      if (wsRef.current) {
        wsRef.current.close();
        wsRef.current = null;
      }
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [runId, enabled]);

  return { events, status, stale, authError, transport, reconnect, lastSeq: lastSeqRef, dropped };
}
