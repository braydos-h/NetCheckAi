import type {
  ApiErrorEnvelope,
  ApiErrorShape,
} from "@/api/types";
import { toast } from "@/hooks/use-toast";

// The bearer token lives in module memory ONLY — never in
// sessionStorage/localStorage, where any XSS payload could replay it against
// the loopback API. Trade-off: a page refresh drops the session and the
// TokenGate re-prompts (accepted: the token is one paste away in
// .webui_secret_key).
let inMemoryToken = "";

export function getStoredToken(): string {
  return inMemoryToken;
}

export function setStoredToken(token: string): void {
  inMemoryToken = token || "";
}

export function clearStoredToken(): void {
  setStoredToken("");
  try {
    sessionStorage.removeItem("breachpilot.telemetry.sessionBaseline.v1");
  } catch {
    // Ignore
  }
}

/** Window event fired when the API rejects the session token (HTTP 401 or a
 *  WS 4401 close). TokenGate subscribes to it because it reads the token at
 *  render time — without this signal a mid-session expiry would never
 *  re-render the gate and the app would sit on a dead console. */
export const AUTH_EXPIRED_EVENT = "breachpilot:auth-expired";

/** Single funnel for session expiry. The stored-token guard makes the first
 *  caller win: several 401s (query + mutation + stream) landing in the same
 *  tick fire exactly one event and one toast. */
export function expireSession(reason: string): void {
  if (!getStoredToken()) return;
  clearStoredToken();
  try {
    sessionStorage.removeItem("breachpilot.telemetry.sessionBaseline.v1");
  } catch {
    // Ignore
  }
  window.dispatchEvent(new CustomEvent(AUTH_EXPIRED_EVENT, { detail: { reason } }));
  toast({
    title: "Session expired",
    description: reason,
    variant: "destructive",
  });
}

export class ApiError extends Error {
  status: number;
  code: string;
  details: Record<string, unknown>;
  requestId: string;
  // ponytail: any (not unknown) so 503 fallbacks assign without `as` casts.
  raw: any;

  constructor(shape: ApiErrorShape) {
    super(shape.message || `API error ${shape.status}`);
    this.name = "ApiError";
    this.status = shape.status;
    this.code = shape.code;
    this.details = shape.details;
    this.requestId = shape.requestId;
    this.raw = shape.raw;
  }

  get isAuth(): boolean {
    return this.status === 401;
  }

  get isConflict(): boolean {
    return this.status === 409;
  }

  get isNotFound(): boolean {
    return this.status === 404;
  }
}

interface FetchOptions {
  method?: string;
  body?: unknown;
  signal?: AbortSignal;
  headers?: Record<string, string>;
  raw?: boolean;
}

const API_PREFIX = "/api/v1";

export async function apiFetch<T>(path: string, options: FetchOptions = {}): Promise<T> {
  const token = getStoredToken();
  const headers: Record<string, string> = {
    Accept: "application/json",
    ...(options.headers ?? {}),
  };
  if (token) headers.Authorization = `Bearer ${token}`;
  if (options.body !== undefined && options.method && options.method !== "GET") {
    headers["Content-Type"] = "application/json";
  }

  const url = path.startsWith("http") || path.startsWith("/api/") ? path : `${API_PREFIX}${path}`;
  const init: RequestInit = {
    method: options.method ?? "GET",
    headers,
    signal: options.signal,
  };
  if (options.body !== undefined && options.method && options.method !== "GET") {
    init.body = typeof options.body === "string" ? options.body : JSON.stringify(options.body);
  }

  let response: Response;
  try {
    response = await fetch(url, init);
  } catch (err) {
    if (err instanceof DOMException && err.name === "AbortError") throw err;
    throw new ApiError({
      status: 0,
      code: "network",
      message: err instanceof Error ? err.message : "Network request failed",
      details: {},
      requestId: "",
      raw: err,
    });
  }

  if (response.status === 204) return undefined as T;

  const contentType = response.headers.get("content-type") ?? "";
  const isJson = contentType.includes("application/json");

  if (options.raw && !response.ok) {
    const rawBody = isJson ? await response.json().catch(() => null) : await response.text().catch(() => null);
    throw normalizeError(response.status, rawBody);
  }

  if (!response.ok) {
    const rawBody = isJson ? await response.json().catch(() => null) : await response.text().catch(() => null);
    throw normalizeError(response.status, rawBody);
  }

  if (options.raw) return (await response.blob()) as unknown as T;
  if (!isJson) return (await response.text()) as unknown as T;
  return (await response.json()) as T;
}

function normalizeError(status: number, body: unknown): ApiError {
  if (body && typeof body === "object" && "error" in body) {
    const env = body as ApiErrorEnvelope;
    const err = env.error;
    return new ApiError({
      status,
      code: err.code,
      message: err.message,
      details: err.details ?? {},
      requestId: err.request_id ?? "",
      raw: body,
    });
  }
  if (body && typeof body === "object" && "detail" in body) {
    const detail = (body as { detail: unknown }).detail;
    const message = typeof detail === "string" ? detail : "Request validation failed";
    return new ApiError({
      status,
      code: "http_error",
      message,
      details: { detail },
      requestId: "",
      raw: body,
    });
  }
  const text = typeof body === "string" ? body : responseStatusText(status);
  return new ApiError({
    status,
    code: "http_error",
    message: text || `Request failed (${status})`,
    details: {},
    requestId: "",
    raw: body,
  });
}

function responseStatusText(status: number): string {
  const map: Record<number, string> = {
    400: "Bad request",
    401: "Unauthorized",
    403: "Forbidden",
    404: "Not found",
    409: "Conflict",
    422: "Validation failed",
    500: "Server error",
    502: "Bad gateway",
    503: "Service unavailable",
    504: "Gateway timeout",
  };
  return map[status] ?? "";
}