// Service-owned. Internal OpenBao HTTP layer on top of the shared core transport: `/v1/` paths,
// `X-Vault-Token` / `X-Vault-Namespace` headers, the response envelope and the OpenBao-specific
// error mapping (API.md §0, DECISIONS.md #4).

import {
  ErrorCode,
  type HttpTransport,
  OpenBaoError,
  type QueryValue,
  type ResponseType,
  Secret,
  UnavailableError,
  ValidationError,
  errorForCode,
} from "./core/index.js";
import type { OpenBaoConfig } from "./config.js";

/** The JSON envelope of every OpenBao response (wire form, snake_case). */
export interface Envelope<T = unknown> {
  request_id?: string;
  lease_id?: string;
  renewable?: boolean;
  lease_duration?: number;
  data?: T | null;
  wrap_info?: WireWrapInfo | null;
  warnings?: string[] | null;
  auth?: WireAuth | null;
}

/** `wrap_info` block (wire form). */
export interface WireWrapInfo {
  token: string;
  accessor?: string;
  ttl?: number;
  creation_time?: string;
  creation_path?: string;
  wrapped_accessor?: string;
}

/** `auth` block (wire form). */
export interface WireAuth {
  client_token: string;
  accessor?: string;
  policies?: string[] | null;
  token_policies?: string[] | null;
  metadata?: Record<string, string> | null;
  lease_duration?: number;
  renewable?: boolean;
  entity_id?: string;
  token_type?: string;
  orphan?: boolean;
  num_uses?: number;
}

/** One OpenBao API call. */
export interface VaultCall {
  method: "GET" | "POST" | "PUT" | "PATCH" | "DELETE";
  /** Path below `/v1/` (already percent-encoded, see {@link encodePath}). */
  path: string;
  /** Operation name for error messages, e.g. `kv.read secret/app`. */
  operation: string;
  query?: Readonly<Record<string, QueryValue>>;
  json?: unknown;
  headers?: Readonly<Record<string, string>>;
  signal?: AbortSignal | undefined;
  idempotent?: boolean;
  /** Error statuses returned instead of thrown (their body is not available). */
  allowStatus?: readonly number[];
  responseType?: ResponseType;
  /** Token override: a value replaces the client token, `null` sends no token. */
  token?: string | null;
  /** Sends `GET ...?list=true` (the LIST operation). */
  list?: boolean;
  /** Requests response wrapping (`X-Vault-Wrap-TTL`). */
  wrapTtlMs?: number;
  /** Login endpoint: 400/401/403 become `AuthenticationError`. */
  login?: boolean;
}

/** Result of {@link VaultHttp.call}. */
export interface VaultResult<T> {
  status: number;
  body: Envelope<T> | undefined;
}

/** Holds the client token (mutable: logins replace it). */
export interface TokenHolder {
  get(): Secret | undefined;
  set(token: Secret | undefined): void;
}

/** Everything a service module needs from the client. @internal */
export interface ClientContext {
  readonly http: VaultHttp;
  readonly config: OpenBaoConfig;
  readonly tokens: TokenHolder;
}

const AUTH_403 = /invalid token|token not found|missing client token|bad token/i;
/** Missing/invalid/revoked tokens get the plain `["permission denied"]` body (API.md §0). */
const PLAIN_DENIED = /: permission denied \(HTTP 403\)$/;
const CAS_MISMATCH = /check-and-set parameter did not match/i;

/**
 * Applies the OpenBao-specific status mapping on top of the SPEC defaults:
 * - login endpoints: 400/401/403 → `AUTHENTICATION`;
 * - 403 with the plain "permission denied" body (missing, invalid or revoked token) or a
 *   message naming an invalid/missing token → `AUTHENTICATION`; a policy denial
 *   ("1 error occurred: * permission denied") stays `PERMISSION_DENIED`;
 * - 400 "check-and-set parameter did not match" → `CONFLICT`;
 * - 405 (unsupported operation) → `UNSUPPORTED`;
 * - 501 (not initialised) → `UNAVAILABLE`.
 */
export function mapVaultError(err: OpenBaoError, login = false): OpenBaoError {
  const status = err.httpStatus;
  if (status === undefined) return err;
  let code: ErrorCode | undefined;
  if (login && (status === 400 || status === 401 || status === 403)) {
    code = ErrorCode.Authentication;
  } else if (status === 403 && (AUTH_403.test(err.message) || PLAIN_DENIED.test(err.message))) {
    code = ErrorCode.Authentication;
  } else if (status === 400 && CAS_MISMATCH.test(err.message)) {
    code = ErrorCode.Conflict;
  } else if (status === 405) {
    code = ErrorCode.Unsupported;
  } else if (status === 501) {
    code = ErrorCode.Unavailable;
  }
  if (code === undefined || code === err.code) return err;
  return errorForCode(code, err.message, {
    httpStatus: status,
    ...(err.requestId === undefined ? {} : { requestId: err.requestId }),
    ...(err.retryAfterMs === undefined ? {} : { retryAfterMs: err.retryAfterMs }),
    ...(err.cause === undefined ? {} : { cause: err.cause }),
  });
}

/** Internal OpenBao HTTP client. @internal */
export class VaultHttp {
  readonly transport: HttpTransport;
  readonly #tokens: TokenHolder;
  readonly #namespace: string | undefined;

  constructor(transport: HttpTransport, tokens: TokenHolder, namespace: string | undefined) {
    this.transport = transport;
    this.#tokens = tokens;
    this.#namespace = namespace;
  }

  /** Sends one call and returns the status and decoded envelope (undefined for 204). */
  async call<T = unknown>(c: VaultCall): Promise<VaultResult<T>> {
    const headers: Record<string, string> = {};
    if (this.#namespace !== undefined) headers["x-vault-namespace"] = this.#namespace;
    const token = c.token === undefined ? this.#tokens.get()?.reveal() : c.token;
    if (token !== null && token !== undefined) headers["x-vault-token"] = token;
    if (c.wrapTtlMs !== undefined) headers["x-vault-wrap-ttl"] = durationString(c.wrapTtlMs);
    Object.assign(headers, c.headers);
    const query = c.list === true ? { ...c.query, list: "true" } : c.query;
    try {
      const res = await this.transport.request<Envelope<T> | undefined>({
        method: c.method,
        path: `/v1/${c.path}`,
        operation: c.operation,
        headers,
        ...(query === undefined ? {} : { query }),
        ...(c.json === undefined ? {} : { json: c.json }),
        ...(c.signal === undefined ? {} : { signal: c.signal }),
        ...(c.idempotent === undefined ? {} : { idempotent: c.idempotent }),
        ...(c.allowStatus === undefined ? {} : { allowStatus: c.allowStatus }),
        ...(c.responseType === undefined ? {} : { responseType: c.responseType }),
      });
      return { status: res.status, body: res.data };
    } catch (err) {
      throw err instanceof OpenBaoError ? mapVaultError(err, c.login === true) : err;
    }
  }

  /** Sends a call and returns the envelope (throws when the body is empty). */
  async envelope<T = unknown>(c: VaultCall): Promise<Envelope<T>> {
    const res = await this.call<T>(c);
    if (res.body === undefined || typeof res.body !== "object") {
      throw unexpected(c.operation, "empty response body");
    }
    return res.body;
  }

  /** Sends a call and returns `envelope.data` (throws when it is missing). */
  async data<T = unknown>(c: VaultCall): Promise<T> {
    const env = await this.envelope<T>(c);
    if (env.data === undefined || env.data === null) {
      throw unexpected(c.operation, "response has no data");
    }
    return env.data;
  }

  /** Sends a call whose response body is ignored (204 or envelope). */
  async send(c: VaultCall): Promise<void> {
    await this.call(c);
  }
}

/** Error for a response that does not have the documented shape. */
export function unexpected(operation: string, reason: string): UnavailableError {
  return new UnavailableError(`${operation}: unexpected response (${reason})`, {
    retryable: false,
  });
}

/** Rejects empty names/paths client side (`ValidationError`). */
export function requireText(value: string, what: string, operation: string): string {
  if (typeof value !== "string" || value.trim() === "") {
    throw new ValidationError(`${operation}: ${what} must not be empty`);
  }
  return value;
}

/** Strips leading and trailing slashes. */
export function trimSlashes(value: string): string {
  // Linear scan: a /^\/+|\/+$/g regex backtracks polynomially on long runs of "/".
  let start = 0;
  let end = value.length;
  while (start < end && value.charCodeAt(start) === 47) start += 1;
  while (end > start && value.charCodeAt(end - 1) === 47) end -= 1;
  return value.slice(start, end);
}

/** RFC 3986 sub-delims and `:`/`@` are valid in a path segment and stay readable. */
const SEGMENT_SAFE = /%(21|24|26|27|28|29|2A|2B|2C|3A|3B|3D|40)/gi;

/** Percent-encodes one path segment (keeps `:` so PKI serials stay readable). */
export function encodeSegment(segment: string): string {
  return encodeURIComponent(segment).replace(SEGMENT_SAFE, (e) => decodeURIComponent(e));
}

/**
 * Joins path parts with `/` and percent-encodes each segment (keeping the separators):
 * `encodePath("kv1", "sdk/with space")` → `kv1/sdk/with%20space`. Empty parts are skipped.
 */
export function encodePath(...parts: string[]): string {
  return parts
    .flatMap((p) => p.split("/"))
    .filter((s) => s !== "")
    .map(encodeSegment)
    .join("/");
}

/** Milliseconds → OpenBao duration string in whole seconds, rounded up (`1500` → `"2s"`). */
export function durationString(ms: number): string {
  if (!Number.isFinite(ms) || ms < 0) {
    throw new ValidationError(`invalid duration: ${String(ms)} ms`);
  }
  return `${Math.ceil(ms / 1000)}s`;
}

/** Seconds (wire) → milliseconds; non-numbers become 0. */
export function secondsToMs(value: unknown): number {
  return typeof value === "number" && Number.isFinite(value) ? value * 1000 : 0;
}

/**
 * Parses an OpenBao duration value (seconds as a number, or a Go duration string such as
 * `"720h0m0s"`) into milliseconds; `undefined` when absent or invalid.
 */
export function parseVaultDuration(value: unknown): number | undefined {
  if (typeof value === "number") return value * 1000;
  if (typeof value !== "string" || value === "") return undefined;
  if (/^\d+$/.test(value)) return Number(value) * 1000;
  const re = /(\d+(?:\.\d+)?)(ns|us|µs|ms|s|m|h)/gy;
  const unit: Record<string, number> = {
    ns: 1e-6,
    us: 1e-3,
    µs: 1e-3,
    ms: 1,
    s: 1000,
    m: 60_000,
    h: 3_600_000,
  };
  let total = 0;
  let pos = 0;
  let m: RegExpExecArray | null;
  while ((m = re.exec(value)) !== null) {
    total += Number(m[1]) * (unit[m[2] as string] as number);
    pos = re.lastIndex;
  }
  return pos === value.length ? Math.round(total) : undefined;
}

/**
 * Parses a timestamp: RFC 3339 string or unix seconds. Empty strings, `0`, `null` and invalid
 * values return `null`.
 */
export function parseTime(value: unknown): Date | null {
  if (typeof value === "number") return value > 0 ? new Date(value * 1000) : null;
  if (typeof value !== "string" || value === "") return null;
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? null : d;
}

/** UTF-8 text or bytes → standard base64. */
export function toBase64(value: string | Uint8Array): string {
  return Buffer.from(typeof value === "string" ? new TextEncoder().encode(value) : value).toString(
    "base64",
  );
}

/** Standard base64 → bytes. */
export function fromBase64(value: string): Uint8Array {
  return new Uint8Array(Buffer.from(value, "base64"));
}

/** `true` when the bytes are valid UTF-8. */
export function isUtf8(bytes: Uint8Array): boolean {
  try {
    new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    return true;
  } catch {
    return false;
  }
}

/** String array from a wire value (`null` → `[]`). */
export function strings(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((v): v is string => typeof v === "string") : [];
}

/** String map from a wire value (`null` → `{}`), stringifying non-string values. */
export function stringMap(value: unknown): Record<string, string> {
  const out: Record<string, string> = {};
  if (value === null || typeof value !== "object" || Array.isArray(value)) return out;
  for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
    if (v === null || v === undefined) continue;
    out[k] = typeof v === "string" ? v : JSON.stringify(v);
  }
  return out;
}

/** Copies the given options to a wire body, dropping `undefined` values. */
export function compact(body: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(body)) if (v !== undefined) out[k] = v;
  return out;
}

/** `durationString(ms)` or `undefined`. */
export function optDuration(ms: number | undefined): string | undefined {
  return ms === undefined ? undefined : durationString(ms);
}
