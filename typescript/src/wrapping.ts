// Service-owned. Response wrapping: wrap, unwrap and look up single-use wrapping tokens
// (API.md §9).

import { Secret } from "./core/index.js";
import { type AuthInfo, authFromEnvelope } from "./auth.js";
import {
  type ClientContext,
  parseTime,
  requireText,
  secondsToMs,
  strings,
  unexpected,
} from "./http.js";

/** Per-call options. */
export interface WrappingCallOptions {
  /** Cancels the call (`CancelledError`). */
  signal?: AbortSignal;
}

/** A wrapping token (redacted in every string form) and its properties. */
export interface WrapInfo {
  /** Single-use wrapping token (redacted). */
  token: Secret;
  /** Accessor (redacted: it can look up or revoke the token). */
  accessor?: Secret;
  /** TTL in ms. */
  ttlMs: number;
  /** Creation time. */
  creationTime: Date | null;
  /** API path that created the token. */
  creationPath: string;
}

/** Result of `lookupWrapping()`. */
export interface WrappingLookup {
  /** API path that created the token. */
  creationPath: string;
  /** Creation time. */
  creationTime: Date | null;
  /** TTL at creation in ms. */
  creationTtlMs: number;
}

/** Result of `unwrap()`: the original response. */
export interface UnwrapResult<T = Record<string, unknown>> {
  /** The wrapped data (`null` for wrapped responses without data, e.g. logins). */
  data: T | null;
  /** The `auth` block when a login response was wrapped. */
  auth?: AuthInfo;
  /** Lease id (empty when the response has no lease). */
  leaseId: string;
  /** Lease TTL in ms. */
  leaseDurationMs: number;
  /** Whether it can be renewed. */
  renewable: boolean;
  /** Server warnings. */
  warnings: string[];
}

/** Response wrapping: `client.wrapping`. */
export class Wrapping {
  readonly #ctx: ClientContext;

  /** @internal */
  constructor(ctx: ClientContext) {
    this.#ctx = ctx;
  }

  /**
   * Wraps `data` in a single-use token valid for `ttlMs` (`POST sys/wrapping/wrap` with
   * `X-Vault-Wrap-TTL`).
   */
  async wrap(
    data: Record<string, unknown>,
    ttlMs: number,
    options: WrappingCallOptions = {},
  ): Promise<WrapInfo> {
    const env = await this.#ctx.http.envelope({
      method: "POST",
      path: "sys/wrapping/wrap",
      operation: "wrapping.wrap",
      json: data,
      wrapTtlMs: ttlMs,
      signal: options.signal,
    });
    const w = env.wrap_info;
    if (w === undefined || w === null || typeof w.token !== "string") {
      throw unexpected("wrapping.wrap", "no wrap_info");
    }
    const accessor = Secret.from(w.accessor);
    return {
      token: new Secret(w.token),
      ...(accessor === undefined ? {} : { accessor }),
      ttlMs: secondsToMs(w.ttl),
      creationTime: parseTime(w.creation_time),
      creationPath: w.creation_path ?? "",
    };
  }

  /**
   * Unwraps a token (`POST sys/wrapping/unwrap` authenticated with the wrapping token itself).
   * A used or invalid token raises `ValidationError`; never retried.
   */
  async unwrap<T = Record<string, unknown>>(
    token: string | Secret,
    options: WrappingCallOptions = {},
  ): Promise<UnwrapResult<T>> {
    const value = token instanceof Secret ? token.reveal() : token;
    const env = await this.#ctx.http.envelope<T>({
      method: "POST",
      path: "sys/wrapping/unwrap",
      operation: "wrapping.unwrap",
      token: requireText(value, "token", "wrapping.unwrap"),
      signal: options.signal,
    });
    const auth =
      env.auth === undefined || env.auth === null
        ? undefined
        : authFromEnvelope(env, "wrapping.unwrap");
    return {
      data: env.data ?? null,
      ...(auth === undefined ? {} : { auth }),
      leaseId: env.lease_id ?? "",
      leaseDurationMs: secondsToMs(env.lease_duration),
      renewable: env.renewable === true,
      warnings: strings(env.warnings),
    };
  }

  /** Properties of a wrapping token without using it: `POST sys/wrapping/lookup`. */
  async lookupWrapping(
    token: string | Secret,
    options: WrappingCallOptions = {},
  ): Promise<WrappingLookup> {
    const value = token instanceof Secret ? token.reveal() : token;
    const d = await this.#ctx.http.data<Record<string, unknown>>({
      method: "POST",
      path: "sys/wrapping/lookup",
      operation: "wrapping.lookupWrapping",
      json: { token: requireText(value, "token", "wrapping.lookupWrapping") },
      token: null,
      signal: options.signal,
      idempotent: true,
    });
    return {
      creationPath: typeof d.creation_path === "string" ? d.creation_path : "",
      creationTime: parseTime(d.creation_time),
      creationTtlMs: secondsToMs(d.creation_ttl),
    };
  }
}
