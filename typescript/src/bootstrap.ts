// Service-owned. Server lifecycle helpers for tests and bootstrap scripts: init, unseal, seal
// and waiting for an active node (API.md §2). Exported only from `@grow-codes/openbao/testing`.

import { Secret, pollUntil, ValidationError } from "./core/index.js";
import type { OpenBaoClient } from "./client.js";
import {
  HEALTH_QUERY,
  type HealthResponse,
  type SealStatus,
  toHealth,
  toSealStatus,
} from "./sys.js";
import { unexpected } from "./http.js";

/** Per-call options. */
export interface LifecycleCallOptions {
  /** Cancels the call (`CancelledError`). */
  signal?: AbortSignal;
}

/** Options of {@link init}. */
export interface InitOptions extends LifecycleCallOptions {
  /** Unseal key shares (Shamir seal, default 1). */
  secretShares?: number;
  /** Shares needed to unseal (Shamir seal, default 1). */
  secretThreshold?: number;
  /** Recovery key shares (auto-unseal / static seal). Sent instead of the secret shares. */
  recoveryShares?: number;
  /** Recovery threshold (auto-unseal / static seal). */
  recoveryThreshold?: number;
}

/** Result of {@link init}. Every key is redacted in string forms. */
export interface InitResult {
  /** Unseal keys (hex). Empty with an auto-unseal seal. */
  keys: Secret[];
  /** Unseal keys (base64). */
  keysBase64: Secret[];
  /** Recovery keys (hex), auto-unseal seals only. */
  recoveryKeys: Secret[];
  /** Recovery keys (base64). */
  recoveryKeysBase64: Secret[];
  /** Initial root token. */
  rootToken: Secret;
}

/** Options of {@link unseal}. */
export interface UnsealOptions extends LifecycleCallOptions {
  /** Discard the keys entered so far. */
  reset?: boolean;
}

/** Options of {@link waitForActive}. */
export interface WaitOptions extends LifecycleCallOptions {
  /** Give up after this many ms (default 30 000). */
  timeoutMs?: number;
  /** Poll interval in ms (default 250). */
  intervalMs?: number;
}

function secrets(value: unknown): Secret[] {
  return Array.isArray(value)
    ? value.filter((v): v is string => typeof v === "string" && v !== "").map((v) => new Secret(v))
    : [];
}

async function rawBody(
  client: OpenBaoClient,
  c: Parameters<OpenBaoClient["context"]["http"]["call"]>[0],
): Promise<Record<string, unknown>> {
  const res = await client.context.http.call<never>(c);
  const body = res.body as unknown;
  if (body === null || typeof body !== "object")
    throw unexpected(c.operation, "empty response body");
  return body as Record<string, unknown>;
}

/** Whether the server is initialised: `GET sys/init`. */
export async function initStatus(
  client: OpenBaoClient,
  options: LifecycleCallOptions = {},
): Promise<boolean> {
  const body = await rawBody(client, {
    method: "GET",
    path: "sys/init",
    operation: "testing.initStatus",
    token: null,
    signal: options.signal,
  });
  return body.initialized === true;
}

/**
 * Initialises a new server: `PUT sys/init`. An initialised server raises `ValidationError`
 * ("already initialized"). Never retried.
 */
export async function init(client: OpenBaoClient, options: InitOptions = {}): Promise<InitResult> {
  const recovery = options.recoveryShares !== undefined || options.recoveryThreshold !== undefined;
  const json = recovery
    ? {
        recovery_shares: options.recoveryShares ?? 1,
        recovery_threshold: options.recoveryThreshold ?? 1,
      }
    : { secret_shares: options.secretShares ?? 1, secret_threshold: options.secretThreshold ?? 1 };
  const body = await rawBody(client, {
    method: "PUT",
    path: "sys/init",
    operation: "testing.init",
    json,
    token: null,
    idempotent: false,
    signal: options.signal,
  });
  if (typeof body.root_token !== "string") throw unexpected("testing.init", "no root_token");
  return {
    keys: secrets(body.keys),
    keysBase64: secrets(body.keys_base64),
    recoveryKeys: secrets(body.recovery_keys),
    recoveryKeysBase64: secrets(body.recovery_keys_base64),
    rootToken: new Secret(body.root_token),
  };
}

/** Enters one unseal key (hex or base64): `PUT sys/unseal`. Returns the seal status. */
export async function unseal(
  client: OpenBaoClient,
  key: string | Secret,
  options: UnsealOptions = {},
): Promise<SealStatus> {
  const value = key instanceof Secret ? key.reveal() : key;
  if (options.reset !== true && value.trim() === "") {
    throw new ValidationError("testing.unseal: key must not be empty");
  }
  const body = await rawBody(client, {
    method: "PUT",
    path: "sys/unseal",
    operation: "testing.unseal",
    json: options.reset === true ? { reset: true } : { key: value },
    token: null,
    idempotent: false,
    signal: options.signal,
  });
  return toSealStatus(body);
}

/** Seals the server (`PUT sys/seal`, needs a root/sudo token). */
export async function seal(
  client: OpenBaoClient,
  options: LifecycleCallOptions = {},
): Promise<void> {
  await client.context.http.send({
    method: "PUT",
    path: "sys/seal",
    operation: "testing.seal",
    signal: options.signal,
  });
}

/**
 * Polls `sys/health` until the node is active (initialised, unsealed and leader). Throws
 * `TimeoutError` when it does not become active in time.
 */
export async function waitForActive(
  client: OpenBaoClient,
  options: WaitOptions = {},
): Promise<HealthResponse> {
  const signal = options.signal === undefined ? {} : { signal: options.signal };
  return pollUntil(
    async () =>
      toHealth(
        await rawBody(client, {
          method: "GET",
          path: "sys/health",
          operation: "testing.waitForActive",
          query: HEALTH_QUERY,
          token: null,
          ...signal,
        }),
      ),
    (h) => h.state === "active",
    {
      timeoutMs: options.timeoutMs ?? 30_000,
      intervalMs: options.intervalMs ?? 250,
      operation: "testing.waitForActive",
      ignoreError: (err) => (err as { retryable?: unknown }).retryable === true,
      ...signal,
    },
  );
}
