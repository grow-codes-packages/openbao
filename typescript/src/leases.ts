// Service-owned. Leases of dynamic secrets: renew, revoke, lookup and automatic renewal
// with `onExpire` (API.md §6).

import { ValidationError } from "./core/index.js";
import {
  type ClientContext,
  type Envelope,
  encodePath,
  optDuration,
  parseTime,
  requireText,
  secondsToMs,
  strings,
} from "./http.js";
import { type LeaseState, RenewalLoop, type RenewalOptions } from "./renewal.js";

/** Per-call options. */
export interface LeaseCallOptions {
  /** Cancels the call (`CancelledError`). */
  signal?: AbortSignal;
}

/** A lease on a dynamic secret (e.g. database credentials). */
export interface Lease<T = Record<string, unknown>> {
  /** Lease id, e.g. `database/creds/readonly/abc`. */
  leaseId: string;
  /** TTL in ms. */
  leaseDurationMs: number;
  /** Whether it can be renewed. */
  renewable: boolean;
  /** The secret data. */
  data: T;
  /** Server warnings (e.g. TTL capped by `max_ttl`). */
  warnings: string[];
}

/** Result of `renew()`. */
export interface LeaseRenewal {
  /** Lease id (empty when the response has no lease). */
  leaseId: string;
  /** Granted TTL in ms (may be capped by the maximum TTL; see `warnings`). */
  leaseDurationMs: number;
  /** Whether it can be renewed. */
  renewable: boolean;
  /** Server warnings. */
  warnings: string[];
}

/** Result of `lookup()`. */
export interface LeaseInfo {
  /** Lease id. */
  id: string;
  /** Path that created the lease, e.g. `database/creds/readonly`. */
  path: string;
  /** Issue time. */
  issueTime: Date | null;
  /** Expiry time, `null` when it never expires. */
  expireTime: Date | null;
  /** Last renewal time, `null` when never renewed. */
  lastRenewal: Date | null;
  /** Whether it can be renewed. */
  renewable: boolean;
  /** Remaining TTL in ms. */
  ttlMs: number;
}

/** Options of `manage()`. */
export interface ManageLeaseOptions extends RenewalOptions {
  /** Called after every renewal. */
  onRenew?: (renewal: LeaseRenewal) => void;
  /** Revoke the lease when the handle is stopped or the client closes (default `false`). */
  revokeOnStop?: boolean;
}

/** Handle of a lease kept alive by {@link LeaseManager.manage}. */
export interface ManagedLease {
  /** Lease id (empty when the response has no lease). */
  readonly leaseId: string;
  /** Whether renewal is still active. */
  readonly running: boolean;
  /** Whether `onExpire` fired. */
  readonly expired: boolean;
  /** Expiry of the current lease (ms since epoch). */
  readonly expiresAt: number;
  /** Stops renewing (and revokes when `revokeOnStop`). Idempotent. */
  stop(): Promise<void>;
}

/** Converts an envelope with a lease into a {@link Lease}. @internal */
export function leaseFromEnvelope<T>(env: Envelope, data: T): Lease<T> {
  return {
    leaseId: env.lease_id ?? "",
    leaseDurationMs: secondsToMs(env.lease_duration),
    renewable: env.renewable === true,
    data,
    warnings: strings(env.warnings),
  };
}

/** Lease operations and automatic renewal: `client.leases`. */
export class LeaseManager {
  readonly #ctx: ClientContext;
  readonly #managed = new Set<ManagedLease>();

  /** @internal */
  constructor(ctx: ClientContext) {
    this.#ctx = ctx;
  }

  /**
   * Renews a lease: `PUT sys/leases/renew`. A TTL beyond the maximum is capped (see
   * `warnings`); unknown or revoked leases raise `ValidationError`.
   */
  async renew(
    leaseId: string,
    incrementMs?: number,
    options: LeaseCallOptions = {},
  ): Promise<LeaseRenewal> {
    const env = await this.#ctx.http.envelope({
      method: "PUT",
      path: "sys/leases/renew",
      operation: "leases.renew",
      json: {
        lease_id: requireText(leaseId, "leaseId", "leases.renew"),
        ...(incrementMs === undefined ? {} : { increment: optDuration(incrementMs) }),
      },
      signal: options.signal,
    });
    return {
      leaseId: env.lease_id ?? leaseId,
      leaseDurationMs: secondsToMs(env.lease_duration),
      renewable: env.renewable === true,
      warnings: strings(env.warnings),
    };
  }

  /** Revokes a lease now: `PUT sys/leases/revoke`. */
  async revoke(leaseId: string, options: LeaseCallOptions = {}): Promise<void> {
    await this.#ctx.http.send({
      method: "PUT",
      path: "sys/leases/revoke",
      operation: "leases.revoke",
      json: { lease_id: requireText(leaseId, "leaseId", "leases.revoke") },
      signal: options.signal,
    });
  }

  /** Revokes every lease under a prefix: `PUT sys/leases/revoke-prefix/<prefix>`. */
  async revokePrefix(prefix: string, options: LeaseCallOptions = {}): Promise<void> {
    await this.#ctx.http.send({
      method: "PUT",
      path: encodePath(
        "sys/leases/revoke-prefix",
        requireText(prefix, "prefix", "leases.revokePrefix"),
      ),
      operation: "leases.revokePrefix",
      signal: options.signal,
    });
  }

  /** Lease details: `PUT sys/leases/lookup`. Unknown leases raise `ValidationError`. */
  async lookup(leaseId: string, options: LeaseCallOptions = {}): Promise<LeaseInfo> {
    const d = await this.#ctx.http.data<Record<string, unknown>>({
      method: "PUT",
      path: "sys/leases/lookup",
      operation: "leases.lookup",
      json: { lease_id: requireText(leaseId, "leaseId", "leases.lookup") },
      signal: options.signal,
    });
    return {
      id: typeof d.id === "string" ? d.id : leaseId,
      path: typeof d.path === "string" ? d.path : "",
      issueTime: parseTime(d.issue_time),
      expireTime: parseTime(d.expire_time),
      lastRenewal: parseTime(d.last_renewal),
      renewable: d.renewable === true,
      ttlMs: secondsToMs(d.ttl),
    };
  }

  /**
   * Keeps a lease alive: renews at 2/3 of its TTL until the maximum TTL is reached, then calls
   * `onExpire` once when it expires. Stopped by the handle, {@link stopAll} or `client.close()`.
   */
  manage(
    lease: Pick<Lease<unknown>, "leaseId" | "leaseDurationMs" | "renewable">,
    options: ManageLeaseOptions = {},
  ): ManagedLease {
    if (lease.leaseId === "") throw new ValidationError("leases.manage: the lease has no id");
    const leaseId = lease.leaseId;
    const loop = new RenewalLoop<LeaseState & LeaseRenewal>({
      ...options,
      renew: async (incrementMs) => {
        const r = await this.renew(leaseId, incrementMs);
        return { ...r, ttlMs: r.leaseDurationMs };
      },
      onExpire: () => {
        this.#managed.delete(handle);
        options.onExpire?.();
      },
      onRenew: (r) =>
        options.onRenew?.({
          leaseId: r.leaseId,
          leaseDurationMs: r.leaseDurationMs,
          renewable: r.renewable,
          warnings: r.warnings,
        }),
    });
    const managed = this.#managed;
    // eslint-disable-next-line prefer-const
    let handle: ManagedLease;
    let stopped: Promise<void> | undefined;
    handle = {
      leaseId,
      get running() {
        return loop.running;
      },
      get expired() {
        return loop.expired;
      },
      get expiresAt() {
        return loop.expiresAt;
      },
      stop: () => {
        stopped ??= (async () => {
          loop.stop();
          managed.delete(handle);
          if (options.revokeOnStop === true && !loop.expired) {
            await this.revoke(leaseId).catch((err: unknown) => {
              options.onError?.(err);
            });
          }
        })();
        return stopped;
      },
    };
    managed.add(handle);
    loop.start({ ttlMs: lease.leaseDurationMs, renewable: lease.renewable });
    return handle;
  }

  /** Number of managed leases. */
  get activeLeases(): number {
    return this.#managed.size;
  }

  /** Stops every managed lease (revoking those with `revokeOnStop`). Idempotent. */
  async stopAll(): Promise<void> {
    await Promise.all([...this.#managed].map((m) => m.stop()));
  }
}
