// Service-owned. Renewal scheduling shared by TokenRenewer (auth tokens) and LeaseManager
// (dynamic secret leases).

import { OpenBaoError } from "./core/index.js";

/** Clock and timers used by renewers; injectable for tests. */
export interface Scheduler {
  /** Current time in ms. */
  now(): number;
  /** Runs `fn` after `ms` ms; returns a handle for {@link clearTimeout}. */
  setTimeout(fn: () => void, ms: number): unknown;
  /** Cancels a pending timer. */
  clearTimeout(handle: unknown): void;
}

/** The real clock. Timers do not keep the process alive. */
export const systemScheduler: Scheduler = Object.freeze({
  now: () => Date.now(),
  setTimeout: (fn: () => void, ms: number): unknown => {
    const t = setTimeout(fn, Math.max(0, ms));
    t.unref();
    return t;
  },
  clearTimeout: (handle: unknown): void => {
    clearTimeout(handle as ReturnType<typeof setTimeout>);
  },
});

/** Remaining lifetime of a token or lease. */
export interface LeaseState {
  /** Time to live in ms (`0` = never expires). */
  ttlMs: number;
  /** Whether it can be renewed. */
  renewable: boolean;
}

/** Common options of the token and lease renewers. */
export interface RenewalOptions {
  /**
   * Requested TTL for each renewal in ms. Default: the server's default for the token/lease. A
   * renewal that grants less than the requested TTL (or less than the initial TTL when no
   * increment is set) means the maximum TTL was reached.
   */
  incrementMs?: number;
  /** Renew after this fraction of the TTL has passed (default `2/3`). */
  renewFraction?: number;
  /** Shortest delay between two attempts in ms (default 500). */
  minDelayMs?: number;
  /** Called with every failed attempt. Renewal goes on while time is left. */
  onError?: (error: unknown) => void;
  /** Called exactly once when the token/lease expires and cannot be renewed any more. */
  onExpire?: () => void;
  /** Clock and timers (tests). */
  scheduler?: Scheduler;
}

/** Internal options of {@link RenewalLoop}. */
export interface RenewalLoopOptions<S extends LeaseState> extends RenewalOptions {
  /** Renews and returns the new state. */
  renew: (incrementMs: number | undefined) => Promise<S>;
  /** Obtains a fresh token/lease (e.g. a new login) when renewal is no longer possible. */
  reacquire?: () => Promise<S>;
  /** Called after every successful renewal or reacquisition. */
  onRenew?: (state: S) => void;
}

/** Slack when comparing a granted TTL with the requested one. */
const CAP_TOLERANCE_MS = 1000;

function safe<A extends unknown[]>(fn: ((...args: A) => void) | undefined, ...args: A): void {
  try {
    fn?.(...args);
  } catch {
    // callbacks never break the renewal loop
  }
}

function isRetryable(err: unknown): boolean {
  return err instanceof OpenBaoError ? err.retryable : true;
}

/**
 * Renews at `renewFraction` of the TTL. When the lifetime cannot be extended any more
 * (not renewable, maximum TTL reached, renewal refused) it reacquires (when configured) or calls
 * `onExpire` once at expiry. Retryable failures are retried halfway to the expiry.
 */
export class RenewalLoop<S extends LeaseState> {
  readonly #o: RenewalLoopOptions<S>;
  readonly #scheduler: Scheduler;
  readonly #fraction: number;
  readonly #minDelay: number;
  #timer: unknown;
  #stopped = false;
  #expired = false;
  #expiresAt = 0;
  #baselineTtl = 0;

  constructor(options: RenewalLoopOptions<S>) {
    this.#o = options;
    this.#scheduler = options.scheduler ?? systemScheduler;
    const f = options.renewFraction ?? 2 / 3;
    this.#fraction = f > 0 && f < 1 ? f : 2 / 3;
    this.#minDelay = Math.max(0, options.minDelayMs ?? 500);
  }

  /** Whether the loop is still scheduled. */
  get running(): boolean {
    return !this.#stopped;
  }

  /** Whether `onExpire` fired. */
  get expired(): boolean {
    return this.#expired;
  }

  /** Expiry time (ms since epoch) of the current token/lease, `0` when it never expires. */
  get expiresAt(): number {
    return this.#expiresAt;
  }

  /** Starts with the current state. */
  start(initial: LeaseState): void {
    this.#baselineTtl = initial.ttlMs;
    this.#schedule(initial, false);
  }

  /** Stops all timers. Idempotent; `onExpire` is not called. */
  stop(): void {
    this.#stopped = true;
    this.#clear();
  }

  #clear(): void {
    if (this.#timer !== undefined) this.#scheduler.clearTimeout(this.#timer);
    this.#timer = undefined;
  }

  #at(delayMs: number, fn: () => void): void {
    this.#clear();
    if (this.#stopped) return;
    this.#timer = this.#scheduler.setTimeout(() => {
      this.#timer = undefined;
      if (!this.#stopped) fn();
    }, delayMs);
  }

  #schedule(state: LeaseState, final: boolean): void {
    if (this.#stopped) return;
    if (state.ttlMs <= 0) {
      // Never expires (e.g. a root token): nothing to schedule.
      this.#expiresAt = 0;
      this.#clear();
      return;
    }
    this.#expiresAt = this.#scheduler.now() + state.ttlMs;
    const early = Math.max(this.#minDelay, state.ttlMs * this.#fraction);
    if (!final && state.renewable) {
      this.#at(early, () => void this.#renew());
    } else if (this.#o.reacquire !== undefined) {
      this.#at(Math.min(early, state.ttlMs), () => void this.#reacquire());
    } else {
      this.#at(state.ttlMs, () => {
        this.#expire();
      });
    }
  }

  #remaining(): number {
    return this.#expiresAt - this.#scheduler.now();
  }

  async #renew(): Promise<void> {
    const requested = this.#o.incrementMs;
    try {
      const state = await this.#o.renew(requested);
      if (this.#stopped) return;
      safe(this.#o.onRenew, state);
      const wanted = requested ?? this.#baselineTtl;
      const capped = state.ttlMs + CAP_TOLERANCE_MS < wanted;
      this.#schedule(state, capped || !state.renewable);
    } catch (err) {
      if (this.#stopped) return;
      safe(this.#o.onError, err);
      const remaining = this.#remaining();
      if (isRetryable(err) && remaining > 2 * this.#minDelay) {
        this.#at(remaining / 2, () => void this.#renew());
      } else {
        this.#schedule({ ttlMs: Math.max(remaining, 1), renewable: false }, true);
      }
    }
  }

  async #reacquire(): Promise<void> {
    try {
      const state = await this.#o.reacquire?.();
      if (this.#stopped || state === undefined) return;
      this.#baselineTtl = state.ttlMs;
      safe(this.#o.onRenew, state);
      this.#schedule(state, false);
    } catch (err) {
      if (this.#stopped) return;
      safe(this.#o.onError, err);
      const remaining = this.#remaining();
      if (remaining > 2 * this.#minDelay) {
        this.#at(remaining / 2, () => void this.#reacquire());
      } else {
        this.#at(Math.max(remaining, 0), () => {
          this.#expire();
        });
      }
    }
  }

  #expire(): void {
    if (this.#expired) return;
    this.#expired = true;
    this.#stopped = true;
    this.#clear();
    safe(this.#o.onExpire);
  }
}
