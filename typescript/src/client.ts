// Service-owned: generated once by sdk-kit, then maintained in this repository.

import {
  type HealthStatus,
  HttpTransport,
  type QueryValue,
  Secret,
  type TransportOptions,
  healthStatus,
  probeHealth,
} from "./core/index.js";
import { OpenBaoConfig, type OpenBaoConfigOptions } from "./config.js";
import { AuthApi } from "./auth.js";
import { Database } from "./database.js";
import {
  type ClientContext,
  type TokenHolder,
  VaultHttp,
  encodePath,
  parseTime,
  secondsToMs,
  strings,
  trimSlashes,
} from "./http.js";
import { KvMount, KvV1, KvV2 } from "./kv.js";
import { LeaseManager } from "./leases.js";
import { Pki } from "./pki.js";
import { OpenBaoSecretsProvider, type OpenBaoSecretsOptions } from "./provider.js";
import { Sys } from "./sys.js";
import { Transit } from "./transit.js";
import { Wrapping, type WrapInfo } from "./wrapping.js";

/** Per-call options. */
export interface CallOptions {
  /** Cancels the call (`CancelledError`). */
  signal?: AbortSignal;
}

/** Test seams (undici `MockAgent`, fake sleep). Not part of the stable API. */
export type ClientInternals = Pick<TransportOptions, "dispatcher" | "sleep" | "now">;

/** Options of {@link OpenBaoClient.request}. */
export interface RawRequestOptions extends CallOptions {
  /** Query parameters. */
  query?: Readonly<Record<string, QueryValue>>;
  /** JSON body. */
  json?: unknown;
  /** Extra headers. */
  headers?: Readonly<Record<string, string>>;
  /** Sends the LIST operation (`GET ...?list=true`). */
  list?: boolean;
  /** Wraps the response in a single-use token valid for this many ms. */
  wrapTtlMs?: number;
  /** Mark a POST as safe to retry. */
  idempotent?: boolean;
}

/** Result of {@link OpenBaoClient.request}: the decoded OpenBao envelope. */
export interface RawResponse<T = Record<string, unknown>> {
  /** HTTP status (204 = no content). */
  status: number;
  /** The response data (`null` when the response had none). */
  data: T | null;
  /** Lease id (empty when the response has no lease). */
  leaseId: string;
  /** Lease TTL in ms. */
  leaseDurationMs: number;
  /** Whether it can be renewed. */
  renewable: boolean;
  /** Server warnings. */
  warnings: string[];
  /** Set when the response was wrapped (`wrapTtlMs`). */
  wrapInfo?: WrapInfo;
}

/**
 * Client for OpenBao.
 *
 * ```ts
 * const client = OpenBaoClient.fromEnv();          // BAO_ADDR / BAO_TOKEN / GROW_OPENBAO_*
 * await client.kv().write("app/db", { password: "s3cret" });
 * const secret = await client.kv().read("app/db");
 * await client.close();
 * ```
 */
export class OpenBaoClient {
  /** The immutable configuration. */
  readonly config: OpenBaoConfig;
  /** Logins, token self-service and token renewal. */
  readonly auth: AuthApi;
  /** System backend (health, seal status, policies, mounts, auth methods, AppRole admin). */
  readonly sys: Sys;
  /** Response wrapping. */
  readonly wrapping: Wrapping;
  /** Lease renew/revoke/lookup and automatic lease renewal. */
  readonly leases: LeaseManager;
  readonly #transport: HttpTransport;
  readonly #http: VaultHttp;
  readonly #ctx: ClientContext;
  readonly #kvMounts = new Map<string, KvMount>();
  readonly #providers = new Set<OpenBaoSecretsProvider>();
  #token: Secret | undefined;
  #closed = false;

  /** Accepts a {@link OpenBaoConfig} or plain options. */
  constructor(config: OpenBaoConfigOptions = {}, internals: ClientInternals = {}) {
    const cfg = OpenBaoConfig.from(config);
    this.config = cfg;
    this.#token = cfg.token;
    this.#transport = new HttpTransport({
      ...internals,
      config: cfg,
      knownSecrets: () => [...cfg.knownSecrets(), this.#token],
    });
    const tokens: TokenHolder = {
      get: () => this.#token,
      set: (t) => {
        this.#token = t;
      },
    };
    this.#http = new VaultHttp(this.#transport, tokens, cfg.namespace);
    this.#ctx = { http: this.#http, config: cfg, tokens };
    this.auth = new AuthApi(this.#ctx);
    this.sys = new Sys(this.#ctx);
    this.wrapping = new Wrapping(this.#ctx);
    this.leases = new LeaseManager(this.#ctx);
  }

  /** Builds a client from `GROW_OPENBAO_*` and `BAO_*`/`VAULT_*` environment variables. */
  static fromEnv(overrides: OpenBaoConfigOptions = {}): OpenBaoClient {
    return new OpenBaoClient(OpenBaoConfig.fromEnv(overrides));
  }

  /** The shared HTTP transport. @internal */
  get transport(): HttpTransport {
    return this.#transport;
  }

  /** Internal module context (HTTP layer, config, token holder). @internal */
  get context(): ClientContext {
    return this.#ctx;
  }

  /** The current client token (from the config, a login or {@link setToken}). */
  get token(): Secret | undefined {
    return this.#token;
  }

  /** Replaces the client token (`undefined` removes it). */
  setToken(token: string | Secret | undefined): void {
    this.#token = Secret.from(token);
  }

  /** Whether {@link close} was called. */
  get closed(): boolean {
    return this.#closed;
  }

  /**
   * KV mount with auto-detected version (default mount `config.kvMount`). The same instance is
   * returned for the same mount.
   */
  kv(mount: string = this.config.kvMount): KvMount {
    const key = trimSlashes(mount);
    let kv = this.#kvMounts.get(key);
    if (kv === undefined) {
      kv = new KvMount(this.#ctx, key, this.config.kvVersion);
      this.#kvMounts.set(key, kv);
    }
    return kv;
  }

  /** KV version 1 mount (no detection). */
  kvV1(mount: string = this.config.kvMount): KvV1 {
    return new KvV1(this.#ctx, mount);
  }

  /** KV version 2 mount (no detection). */
  kvV2(mount: string = this.config.kvMount): KvV2 {
    return new KvV2(this.#ctx, mount);
  }

  /** Transit engine (default mount `transit`). */
  transit(mount = "transit"): Transit {
    return new Transit(this.#ctx, mount);
  }

  /** Database engine (default mount `database`). */
  database(mount = "database"): Database {
    return new Database(this.#ctx, mount);
  }

  /** PKI engine (default mount `pki`). */
  pki(mount = "pki"): Pki {
    return new Pki(this.#ctx, mount);
  }

  /**
   * {@link SecretsProvider} over a KV mount (default `config.kvMount`). `client.close()` stops
   * its watchers.
   */
  secrets(options: OpenBaoSecretsOptions = {}): OpenBaoSecretsProvider {
    const provider: OpenBaoSecretsProvider = new OpenBaoSecretsProvider(
      this.kv(options.mount ?? this.config.kvMount),
      options,
      () => this.#providers.delete(provider),
    );
    this.#providers.add(provider);
    return provider;
  }

  /**
   * Calls any OpenBao API path (`/v1/<path>`) with the client token, namespace, retries and
   * error mapping. Use it for endpoints this SDK has no method for.
   */
  async request<T = Record<string, unknown>>(
    method: "GET" | "POST" | "PUT" | "PATCH" | "DELETE",
    path: string,
    options: RawRequestOptions = {},
  ): Promise<RawResponse<T>> {
    const res = await this.#http.call<T>({
      method,
      path: encodePath(path),
      operation: `${method} ${trimSlashes(path)}`,
      ...options,
    });
    const env = res.body ?? {};
    const out: RawResponse<T> = {
      status: res.status,
      data: env.data ?? null,
      leaseId: env.lease_id ?? "",
      leaseDurationMs: secondsToMs(env.lease_duration),
      renewable: env.renewable === true,
      warnings: strings(env.warnings),
    };
    const w = env.wrap_info;
    if (w !== undefined && w !== null) {
      const accessor = Secret.from(w.accessor);
      out.wrapInfo = {
        token: new Secret(w.token),
        ...(accessor === undefined ? {} : { accessor }),
        ttlMs: secondsToMs(w.ttl),
        creationTime: parseTime(w.creation_time),
        creationPath: w.creation_path ?? "",
      };
    }
    return out;
  }

  /**
   * Unauthenticated health: `GET /v1/sys/health` (answers 200 in every node state). `healthy`
   * is `true` only for an active, unsealed node; `status` is `active`, `standby`,
   * `perfstandby`, `sealed` or `uninitialized` (`unreachable`/`unhealthy` on errors). Never
   * throws except for `CANCELLED` and `CONFIG`.
   */
  health(options: CallOptions = {}): Promise<HealthStatus> {
    return probeHealth(async () => {
      const h = await this.sys.health(options);
      return healthStatus(
        h.state,
        {
          version: h.version,
          initialized: h.initialized,
          sealed: h.sealed,
          standby: h.standby,
          clusterName: h.clusterName === "" ? undefined : h.clusterName,
        },
        h.state === "active",
      );
    });
  }

  /**
   * Authenticated round trip (`GET /v1/auth/token/lookup-self`, allowed for every valid
   * token). Returns the latency in ms; a missing, invalid or revoked token raises
   * `AuthenticationError`.
   */
  async ping(options: CallOptions = {}): Promise<number> {
    const start = performance.now();
    await this.#http.send({
      method: "GET",
      path: "auth/token/lookup-self",
      operation: "ping",
      signal: options.signal,
      // lookup-self is allowed for every valid token: 400/401/403 mean bad credentials.
      login: true,
    });
    return performance.now() - start;
  }

  /** Server version from `sys/health` (e.g. `2.7.2`). */
  async serverVersion(options: CallOptions = {}): Promise<string> {
    return this.sys.version(options);
  }

  /**
   * Stops token renewers, managed leases and secret watchers, then releases connections.
   * Idempotent.
   */
  async close(): Promise<void> {
    if (this.#closed) return;
    this.#closed = true;
    this.auth.stopRenewers();
    await this.leases.stopAll();
    await Promise.all([...this.#providers].map((p) => p.close()));
    await this.#transport.close();
  }
}
