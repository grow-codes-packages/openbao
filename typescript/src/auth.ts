// Service-owned. Auth methods (token, AppRole, Kubernetes, JWT, userpass), token self-service
// and automatic token renewal (API.md §3).

import { readFile } from "node:fs/promises";
import { ConfigError, Secret, ValidationError } from "./core/index.js";
import {
  type ClientContext,
  type Envelope,
  type WireAuth,
  compact,
  encodePath,
  optDuration,
  parseTime,
  requireText,
  secondsToMs,
  stringMap,
  strings,
  trimSlashes,
  unexpected,
} from "./http.js";
import { type LeaseState, RenewalLoop, type RenewalOptions } from "./renewal.js";

/** Per-call options. */
export interface AuthCallOptions {
  /** Cancels the call (`CancelledError`). */
  signal?: AbortSignal;
}

/** Result of a login or token creation. The token is redacted in every string form. */
export interface AuthInfo {
  /** The client token. */
  clientToken: Secret;
  /** Token accessor (redacted: it can revoke the token). */
  accessor?: Secret;
  /** All policies of the token. */
  policies: string[];
  /** Policies attached to the token itself. */
  tokenPolicies: string[];
  /** Auth metadata (e.g. `role_name`, `username`). */
  metadata: Record<string, string>;
  /** Token TTL in ms (`0` = no expiry). */
  leaseDurationMs: number;
  /** Whether the token can be renewed. */
  renewable: boolean;
  /** Identity entity id. */
  entityId: string;
  /** `service` or `batch`. */
  tokenType: string;
  /** Whether the token has no parent. */
  orphan: boolean;
  /** Remaining uses (`0` = unlimited). */
  numUses: number;
}

/** Token properties from `lookupSelf()`. */
export interface TokenInfo {
  /** The token id (redacted). */
  id: Secret;
  /** Token accessor (redacted). */
  accessor?: Secret;
  /** Attached policies. */
  policies: string[];
  /** Remaining TTL in ms (`0` = no expiry). */
  ttlMs: number;
  /** TTL at creation in ms. */
  creationTtlMs: number;
  /** Creation time. */
  creationTime: Date | null;
  /** Expiry time, `null` when it never expires. */
  expireTime: Date | null;
  /** Issue time. */
  issueTime: Date | null;
  /** Whether it can be renewed. */
  renewable: boolean;
  /** Display name (`token-<name>`). */
  displayName: string;
  /** Token metadata. */
  meta: Record<string, string>;
  /** Remaining uses (`0` = unlimited). */
  numUses: number;
  /** Whether the token has no parent. */
  orphan: boolean;
  /** Creation path, e.g. `auth/token/create`. */
  path: string;
  /** `service` or `batch`. */
  type: string;
  /** Explicit maximum TTL in ms (`0` = none). */
  explicitMaxTtlMs: number;
  /** Identity entity id (empty when none). */
  entityId: string;
}

/** Options of `createToken()`. */
export interface CreateTokenOptions extends AuthCallOptions {
  /** Attached policies. */
  policies?: string[];
  /** TTL in ms. */
  ttlMs?: number;
  /** Hard maximum TTL in ms. */
  explicitMaxTtlMs?: number;
  /** Whether it can be renewed. */
  renewable?: boolean;
  /** Display name (`token-<name>`). */
  displayName?: string;
  /** Token metadata. */
  meta?: Record<string, string>;
  /** Number of uses (`0` = unlimited). */
  numUses?: number;
  /** Create an orphan token (needs root or sudo). */
  noParent?: boolean;
  /** Do not attach the `default` policy. */
  noDefaultPolicy?: boolean;
  /** Periodic token period in ms. */
  periodMs?: number;
  /** Token role (`auth/token/create/<role>`). */
  role?: string;
}

/** Context handed to an {@link AuthMethod}. */
export interface LoginContext {
  /** Sends `POST auth/<mount>/<path>` without a token and returns the `auth` block. */
  post(path: string, body: Record<string, unknown>, operation: string): Promise<AuthInfo>;
  /** Looks up the given token (used by {@link TokenAuth}). */
  lookup(token: Secret): Promise<TokenInfo>;
  /** Cancels the call (`CancelledError`). */
  signal?: AbortSignal;
}

/** An auth method that can log in (`client.auth.login(method)`). */
export interface AuthMethod {
  /** Short method name, e.g. `approle`. */
  readonly method: string;
  /** Performs the login and returns the new token. */
  login(context: LoginContext): Promise<AuthInfo>;
}

/** Uses an existing token (`X-Vault-Token`). `login()` checks it with `lookup-self`. */
export class TokenAuth implements AuthMethod {
  readonly method = "token";
  readonly #token: Secret;

  constructor(token: string | Secret) {
    const t = Secret.from(token);
    if (t === undefined) throw new ConfigError("TokenAuth: token must not be empty");
    this.#token = t;
  }

  async login(context: LoginContext): Promise<AuthInfo> {
    const info = await context.lookup(this.#token);
    return {
      clientToken: this.#token,
      ...(info.accessor === undefined ? {} : { accessor: info.accessor }),
      policies: info.policies,
      tokenPolicies: info.policies,
      metadata: info.meta,
      leaseDurationMs: info.ttlMs,
      renewable: info.renewable,
      entityId: info.entityId,
      tokenType: info.type,
      orphan: info.orphan,
      numUses: info.numUses,
    };
  }

  toString(): string {
    return "TokenAuth([REDACTED])";
  }
}

/** Options shared by the login methods. */
export interface MountOptions {
  /** Auth mount path (defaults per method: `approle`, `kubernetes`, `jwt`, `userpass`). */
  mount?: string;
}

/** AppRole login: `POST auth/<mount>/login {role_id, secret_id}`. */
export class AppRoleAuth implements AuthMethod {
  readonly method = "approle";
  /** Mount path. */
  readonly mount: string;
  /** AppRole role id. */
  readonly roleId: string;
  readonly #secretId: Secret | undefined;

  /** `secretId` may be omitted for roles with `bind_secret_id=false`. */
  constructor(roleId: string, secretId?: string | Secret, options: MountOptions = {}) {
    this.roleId = requireText(roleId, "roleId", "AppRoleAuth");
    this.#secretId = Secret.from(secretId);
    this.mount = trimSlashes(options.mount ?? "approle");
  }

  login(context: LoginContext): Promise<AuthInfo> {
    return context.post(
      encodePath("auth", this.mount, "login"),
      compact({ role_id: this.roleId, secret_id: this.#secretId?.reveal() }),
      `auth.approle.login ${this.mount}`,
    );
  }

  toString(): string {
    return `AppRoleAuth(${this.mount}, roleId=${this.roleId}, secretId=[REDACTED])`;
  }
}

/** Options of {@link KubernetesAuth}. */
export interface KubernetesAuthOptions extends MountOptions {
  /** Service account token file (default {@link KubernetesAuth.DEFAULT_JWT_PATH}). */
  jwtPath?: string;
  /** Service account token value (instead of reading `jwtPath`). */
  jwt?: string | Secret;
}

/** Kubernetes login: `POST auth/<mount>/login {role, jwt}` with the service account token. */
export class KubernetesAuth implements AuthMethod {
  /** Default service account token path inside a pod. */
  static readonly DEFAULT_JWT_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/token";
  readonly method = "kubernetes";
  /** Mount path. */
  readonly mount: string;
  /** Role name. */
  readonly role: string;
  /** Service account token file read at login. */
  readonly jwtPath: string;
  readonly #jwt: Secret | undefined;

  constructor(role: string, options: KubernetesAuthOptions | string = {}) {
    const opts = typeof options === "string" ? { jwtPath: options } : options;
    this.role = requireText(role, "role", "KubernetesAuth");
    this.jwtPath = opts.jwtPath ?? KubernetesAuth.DEFAULT_JWT_PATH;
    this.#jwt = Secret.from(opts.jwt);
    this.mount = trimSlashes(opts.mount ?? "kubernetes");
  }

  async login(context: LoginContext): Promise<AuthInfo> {
    let jwt = this.#jwt?.reveal();
    if (jwt === undefined) {
      try {
        jwt = (await readFile(this.jwtPath, "utf8")).trim();
      } catch {
        throw new ConfigError(
          `auth.kubernetes.login: cannot read the service account token at ${this.jwtPath}`,
        );
      }
      if (jwt === "") {
        throw new ConfigError(`auth.kubernetes.login: ${this.jwtPath} is empty`);
      }
    }
    return context.post(
      encodePath("auth", this.mount, "login"),
      { role: this.role, jwt },
      `auth.kubernetes.login ${this.mount}`,
    );
  }

  toString(): string {
    return `KubernetesAuth(${this.mount}, role=${this.role})`;
  }
}

/** JWT/OIDC login with a JWT: `POST auth/<mount>/login {role, jwt}`. */
export class JwtAuth implements AuthMethod {
  readonly method = "jwt";
  /** Mount path. */
  readonly mount: string;
  /** Role name. */
  readonly role: string;
  readonly #jwt: Secret;

  constructor(role: string, jwt: string | Secret, options: MountOptions = {}) {
    this.role = requireText(role, "role", "JwtAuth");
    const token = Secret.from(jwt);
    if (token === undefined) throw new ConfigError("JwtAuth: jwt must not be empty");
    this.#jwt = token;
    this.mount = trimSlashes(options.mount ?? "jwt");
  }

  login(context: LoginContext): Promise<AuthInfo> {
    return context.post(
      encodePath("auth", this.mount, "login"),
      { role: this.role, jwt: this.#jwt.reveal() },
      `auth.jwt.login ${this.mount}`,
    );
  }

  toString(): string {
    return `JwtAuth(${this.mount}, role=${this.role}, jwt=[REDACTED])`;
  }
}

/** Username/password login: `POST auth/<mount>/login/<username> {password}`. */
export class UserpassAuth implements AuthMethod {
  readonly method = "userpass";
  /** Mount path. */
  readonly mount: string;
  /** User name. */
  readonly username: string;
  readonly #password: Secret;

  constructor(username: string, password: string | Secret, options: MountOptions = {}) {
    this.username = requireText(username, "username", "UserpassAuth");
    const pw = Secret.from(password);
    if (pw === undefined) throw new ConfigError("UserpassAuth: password must not be empty");
    this.#password = pw;
    this.mount = trimSlashes(options.mount ?? "userpass");
  }

  login(context: LoginContext): Promise<AuthInfo> {
    return context.post(
      encodePath("auth", this.mount, "login", this.username),
      { password: this.#password.reveal() },
      `auth.userpass.login ${this.mount}`,
    );
  }

  toString(): string {
    return `UserpassAuth(${this.mount}, username=${this.username}, password=[REDACTED])`;
  }
}

/** Options of {@link TokenRenewer}. */
export interface TokenRenewerOptions extends RenewalOptions {
  /**
   * Logs in again with this method when the token cannot be renewed any more (not renewable or
   * maximum TTL reached). Without it, `onExpire` is called at expiry.
   */
  reauth?: AuthMethod;
  /** Called after every renewal or re-login with the new token TTL. */
  onRenew?: (info: TokenRenewal) => void;
}

/** One renewal or re-login seen by {@link TokenRenewerOptions.onRenew}. */
export interface TokenRenewal extends LeaseState {
  /** `true` when the token was replaced by a new login. */
  reauthenticated: boolean;
}

/** Options of `login()`. */
export interface LoginOptions extends AuthCallOptions {
  /** Use the new token for this client (default `true`). */
  setToken?: boolean;
  /**
   * Starts a {@link TokenRenewer} for the new token (re-login with the same method when it can
   * no longer be renewed). `true` uses the defaults. Default `false`.
   */
  autoRenew?: boolean | Omit<TokenRenewerOptions, "reauth">;
}

/**
 * Renews the client token at 2/3 of its TTL (`renew-self`). When the token cannot be renewed
 * any more it logs in again (`reauth`) or calls `onExpire` once at expiry. Stopped by
 * `stop()` or `client.close()`.
 */
export class TokenRenewer {
  readonly #auth: AuthApi;
  readonly #loop: RenewalLoop<TokenRenewal>;
  #started = false;

  constructor(auth: AuthApi, options: TokenRenewerOptions = {}) {
    this.#auth = auth;
    const reauth = options.reauth;
    this.#loop = new RenewalLoop<TokenRenewal>({
      ...options,
      renew: async (incrementMs) => {
        const info = await auth.renewSelf(incrementMs);
        return { ttlMs: info.leaseDurationMs, renewable: info.renewable, reauthenticated: false };
      },
      ...(reauth === undefined
        ? {}
        : {
            reacquire: async () => {
              const info = await auth.login(reauth);
              return {
                ttlMs: info.leaseDurationMs,
                renewable: info.renewable,
                reauthenticated: true,
              };
            },
          }),
    });
  }

  /**
   * Starts renewing. Without `initial`, the TTL is read with `lookupSelf()`. A token without
   * TTL (e.g. root) needs no renewal; the renewer then stays idle.
   */
  async start(initial?: LeaseState, options: AuthCallOptions = {}): Promise<void> {
    if (this.#started) return;
    this.#started = true;
    let state = initial;
    if (state === undefined) {
      const info = await this.#auth.lookupSelf(options);
      state = { ttlMs: info.ttlMs, renewable: info.renewable };
    }
    this.#loop.start(state);
  }

  /** Stops renewing. Idempotent. */
  stop(): void {
    this.#loop.stop();
    this.#auth.forget(this);
  }

  /** Whether the renewer is active. */
  get running(): boolean {
    return this.#started && this.#loop.running;
  }

  /** Whether `onExpire` fired. */
  get expired(): boolean {
    return this.#loop.expired;
  }

  /** Expiry of the current token (ms since epoch), `0` when it never expires or is unknown. */
  get expiresAt(): number {
    return this.#loop.expiresAt;
  }
}

function toAuthInfo(auth: WireAuth): AuthInfo {
  const accessor = Secret.from(auth.accessor);
  return {
    clientToken: new Secret(auth.client_token),
    ...(accessor === undefined ? {} : { accessor }),
    policies: strings(auth.policies),
    tokenPolicies: strings(auth.token_policies),
    metadata: stringMap(auth.metadata),
    leaseDurationMs: secondsToMs(auth.lease_duration),
    renewable: auth.renewable === true,
    entityId: auth.entity_id ?? "",
    tokenType: auth.token_type ?? "",
    orphan: auth.orphan === true,
    numUses: auth.num_uses ?? 0,
  };
}

/** Converts the `auth` block of an envelope; throws when it is missing. @internal */
export function authFromEnvelope(env: Envelope | undefined, operation: string): AuthInfo {
  const auth = env?.auth;
  if (auth === undefined || auth === null || typeof auth.client_token !== "string") {
    throw unexpected(operation, "response has no auth block");
  }
  return toAuthInfo(auth);
}

function toTokenInfo(d: Record<string, unknown>): TokenInfo {
  const accessor = Secret.from(typeof d.accessor === "string" ? d.accessor : undefined);
  return {
    id: new Secret(typeof d.id === "string" ? d.id : ""),
    ...(accessor === undefined ? {} : { accessor }),
    policies: strings(d.policies),
    ttlMs: secondsToMs(d.ttl),
    creationTtlMs: secondsToMs(d.creation_ttl),
    creationTime: parseTime(d.creation_time),
    expireTime: parseTime(d.expire_time),
    issueTime: parseTime(d.issue_time),
    renewable: d.renewable === true,
    displayName: typeof d.display_name === "string" ? d.display_name : "",
    meta: stringMap(d.meta),
    numUses: typeof d.num_uses === "number" ? d.num_uses : 0,
    orphan: d.orphan === true,
    path: typeof d.path === "string" ? d.path : "",
    type: typeof d.type === "string" ? d.type : "",
    explicitMaxTtlMs: secondsToMs(d.explicit_max_ttl),
    entityId: typeof d.entity_id === "string" ? d.entity_id : "",
  };
}

/** Token self-service, logins and renewal: `client.auth`. */
export class AuthApi {
  readonly #ctx: ClientContext;
  readonly #renewers = new Set<TokenRenewer>();

  /** @internal */
  constructor(ctx: ClientContext) {
    this.#ctx = ctx;
  }

  /**
   * Logs in with an auth method and (by default) uses the new token for this client.
   * Failed logins raise `AuthenticationError`.
   */
  async login(method: AuthMethod, options: LoginOptions = {}): Promise<AuthInfo> {
    const http = this.#ctx.http;
    const signal = options.signal;
    const context: LoginContext = {
      post: async (path, body, operation) => {
        const env = await http.envelope({
          method: "POST",
          path,
          operation,
          json: body,
          token: null,
          signal,
          login: true,
        });
        return authFromEnvelope(env, operation);
      },
      lookup: (token) => this.#lookup(token.reveal(), signal, true),
      ...(signal === undefined ? {} : { signal }),
    };
    const info = await method.login(context);
    if (options.setToken !== false) this.#ctx.tokens.set(info.clientToken);
    if (options.autoRenew !== undefined && options.autoRenew !== false) {
      const renewOpts = options.autoRenew === true ? {} : options.autoRenew;
      const renewer = this.#track(new TokenRenewer(this, { ...renewOpts, reauth: method }));
      await renewer.start({ ttlMs: info.leaseDurationMs, renewable: info.renewable });
    }
    return info;
  }

  async #lookup(token: string | undefined, signal?: AbortSignal, login = false) {
    const data = await this.#ctx.http.data<Record<string, unknown>>({
      method: "GET",
      path: "auth/token/lookup-self",
      operation: "auth.lookupSelf",
      ...(token === undefined ? {} : { token }),
      signal,
      login,
    });
    return toTokenInfo(data);
  }

  /** Properties of the client token: `GET auth/token/lookup-self`. */
  lookupSelf(options: AuthCallOptions = {}): Promise<TokenInfo> {
    return this.#lookup(undefined, options.signal);
  }

  /**
   * Renews the client token: `POST auth/token/renew-self`. `incrementMs` requests a TTL; the
   * granted TTL is `leaseDurationMs` (capped by the maximum TTL). Non-renewable tokens raise
   * `ValidationError`.
   */
  async renewSelf(incrementMs?: number, options: AuthCallOptions = {}): Promise<AuthInfo> {
    const env = await this.#ctx.http.envelope({
      method: "POST",
      path: "auth/token/renew-self",
      operation: "auth.renewSelf",
      json: compact({ increment: optDuration(incrementMs) }),
      signal: options.signal,
    });
    return authFromEnvelope(env, "auth.renewSelf");
  }

  /**
   * Revokes the client token (`POST auth/token/revoke-self`) and forgets it, so later calls
   * send no token until the next login or `setToken()`.
   */
  async revokeSelf(options: AuthCallOptions = {}): Promise<void> {
    await this.#ctx.http.send({
      method: "POST",
      path: "auth/token/revoke-self",
      operation: "auth.revokeSelf",
      signal: options.signal,
    });
    this.stopRenewers();
    this.#ctx.tokens.set(undefined);
  }

  /** Creates a child (or orphan) token: `POST auth/token/create[/<role>]`. */
  async createToken(options: CreateTokenOptions = {}): Promise<AuthInfo> {
    const path =
      options.role === undefined
        ? "auth/token/create"
        : encodePath("auth/token/create", options.role);
    if (options.numUses !== undefined && options.numUses < 0) {
      throw new ValidationError("auth.createToken: numUses must be >= 0");
    }
    const env = await this.#ctx.http.envelope({
      method: "POST",
      path,
      operation: "auth.createToken",
      json: compact({
        policies: options.policies,
        ttl: optDuration(options.ttlMs),
        explicit_max_ttl: optDuration(options.explicitMaxTtlMs),
        renewable: options.renewable,
        display_name: options.displayName,
        meta: options.meta,
        num_uses: options.numUses,
        no_parent: options.noParent,
        no_default_policy: options.noDefaultPolicy,
        period: optDuration(options.periodMs),
      }),
      signal: options.signal,
    });
    return authFromEnvelope(env, "auth.createToken");
  }

  /**
   * Starts a {@link TokenRenewer} for the current client token (reads its TTL with
   * `lookupSelf()`). Stopped by `client.close()`.
   */
  async startRenewer(
    options: TokenRenewerOptions = {},
    callOptions: AuthCallOptions = {},
  ): Promise<TokenRenewer> {
    const renewer = this.#track(new TokenRenewer(this, options));
    try {
      await renewer.start(undefined, callOptions);
    } catch (err) {
      renewer.stop();
      throw err;
    }
    return renewer;
  }

  #track(renewer: TokenRenewer): TokenRenewer {
    this.#renewers.add(renewer);
    return renewer;
  }

  /** @internal */
  forget(renewer: TokenRenewer): void {
    this.#renewers.delete(renewer);
  }

  /** Number of active renewers. */
  get activeRenewers(): number {
    return this.#renewers.size;
  }

  /** Stops every renewer started through this API. Idempotent. */
  stopRenewers(): void {
    for (const r of [...this.#renewers]) r.stop();
  }
}
