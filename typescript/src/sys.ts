// Service-owned. System backend: health, seal status, leader, version, ACL policies,
// secrets engines, auth methods and AppRole administration (API.md §2, §8).

import { Secret, UnsupportedError } from "./core/index.js";
import {
  type ClientContext,
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

/** Per-call options. */
export interface SysCallOptions {
  /** Cancels the call (`CancelledError`). */
  signal?: AbortSignal;
}

/** Node state from `sys/health`. */
export type NodeState = "active" | "standby" | "perfstandby" | "sealed" | "uninitialized";

/** Raw `sys/health` answer (never an error for sealed/standby/uninitialised nodes). */
export interface HealthResponse {
  /** Derived node state. */
  state: NodeState;
  /** Whether the server is initialised. */
  initialized: boolean;
  /** Whether the server is sealed. */
  sealed: boolean;
  /** Whether this node is a standby. */
  standby: boolean;
  /** Whether this node is a performance standby. */
  performanceStandby: boolean;
  /** Server version, e.g. `2.7.2`. */
  version: string;
  /** Cluster name. */
  clusterName: string;
  /** Cluster id. */
  clusterId: string;
  /** Server clock. */
  serverTime: Date | null;
}

/** `sys/seal-status`. */
export interface SealStatus {
  /** `shamir`, `static`, `transit`, … */
  type: string;
  /** Whether the server is initialised. */
  initialized: boolean;
  /** Whether the server is sealed. */
  sealed: boolean;
  /** Unseal threshold. */
  threshold: number;
  /** Number of key shares. */
  shares: number;
  /** Unseal keys provided so far. */
  progress: number;
  /** Nonce of the current unseal/rekey operation. */
  nonce: string;
  /** Whether the seal uses recovery keys (auto-unseal). */
  recoverySeal: boolean;
  /** Server version, e.g. `2.7.2`. */
  version: string;
  /** Cluster name. */
  clusterName: string;
  /** Cluster id. */
  clusterId: string;
  /** Storage backend, e.g. `raft`. */
  storageType: string;
}

/** `sys/leader`. */
export interface LeaderStatus {
  /** Whether high availability is enabled. */
  haEnabled: boolean;
  /** Whether this node is the leader. */
  isSelf: boolean;
  /** Time the leader became active. */
  activeTime: Date | null;
  /** API address of the leader. */
  leaderAddress: string;
  /** Cluster address of the leader. */
  leaderClusterAddress: string;
}

/** An ACL policy. */
export interface Policy {
  /** Policy name. */
  name: string;
  /** HCL text. */
  policy: string;
}

/** A secrets engine or auth method mount. */
export interface MountInfo {
  /** Engine/method type, e.g. `kv`, `approle`. */
  type: string;
  /** Human-readable description. */
  description: string;
  /** Accessor (redacted: it can look up or revoke the token). */
  accessor: string;
  /** Mount options (e.g. `{ version: "2" }` for KV v2). */
  options: Record<string, string>;
  /** Mount config (TTLs etc., values as strings). */
  config: Record<string, string>;
  /** Local to this cluster (not replicated). */
  local: boolean;
  /** Seal-wrap the mount's data. */
  sealWrap: boolean;
}

/** Options of `enableSecretsEngine()`. */
export interface EnableEngineOptions extends SysCallOptions {
  /** Human-readable description. */
  description?: string;
  /** Engine options, e.g. `{ version: "2" }` for KV v2. */
  options?: Record<string, string>;
  /** Default lease TTL in ms. */
  defaultLeaseTtlMs?: number;
  /** Maximum lease TTL in ms. */
  maxLeaseTtlMs?: number;
  /** Local to this cluster (not replicated). */
  local?: boolean;
  /** Seal-wrap the mount's data. */
  sealWrap?: boolean;
}

/** Options of `enableAuthMethod()`. */
export interface EnableAuthOptions extends SysCallOptions {
  /** Human-readable description. */
  description?: string;
  /** Default lease TTL in ms. */
  defaultLeaseTtlMs?: number;
  /** Maximum lease TTL in ms. */
  maxLeaseTtlMs?: number;
  /** Local to this cluster (not replicated). */
  local?: boolean;
}

/** Options of `createAppRole()`. */
export interface AppRoleOptions extends SysCallOptions {
  /** AppRole mount (default `approle`). */
  mount?: string;
  /** Policies attached to the token itself. */
  tokenPolicies?: string[];
  /** Token TTL in ms. */
  tokenTtlMs?: number;
  /** Token maximum TTL in ms. */
  tokenMaxTtlMs?: number;
  /** Secret id TTL in ms (`0` = never expires). */
  secretIdTtlMs?: number;
  /** Uses per secret id (`0` = unlimited). */
  secretIdNumUses?: number;
  /** Require a secret id at login (default server-side `true`). */
  bindSecretId?: boolean;
  /** `service` or `batch`. */
  tokenType?: string;
}

/** Options of the AppRole calls that only need the mount. */
export interface AppRoleMountOptions extends SysCallOptions {
  /** AppRole mount (default `approle`). */
  mount?: string;
}

/** Options of `generateSecretId()`. */
export interface SecretIdOptions extends AppRoleMountOptions {
  /** Metadata attached to the secret id (and to tokens from it). */
  metadata?: Record<string, string>;
  /** CIDRs allowed to use the secret id. */
  cidrList?: string[];
  /** TTL in ms. */
  ttlMs?: number;
  /** Number of uses. */
  numUses?: number;
}

/** A generated AppRole secret id (redacted in every string form). */
export interface SecretIdInfo {
  /** AppRole secret id (redacted in every string form). */
  secretId: Secret;
  /** Secret id accessor (redacted). */
  secretIdAccessor: Secret;
  /** Uses left (`0` = unlimited). */
  secretIdNumUses: number;
  /** TTL in ms (`0` = never expires). */
  secretIdTtlMs: number;
}

/** Query parameters that make `sys/health` answer 200 for every node state. */
export const HEALTH_QUERY = Object.freeze({
  uninitcode: 200,
  sealedcode: 200,
  standbycode: 200,
  performancestandbycode: 200,
});

function str(v: unknown): string {
  return typeof v === "string" ? v : "";
}

function num(v: unknown): number {
  return typeof v === "number" ? v : 0;
}

function toMount(raw: unknown): MountInfo {
  const m = (raw ?? {}) as Record<string, unknown>;
  return {
    type: str(m.type),
    description: str(m.description),
    accessor: str(m.accessor),
    options: stringMap(m.options),
    config: stringMap(m.config),
    local: m.local === true,
    sealWrap: m.seal_wrap === true,
  };
}

function toMounts(data: Record<string, unknown>): Record<string, MountInfo> {
  const out: Record<string, MountInfo> = {};
  for (const [path, raw] of Object.entries(data)) {
    if (raw !== null && typeof raw === "object" && "type" in raw) out[path] = toMount(raw);
  }
  return out;
}

/** Converts a raw `sys/health` body. @internal */
export function toHealth(d: Record<string, unknown>): HealthResponse {
  const initialized = d.initialized === true;
  const sealed = d.sealed === true;
  const standby = d.standby === true;
  const performanceStandby = d.performance_standby === true;
  const state: NodeState = !initialized
    ? "uninitialized"
    : sealed
      ? "sealed"
      : performanceStandby
        ? "perfstandby"
        : standby
          ? "standby"
          : "active";
  return {
    state,
    initialized,
    sealed,
    standby,
    performanceStandby,
    version: str(d.version),
    clusterName: str(d.cluster_name),
    clusterId: str(d.cluster_id),
    serverTime: parseTime(d.server_time_utc),
  };
}

/** Converts a raw seal-status body. @internal */
export function toSealStatus(d: Record<string, unknown>): SealStatus {
  return {
    type: str(d.type),
    initialized: d.initialized === true,
    sealed: d.sealed === true,
    threshold: num(d.t),
    shares: num(d.n),
    progress: num(d.progress),
    nonce: str(d.nonce),
    recoverySeal: d.recovery_seal === true,
    version: str(d.version),
    clusterName: str(d.cluster_name),
    clusterId: str(d.cluster_id),
    storageType: str(d.storage_type),
  };
}

/** System backend: `client.sys`. Most write calls need a privileged (root/sudo) token. */
export class Sys {
  readonly #ctx: ClientContext;

  /** @internal */
  constructor(ctx: ClientContext) {
    this.#ctx = ctx;
  }

  async #raw(path: string, op: string, signal?: AbortSignal, query?: Record<string, number>) {
    const res = await this.#ctx.http.call<never>({
      method: "GET",
      path,
      operation: op,
      signal,
      ...(query === undefined ? {} : { query }),
    });
    const body = res.body as unknown;
    if (body === undefined || body === null || typeof body !== "object") {
      throw unexpected(op, "empty response body");
    }
    return body as Record<string, unknown>;
  }

  /** `GET sys/health` (unauthenticated). Sealed, standby and uninitialised nodes are no error. */
  async health(options: SysCallOptions = {}): Promise<HealthResponse> {
    return toHealth(await this.#raw("sys/health", "sys.health", options.signal, HEALTH_QUERY));
  }

  /** `GET sys/seal-status` (unauthenticated). */
  async sealStatus(options: SysCallOptions = {}): Promise<SealStatus> {
    return toSealStatus(await this.#raw("sys/seal-status", "sys.sealStatus", options.signal));
  }

  /** `GET sys/leader` (unauthenticated). */
  async leader(options: SysCallOptions = {}): Promise<LeaderStatus> {
    const d = await this.#raw("sys/leader", "sys.leader", options.signal);
    return {
      haEnabled: d.ha_enabled === true,
      isSelf: d.is_self === true,
      activeTime: parseTime(d.active_time),
      leaderAddress: str(d.leader_address),
      leaderClusterAddress: str(d.leader_cluster_address),
    };
  }

  /** Server version from `sys/health`; `UnsupportedError` when the server reports none. */
  async version(options: SysCallOptions = {}): Promise<string> {
    const h = await this.health(options);
    if (h.version === "") throw new UnsupportedError("sys.version: the server reports no version");
    return h.version;
  }

  /** Creates or replaces an ACL policy: `PUT sys/policies/acl/<name>`. */
  async writePolicy(name: string, policy: string, options: SysCallOptions = {}): Promise<void> {
    const op = `sys.writePolicy ${name}`;
    await this.#ctx.http.send({
      method: "PUT",
      path: encodePath("sys/policies/acl", requireText(name, "name", op)),
      operation: op,
      json: { policy: requireText(policy, "policy", op) },
      signal: options.signal,
    });
  }

  /** Reads an ACL policy; `NotFoundError` when missing. */
  async readPolicy(name: string, options: SysCallOptions = {}): Promise<Policy> {
    const op = `sys.readPolicy ${name}`;
    const d = await this.#ctx.http.data<Record<string, unknown>>({
      method: "GET",
      path: encodePath("sys/policies/acl", requireText(name, "name", op)),
      operation: op,
      signal: options.signal,
    });
    return { name: str(d.name) || name, policy: str(d.policy) };
  }

  /** ACL policy names (includes `default` and `root`). */
  async listPolicies(options: SysCallOptions = {}): Promise<string[]> {
    const d = await this.#ctx.http.data<{ keys?: unknown }>({
      method: "GET",
      path: "sys/policies/acl",
      operation: "sys.listPolicies",
      list: true,
      signal: options.signal,
    });
    return strings(d.keys);
  }

  /** Deletes an ACL policy. */
  async deletePolicy(name: string, options: SysCallOptions = {}): Promise<void> {
    const op = `sys.deletePolicy ${name}`;
    await this.#ctx.http.send({
      method: "DELETE",
      path: encodePath("sys/policies/acl", requireText(name, "name", op)),
      operation: op,
      signal: options.signal,
    });
  }

  /** Secrets engines by path (`"secret/"` → info). */
  async listMounts(options: SysCallOptions = {}): Promise<Record<string, MountInfo>> {
    const d = await this.#ctx.http.data<Record<string, unknown>>({
      method: "GET",
      path: "sys/mounts",
      operation: "sys.listMounts",
      signal: options.signal,
    });
    return toMounts(d);
  }

  /** Enables a secrets engine at `path`. A used path raises `ValidationError`. */
  async enableSecretsEngine(
    path: string,
    type: string,
    options: EnableEngineOptions = {},
  ): Promise<void> {
    const op = `sys.enableSecretsEngine ${path}`;
    const config = compact({
      default_lease_ttl: optDuration(options.defaultLeaseTtlMs),
      max_lease_ttl: optDuration(options.maxLeaseTtlMs),
    });
    await this.#ctx.http.send({
      method: "POST",
      path: encodePath("sys/mounts", requireText(trimSlashes(path), "path", op)),
      operation: op,
      json: compact({
        type: requireText(type, "type", op),
        description: options.description,
        options: options.options,
        config: Object.keys(config).length > 0 ? config : undefined,
        local: options.local,
        seal_wrap: options.sealWrap,
      }),
      signal: options.signal,
    });
  }

  /** Disables (unmounts) a secrets engine; its data is deleted. */
  async disableSecretsEngine(path: string, options: SysCallOptions = {}): Promise<void> {
    const op = `sys.disableSecretsEngine ${path}`;
    await this.#ctx.http.send({
      method: "DELETE",
      path: encodePath("sys/mounts", requireText(trimSlashes(path), "path", op)),
      operation: op,
      signal: options.signal,
    });
  }

  /** Auth methods by path (`"approle/"` → info). */
  async listAuthMethods(options: SysCallOptions = {}): Promise<Record<string, MountInfo>> {
    const d = await this.#ctx.http.data<Record<string, unknown>>({
      method: "GET",
      path: "sys/auth",
      operation: "sys.listAuthMethods",
      signal: options.signal,
    });
    return toMounts(d);
  }

  /** Enables an auth method at `path`. */
  async enableAuthMethod(
    path: string,
    type: string,
    options: EnableAuthOptions = {},
  ): Promise<void> {
    const op = `sys.enableAuthMethod ${path}`;
    const config = compact({
      default_lease_ttl: optDuration(options.defaultLeaseTtlMs),
      max_lease_ttl: optDuration(options.maxLeaseTtlMs),
    });
    await this.#ctx.http.send({
      method: "POST",
      path: encodePath("sys/auth", requireText(trimSlashes(path), "path", op)),
      operation: op,
      json: compact({
        type: requireText(type, "type", op),
        description: options.description,
        config: Object.keys(config).length > 0 ? config : undefined,
        local: options.local,
      }),
      signal: options.signal,
    });
  }

  /** Disables an auth method; its tokens are revoked. */
  async disableAuthMethod(path: string, options: SysCallOptions = {}): Promise<void> {
    const op = `sys.disableAuthMethod ${path}`;
    await this.#ctx.http.send({
      method: "DELETE",
      path: encodePath("sys/auth", requireText(trimSlashes(path), "path", op)),
      operation: op,
      signal: options.signal,
    });
  }

  /** Creates or updates an AppRole role: `POST auth/<mount>/role/<name>`. */
  async createAppRole(name: string, options: AppRoleOptions = {}): Promise<void> {
    const op = `sys.createAppRole ${name}`;
    await this.#ctx.http.send({
      method: "POST",
      path: encodePath("auth", options.mount ?? "approle", "role", requireText(name, "name", op)),
      operation: op,
      json: compact({
        token_policies: options.tokenPolicies,
        token_ttl: optDuration(options.tokenTtlMs),
        token_max_ttl: optDuration(options.tokenMaxTtlMs),
        secret_id_ttl: optDuration(options.secretIdTtlMs),
        secret_id_num_uses: options.secretIdNumUses,
        bind_secret_id: options.bindSecretId,
        token_type: options.tokenType,
      }),
      signal: options.signal,
    });
  }

  /** AppRole role names; `[]` when there is none. */
  async listAppRoles(options: AppRoleMountOptions = {}): Promise<string[]> {
    try {
      const d = await this.#ctx.http.data<{ keys?: unknown }>({
        method: "GET",
        path: encodePath("auth", options.mount ?? "approle", "role"),
        operation: "sys.listAppRoles",
        list: true,
        signal: options.signal,
      });
      return strings(d.keys);
    } catch (err) {
      if ((err as { code?: unknown }).code === "NOT_FOUND") return [];
      throw err;
    }
  }

  /** Deletes an AppRole role. */
  async deleteAppRole(name: string, options: AppRoleMountOptions = {}): Promise<void> {
    const op = `sys.deleteAppRole ${name}`;
    await this.#ctx.http.send({
      method: "DELETE",
      path: encodePath("auth", options.mount ?? "approle", "role", requireText(name, "name", op)),
      operation: op,
      signal: options.signal,
    });
  }

  /** The role id of an AppRole role; `NotFoundError` for unknown roles. */
  async readRoleId(name: string, options: AppRoleMountOptions = {}): Promise<string> {
    const op = `sys.readRoleId ${name}`;
    const d = await this.#ctx.http.data<{ role_id?: unknown }>({
      method: "GET",
      path: encodePath(
        "auth",
        options.mount ?? "approle",
        "role",
        requireText(name, "name", op),
        "role-id",
      ),
      operation: op,
      signal: options.signal,
    });
    if (typeof d.role_id !== "string") throw unexpected(op, "no role_id");
    return d.role_id;
  }

  /** Generates a new secret id for an AppRole role. */
  async generateSecretId(name: string, options: SecretIdOptions = {}): Promise<SecretIdInfo> {
    const op = `sys.generateSecretId ${name}`;
    const d = await this.#ctx.http.data<Record<string, unknown>>({
      method: "POST",
      path: encodePath(
        "auth",
        options.mount ?? "approle",
        "role",
        requireText(name, "name", op),
        "secret-id",
      ),
      operation: op,
      json: compact({
        metadata: options.metadata === undefined ? undefined : JSON.stringify(options.metadata),
        cidr_list: options.cidrList,
        ttl: optDuration(options.ttlMs),
        num_uses: options.numUses,
      }),
      signal: options.signal,
    });
    if (typeof d.secret_id !== "string") throw unexpected(op, "no secret_id");
    return {
      secretId: new Secret(d.secret_id),
      secretIdAccessor: new Secret(str(d.secret_id_accessor)),
      secretIdNumUses: num(d.secret_id_num_uses),
      secretIdTtlMs: secondsToMs(d.secret_id_ttl),
    };
  }
}
