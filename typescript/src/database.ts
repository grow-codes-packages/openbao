// Service-owned. Database secrets engine: dynamic credentials and admin helpers (API.md §6).

import { Secret } from "./core/index.js";
import {
  type ClientContext,
  compact,
  encodePath,
  optDuration,
  requireText,
  secondsToMs,
  stringMap,
  strings,
  trimSlashes,
  unexpected,
} from "./http.js";
import { type Lease, leaseFromEnvelope } from "./leases.js";

/** Per-call options. */
export interface DatabaseCallOptions {
  /** Cancels the call (`CancelledError`). */
  signal?: AbortSignal;
}

/** Dynamic database credentials (the password is redacted in every string form). */
export interface DatabaseCredentials {
  /** Generated database user name. */
  username: string;
  /** Password (redacted in every string form). */
  password: Secret;
}

/** Options of `configureConnection()`. */
export interface ConnectionConfig extends DatabaseCallOptions {
  /** Plugin, e.g. `postgresql-database-plugin`. */
  pluginName: string;
  /** Connection URL with `{{username}}`/`{{password}}` templates. */
  connectionUrl: string;
  /** Root username. */
  username?: string;
  /** Root password. */
  password?: string | Secret;
  /** Roles allowed to use this connection (`["*"]` = all). */
  allowedRoles?: string[];
  /** Check the connection when writing (default server-side `true`). */
  verifyConnection?: boolean;
  /** Extra plugin-specific fields sent as is (snake_case). */
  extra?: Record<string, unknown>;
}

/** A connection as returned by `readConnection()` (never contains the password). */
export interface ConnectionInfo {
  /** Database plugin, e.g. `postgresql-database-plugin`. */
  pluginName: string;
  /** Roles allowed to use the connection (`["*"]` = all). */
  allowedRoles: string[];
  /** Plugin connection details (e.g. `connection_url`, `username`). */
  connectionDetails: Record<string, string>;
}

/** Options of `createRole()`. */
export interface RoleConfig extends DatabaseCallOptions {
  /** Connection name. */
  dbName: string;
  /** SQL run to create the user (`{{name}}`, `{{password}}`, `{{expiration}}`). */
  creationStatements: string[];
  /** SQL statements run on revocation. */
  revocationStatements?: string[];
  /** SQL statements run on renewal. */
  renewStatements?: string[];
  /** SQL statements run when creation fails. */
  rollbackStatements?: string[];
  /** Default lease TTL in ms. */
  defaultTtlMs?: number;
  /** Maximum lease TTL in ms. */
  maxTtlMs?: number;
}

/** A role as returned by `readRole()`. */
export interface RoleInfo {
  /** Connection name the role uses. */
  dbName: string;
  /** SQL statements that create the user. */
  creationStatements: string[];
  /** SQL statements run on revocation. */
  revocationStatements: string[];
  /** SQL statements run on renewal. */
  renewStatements: string[];
  /** SQL statements run when creation fails. */
  rollbackStatements: string[];
  /** Default lease TTL in ms. */
  defaultTtlMs: number;
  /** Maximum lease TTL in ms. */
  maxTtlMs: number;
  /** Credential type, e.g. `password`. */
  credentialType: string;
}

/** Database engine on one mount: `client.database(mount = "database")`. */
export class Database {
  /** Mount path. */
  readonly mount: string;
  readonly #ctx: ClientContext;

  /** @internal */
  constructor(ctx: ClientContext, mount = "database") {
    this.#ctx = ctx;
    this.mount = trimSlashes(mount);
  }

  /**
   * Generates credentials for a role: `GET <mount>/creds/<role>`. Keep them alive with
   * `client.leases.manage(lease, { onExpire })`. Unknown roles raise `ValidationError`.
   */
  async getCredentials(
    role: string,
    options: DatabaseCallOptions = {},
  ): Promise<Lease<DatabaseCredentials>> {
    const op = `database.getCredentials ${role}`;
    const env = await this.#ctx.http.envelope<Record<string, unknown>>({
      method: "GET",
      path: encodePath(this.mount, "creds", requireText(role, "role", op)),
      operation: op,
      signal: options.signal,
      // Each GET creates new credentials: never retry blindly.
      idempotent: false,
    });
    const d = env.data;
    if (d === undefined || d === null || typeof d.username !== "string") {
      throw unexpected(op, "no credentials in response");
    }
    return leaseFromEnvelope(env, {
      username: d.username,
      password: new Secret(typeof d.password === "string" ? d.password : ""),
    });
  }

  /** Creates or replaces a connection: `POST <mount>/config/<name>` (verified by default). */
  async configureConnection(name: string, config: ConnectionConfig): Promise<void> {
    const op = `database.configureConnection ${name}`;
    const password = config.password instanceof Secret ? config.password.reveal() : config.password;
    await this.#ctx.http.send({
      method: "POST",
      path: encodePath(this.mount, "config", requireText(name, "name", op)),
      operation: op,
      json: compact({
        ...config.extra,
        plugin_name: config.pluginName,
        connection_url: config.connectionUrl,
        username: config.username,
        password,
        allowed_roles: config.allowedRoles,
        verify_connection: config.verifyConnection,
      }),
      signal: config.signal,
    });
  }

  /** Reads a connection (without its password); `NotFoundError` when missing. */
  async readConnection(name: string, options: DatabaseCallOptions = {}): Promise<ConnectionInfo> {
    const op = `database.readConnection ${name}`;
    const d = await this.#ctx.http.data<Record<string, unknown>>({
      method: "GET",
      path: encodePath(this.mount, "config", requireText(name, "name", op)),
      operation: op,
      signal: options.signal,
    });
    return {
      pluginName: typeof d.plugin_name === "string" ? d.plugin_name : "",
      allowedRoles: strings(d.allowed_roles),
      connectionDetails: stringMap(d.connection_details),
    };
  }

  /** Deletes a connection. */
  async deleteConnection(name: string, options: DatabaseCallOptions = {}): Promise<void> {
    const op = `database.deleteConnection ${name}`;
    await this.#ctx.http.send({
      method: "DELETE",
      path: encodePath(this.mount, "config", requireText(name, "name", op)),
      operation: op,
      signal: options.signal,
    });
  }

  /** Creates or replaces a dynamic role: `POST <mount>/roles/<name>`. */
  async createRole(name: string, config: RoleConfig): Promise<void> {
    const op = `database.createRole ${name}`;
    await this.#ctx.http.send({
      method: "POST",
      path: encodePath(this.mount, "roles", requireText(name, "name", op)),
      operation: op,
      json: compact({
        db_name: config.dbName,
        creation_statements: config.creationStatements,
        revocation_statements: config.revocationStatements,
        renew_statements: config.renewStatements,
        rollback_statements: config.rollbackStatements,
        default_ttl: optDuration(config.defaultTtlMs),
        max_ttl: optDuration(config.maxTtlMs),
      }),
      signal: config.signal,
    });
  }

  /** Reads a role; `NotFoundError` when missing. */
  async readRole(name: string, options: DatabaseCallOptions = {}): Promise<RoleInfo> {
    const op = `database.readRole ${name}`;
    const d = await this.#ctx.http.data<Record<string, unknown>>({
      method: "GET",
      path: encodePath(this.mount, "roles", requireText(name, "name", op)),
      operation: op,
      signal: options.signal,
    });
    return {
      dbName: typeof d.db_name === "string" ? d.db_name : "",
      creationStatements: strings(d.creation_statements),
      revocationStatements: strings(d.revocation_statements),
      renewStatements: strings(d.renew_statements),
      rollbackStatements: strings(d.rollback_statements),
      defaultTtlMs: secondsToMs(d.default_ttl),
      maxTtlMs: secondsToMs(d.max_ttl),
      credentialType: typeof d.credential_type === "string" ? d.credential_type : "",
    };
  }

  /** Deletes a role. */
  async deleteRole(name: string, options: DatabaseCallOptions = {}): Promise<void> {
    const op = `database.deleteRole ${name}`;
    await this.#ctx.http.send({
      method: "DELETE",
      path: encodePath(this.mount, "roles", requireText(name, "name", op)),
      operation: op,
      signal: options.signal,
    });
  }
}
