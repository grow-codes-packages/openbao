// Service-owned. KV secrets engine v1 + v2 with per-mount auto-detection (API.md §4).

import { NotFoundError, UnsupportedError, ValidationError } from "./core/index.js";
import type { KvVersion } from "./config.js";
import {
  type ClientContext,
  compact,
  encodePath,
  optDuration,
  parseTime,
  parseVaultDuration,
  requireText,
  stringMap,
  strings,
  trimSlashes,
  unexpected,
} from "./http.js";

/** Per-call options. */
export interface KvCallOptions {
  /** Cancels the call (`CancelledError`). */
  signal?: AbortSignal;
}

/** Options of `read()`. */
export interface KvReadOptions extends KvCallOptions {
  /** Version to read (KV v2 only). */
  version?: number;
}

/** Options of `write()` / `patch()`. */
export interface KvWriteOptions extends KvCallOptions {
  /** Check-and-set: the current version must equal this (`0` = create only). KV v2 only. */
  cas?: number;
}

/** Options of `list()`. */
export interface KvListOptions extends KvCallOptions {
  /** Start after this key (KV v2). */
  after?: string;
  /** Return at most this many keys (KV v2). */
  limit?: number;
}

/** Metadata of one KV v2 version. */
export interface KvVersionMetadata {
  /** Version number. */
  version: number;
  /** Creation time. */
  createdTime: Date | null;
  /** Soft-delete time, `null` when not deleted. */
  deletionTime: Date | null;
  /** Whether the version was destroyed permanently. */
  destroyed: boolean;
  /** Free-form string metadata. */
  customMetadata: Record<string, string>;
}

/** A KV secret. */
export interface KvSecret {
  /** The key/value data. */
  data: Record<string, unknown>;
  /** Version metadata (KV v2 only). */
  metadata?: KvVersionMetadata;
}

/** Metadata of a KV v2 secret (all versions). */
export interface KvMetadata {
  /** Whether every write must pass `cas`. */
  casRequired: boolean;
  /** Creation time. */
  createdTime: Date | null;
  /** Last update time. */
  updatedTime: Date | null;
  /** Latest version number. */
  currentVersion: number;
  /** Oldest version kept. */
  oldestVersion: number;
  /** Versions kept (`0` = mount default). */
  maxVersions: number;
  /** Automatic deletion delay in ms (`0` = never). */
  deleteVersionAfterMs: number;
  /** Free-form string metadata. */
  customMetadata: Record<string, string>;
  /** Per-version state by version number. */
  versions: Record<string, KvVersionMetadata>;
}

/** Options of `writeMetadata()`. */
export interface KvMetadataOptions extends KvCallOptions {
  /** Versions to keep (`0` = mount default). */
  maxVersions?: number;
  /** Require `cas` on every write. */
  casRequired?: boolean;
  /** Delete versions this long after writing, in ms (`0` = never). */
  deleteVersionAfterMs?: number;
  /** Free-form string metadata. */
  customMetadata?: Record<string, string>;
}

/** The KV interface shared by {@link KvV1}, {@link KvV2} and the auto-detecting mount. */
export interface Kv {
  /** Mount path, e.g. `secret`. */
  readonly mount: string;
  /** Reads a secret; `NotFoundError` when missing (or the version is deleted/destroyed). */
  read(path: string, options?: KvReadOptions): Promise<KvSecret>;
  /** Writes (replaces) a secret. Returns the new version metadata (v2) or `null` (v1). */
  write(
    path: string,
    data: Record<string, unknown>,
    options?: KvWriteOptions,
  ): Promise<KvVersionMetadata | null>;
  /** Merges keys into the latest version (RFC 7386, `null` removes a key). KV v2 only. */
  patch(
    path: string,
    data: Record<string, unknown>,
    options?: KvWriteOptions,
  ): Promise<KvVersionMetadata>;
  /** Deletes the secret (v2: soft-deletes the latest version). Missing paths are not an error. */
  delete(path: string, options?: KvCallOptions): Promise<void>;
  /** Soft-deletes versions. KV v2 only. */
  deleteVersions(path: string, versions: number[], options?: KvCallOptions): Promise<void>;
  /** Restores soft-deleted versions. KV v2 only. */
  undelete(path: string, versions: number[], options?: KvCallOptions): Promise<void>;
  /** Permanently destroys versions. KV v2 only. */
  destroy(path: string, versions: number[], options?: KvCallOptions): Promise<void>;
  /** Keys directly under a folder (sub-folders end in `/`); `[]` when there is none. */
  list(path?: string, options?: KvListOptions): Promise<string[]>;
  /** Metadata of all versions. KV v2 only; `NotFoundError` when missing. */
  readMetadata(path: string, options?: KvCallOptions): Promise<KvMetadata>;
  /** Updates metadata settings. KV v2 only. */
  writeMetadata(path: string, options: KvMetadataOptions): Promise<void>;
  /** Deletes the secret with all versions and metadata. KV v2 only. */
  deleteMetadata(path: string, options?: KvCallOptions): Promise<void>;
}

function versionMeta(raw: unknown): KvVersionMetadata | undefined {
  if (raw === null || typeof raw !== "object") return undefined;
  const m = raw as Record<string, unknown>;
  return {
    version: typeof m.version === "number" ? m.version : 0,
    createdTime: parseTime(m.created_time),
    deletionTime: parseTime(m.deletion_time),
    destroyed: m.destroyed === true,
    customMetadata: stringMap(m.custom_metadata),
  };
}

function checkVersions(versions: number[], operation: string): number[] {
  if (
    !Array.isArray(versions) ||
    versions.length === 0 ||
    versions.some((v) => !Number.isInteger(v) || v <= 0)
  ) {
    throw new ValidationError(
      `${operation}: versions must be a non-empty list of positive integers`,
    );
  }
  return versions;
}

function asNotFoundEmpty(err: unknown): string[] {
  if (err instanceof NotFoundError) return [];
  throw err;
}

/** KV version 1 (unversioned) mount. Version-only operations raise `UnsupportedError`. */
export class KvV1 implements Kv {
  /** Mount path. */
  readonly mount: string;
  /** Always `1`. */
  readonly version = 1 as const;
  readonly #ctx: ClientContext;

  /** @internal */
  constructor(ctx: ClientContext, mount: string) {
    this.#ctx = ctx;
    this.mount = trimSlashes(mount);
  }

  #path(path: string, op: string): string {
    return encodePath(this.mount, requireText(path, "path", op));
  }

  #unsupported(op: string): never {
    throw new UnsupportedError(`kv.${op} ${this.mount}: not supported by KV version 1`);
  }

  async read(path: string, options: KvReadOptions = {}): Promise<KvSecret> {
    const op = `kv.read ${this.mount}/${path}`;
    if (options.version !== undefined) this.#unsupported("read with version");
    const data = await this.#ctx.http.data<Record<string, unknown>>({
      method: "GET",
      path: this.#path(path, op),
      operation: op,
      signal: options.signal,
    });
    return { data };
  }

  async write(
    path: string,
    data: Record<string, unknown>,
    options: KvWriteOptions = {},
  ): Promise<null> {
    const op = `kv.write ${this.mount}/${path}`;
    if (options.cas !== undefined) this.#unsupported("write with cas");
    await this.#ctx.http.send({
      method: "POST",
      path: this.#path(path, op),
      operation: op,
      json: data,
      signal: options.signal,
    });
    return null;
  }

  patch(): Promise<KvVersionMetadata> {
    return this.#reject("patch");
  }

  async delete(path: string, options: KvCallOptions = {}): Promise<void> {
    const op = `kv.delete ${this.mount}/${path}`;
    await this.#ctx.http.send({
      method: "DELETE",
      path: this.#path(path, op),
      operation: op,
      signal: options.signal,
    });
  }

  deleteVersions(): Promise<void> {
    return this.#reject("deleteVersions");
  }

  undelete(): Promise<void> {
    return this.#reject("undelete");
  }

  destroy(): Promise<void> {
    return this.#reject("destroy");
  }

  async list(path = "", options: KvListOptions = {}): Promise<string[]> {
    const op = `kv.list ${this.mount}/${path}`;
    try {
      const data = await this.#ctx.http.data<{ keys?: unknown }>({
        method: "GET",
        path: encodePath(this.mount, path) + "/",
        operation: op,
        list: true,
        signal: options.signal,
      });
      return strings(data.keys);
    } catch (err) {
      return asNotFoundEmpty(err);
    }
  }

  readMetadata(): Promise<KvMetadata> {
    return this.#reject("readMetadata");
  }

  writeMetadata(): Promise<void> {
    return this.#reject("writeMetadata");
  }

  deleteMetadata(): Promise<void> {
    return this.#reject("deleteMetadata");
  }

  #reject<T>(op: string): Promise<T> {
    return Promise.reject(
      new UnsupportedError(`kv.${op} ${this.mount}: not supported by KV version 1`),
    );
  }
}

/** KV version 2 (versioned) mount. */
export class KvV2 implements Kv {
  /** Mount path. */
  readonly mount: string;
  /** Always `2`. */
  readonly version = 2 as const;
  readonly #ctx: ClientContext;

  /** @internal */
  constructor(ctx: ClientContext, mount: string) {
    this.#ctx = ctx;
    this.mount = trimSlashes(mount);
  }

  #path(kind: string, path: string, op: string): string {
    return encodePath(this.mount, kind, requireText(path, "path", op));
  }

  async read(path: string, options: KvReadOptions = {}): Promise<KvSecret> {
    const op = `kv.read ${this.mount}/${path}`;
    const data = await this.#ctx.http.data<{ data?: unknown; metadata?: unknown }>({
      method: "GET",
      path: this.#path("data", path, op),
      operation: op,
      query: { version: options.version },
      signal: options.signal,
    });
    if (data.data === null || data.data === undefined || typeof data.data !== "object") {
      throw new NotFoundError(`${op}: version is deleted or destroyed`);
    }
    const metadata = versionMeta(data.metadata);
    return {
      data: data.data as Record<string, unknown>,
      ...(metadata === undefined ? {} : { metadata }),
    };
  }

  async write(
    path: string,
    data: Record<string, unknown>,
    options: KvWriteOptions = {},
  ): Promise<KvVersionMetadata> {
    const op = `kv.write ${this.mount}/${path}`;
    const res = await this.#ctx.http.data({
      method: "POST",
      path: this.#path("data", path, op),
      operation: op,
      json: { ...(options.cas === undefined ? {} : { options: { cas: options.cas } }), data },
      signal: options.signal,
    });
    return versionMeta(res) as KvVersionMetadata;
  }

  async patch(
    path: string,
    data: Record<string, unknown>,
    options: KvWriteOptions = {},
  ): Promise<KvVersionMetadata> {
    const op = `kv.patch ${this.mount}/${path}`;
    const res = await this.#ctx.http.data({
      method: "PATCH",
      path: this.#path("data", path, op),
      operation: op,
      headers: { "content-type": "application/merge-patch+json" },
      json: { ...(options.cas === undefined ? {} : { options: { cas: options.cas } }), data },
      signal: options.signal,
    });
    return versionMeta(res) as KvVersionMetadata;
  }

  async delete(path: string, options: KvCallOptions = {}): Promise<void> {
    const op = `kv.delete ${this.mount}/${path}`;
    await this.#ctx.http.send({
      method: "DELETE",
      path: this.#path("data", path, op),
      operation: op,
      signal: options.signal,
    });
  }

  async #versions(
    kind: "delete" | "undelete" | "destroy",
    path: string,
    versions: number[],
    options: KvCallOptions,
  ): Promise<void> {
    const op = `kv.${kind === "delete" ? "deleteVersions" : kind} ${this.mount}/${path}`;
    await this.#ctx.http.send({
      method: kind === "destroy" ? "PUT" : "POST",
      path: this.#path(kind, path, op),
      operation: op,
      json: { versions: checkVersions(versions, op) },
      signal: options.signal,
    });
  }

  deleteVersions(path: string, versions: number[], options: KvCallOptions = {}): Promise<void> {
    return this.#versions("delete", path, versions, options);
  }

  undelete(path: string, versions: number[], options: KvCallOptions = {}): Promise<void> {
    return this.#versions("undelete", path, versions, options);
  }

  destroy(path: string, versions: number[], options: KvCallOptions = {}): Promise<void> {
    return this.#versions("destroy", path, versions, options);
  }

  async list(path = "", options: KvListOptions = {}): Promise<string[]> {
    const op = `kv.list ${this.mount}/${path}`;
    try {
      const data = await this.#ctx.http.data<{ keys?: unknown }>({
        method: "GET",
        path: encodePath(this.mount, "metadata", path) + "/",
        operation: op,
        list: true,
        query: { after: options.after, limit: options.limit },
        signal: options.signal,
      });
      return strings(data.keys);
    } catch (err) {
      return asNotFoundEmpty(err);
    }
  }

  async readMetadata(path: string, options: KvCallOptions = {}): Promise<KvMetadata> {
    const op = `kv.readMetadata ${this.mount}/${path}`;
    const d = await this.#ctx.http.data<Record<string, unknown>>({
      method: "GET",
      path: this.#path("metadata", path, op),
      operation: op,
      signal: options.signal,
    });
    const versions: Record<string, KvVersionMetadata> = {};
    const rawVersions = d.versions;
    if (rawVersions !== null && typeof rawVersions === "object") {
      for (const [v, meta] of Object.entries(rawVersions as Record<string, unknown>)) {
        const parsed = versionMeta({ ...(meta as object), version: Number(v) });
        if (parsed !== undefined) versions[v] = parsed;
      }
    }
    return {
      casRequired: d.cas_required === true,
      createdTime: parseTime(d.created_time),
      updatedTime: parseTime(d.updated_time),
      currentVersion: typeof d.current_version === "number" ? d.current_version : 0,
      oldestVersion: typeof d.oldest_version === "number" ? d.oldest_version : 0,
      maxVersions: typeof d.max_versions === "number" ? d.max_versions : 0,
      deleteVersionAfterMs: parseVaultDuration(d.delete_version_after) ?? 0,
      customMetadata: stringMap(d.custom_metadata),
      versions,
    };
  }

  async writeMetadata(path: string, options: KvMetadataOptions): Promise<void> {
    const op = `kv.writeMetadata ${this.mount}/${path}`;
    await this.#ctx.http.send({
      method: "POST",
      path: this.#path("metadata", path, op),
      operation: op,
      json: compact({
        max_versions: options.maxVersions,
        cas_required: options.casRequired,
        delete_version_after: optDuration(options.deleteVersionAfterMs),
        custom_metadata: options.customMetadata,
      }),
      signal: options.signal,
    });
  }

  async deleteMetadata(path: string, options: KvCallOptions = {}): Promise<void> {
    const op = `kv.deleteMetadata ${this.mount}/${path}`;
    await this.#ctx.http.send({
      method: "DELETE",
      path: this.#path("metadata", path, op),
      operation: op,
      signal: options.signal,
    });
  }
}

/**
 * Detects the KV version of a mount: `GET sys/internal/ui/mounts/<mount>/<path>` →
 * `options.version`. Restricted tokens need some capability on `path`. Throws
 * `ValidationError` when the mount is not a KV mount.
 */
async function detectKvVersion(
  ctx: ClientContext,
  mount: string,
  path = "",
  options: KvCallOptions = {},
): Promise<KvVersion> {
  const op = `kv.detectVersion ${mount}`;
  const data = await ctx.http.data<{ type?: unknown; options?: { version?: unknown } | null }>({
    method: "GET",
    path: encodePath("sys/internal/ui/mounts", mount, path),
    operation: op,
    signal: options.signal,
  });
  if (data.type !== "kv") {
    throw new ValidationError(`${op}: not a KV mount (type ${String(data.type)})`);
  }
  const version = data.options?.version;
  if (version === "2" || version === 2) return 2;
  if (version === "1" || version === 1 || version === undefined || version === null) return 1;
  throw unexpected(op, `unknown KV version ${JSON.stringify(version)}`);
}

/**
 * A KV mount whose version is detected on first use (or taken from `config.kvVersion`), then
 * delegates to {@link KvV1} or {@link KvV2}. Version-only operations raise `UnsupportedError`
 * on v1 mounts.
 */
export class KvMount implements Kv {
  /** Mount path. */
  readonly mount: string;
  readonly #ctx: ClientContext;
  #detected: Promise<Kv> | undefined;
  #engine: Kv | undefined;

  /** @internal */
  constructor(ctx: ClientContext, mount: string, version?: KvVersion) {
    this.#ctx = ctx;
    this.mount = trimSlashes(mount);
    if (version !== undefined) this.#engine = this.#make(version);
  }

  #make(version: KvVersion): Kv {
    return version === 2 ? new KvV2(this.#ctx, this.mount) : new KvV1(this.#ctx, this.mount);
  }

  /** The KV version (detects it when unknown). */
  async version(options: KvCallOptions & { path?: string } = {}): Promise<KvVersion> {
    const engine = await this.engine(options.path ?? "", options);
    return engine instanceof KvV2 ? 2 : 1;
  }

  /** The concrete engine (detects the version on first use). */
  engine(path = "", options: KvCallOptions = {}): Promise<Kv> {
    if (this.#engine !== undefined) return Promise.resolve(this.#engine);
    this.#detected ??= detectKvVersion(this.#ctx, this.mount, path, options).then(
      (v) => (this.#engine = this.#make(v)),
      (err: unknown) => {
        this.#detected = undefined;
        throw err;
      },
    );
    return this.#detected;
  }

  async read(path: string, options?: KvReadOptions): Promise<KvSecret> {
    return (await this.engine(path, options)).read(path, options);
  }

  async write(
    path: string,
    data: Record<string, unknown>,
    options?: KvWriteOptions,
  ): Promise<KvVersionMetadata | null> {
    return (await this.engine(path, options)).write(path, data, options);
  }

  async patch(
    path: string,
    data: Record<string, unknown>,
    options?: KvWriteOptions,
  ): Promise<KvVersionMetadata> {
    return (await this.engine(path, options)).patch(path, data, options);
  }

  async delete(path: string, options?: KvCallOptions): Promise<void> {
    return (await this.engine(path, options)).delete(path, options);
  }

  async deleteVersions(path: string, versions: number[], options?: KvCallOptions): Promise<void> {
    return (await this.engine(path, options)).deleteVersions(path, versions, options);
  }

  async undelete(path: string, versions: number[], options?: KvCallOptions): Promise<void> {
    return (await this.engine(path, options)).undelete(path, versions, options);
  }

  async destroy(path: string, versions: number[], options?: KvCallOptions): Promise<void> {
    return (await this.engine(path, options)).destroy(path, versions, options);
  }

  async list(path = "", options?: KvListOptions): Promise<string[]> {
    return (await this.engine(path, options)).list(path, options);
  }

  async readMetadata(path: string, options?: KvCallOptions): Promise<KvMetadata> {
    return (await this.engine(path, options)).readMetadata(path, options);
  }

  async writeMetadata(path: string, options: KvMetadataOptions): Promise<void> {
    return (await this.engine(path, options)).writeMetadata(path, options);
  }

  async deleteMetadata(path: string, options?: KvCallOptions): Promise<void> {
    return (await this.engine(path, options)).deleteMetadata(path, options);
  }
}
