// Service-owned. SecretsProvider (SPEC §3) on top of a KV mount (DECISIONS.md #1, #2, #6):
// one secret = one KV path whose data is `{"value": "<string>"}`; bytes are stored as
// `{"value": "<base64>", "encoding": "base64"}`; objects are JSON-encoded into `value`.

import { throwIfAborted } from "./core/abort.js";
import {
  ErrorCode,
  NotFoundError,
  UnsupportedError,
  ValidationError,
  isOpenBaoError,
} from "./core/index.js";
import {
  BaseSecretsProvider,
  type DeleteOptions,
  type GetOptions,
  type SecretInput,
  type SecretMetadata,
  type SetOptions,
  type SignalOptions,
  SecretValue,
} from "./secrets/index.js";
import type { KvVersion } from "./config.js";
import { fromBase64, isUtf8, toBase64, trimSlashes } from "./http.js";
import type { Kv, KvMetadata, KvMount } from "./kv.js";

/** Options of {@link OpenBaoSecretsProvider} (`client.secrets(options)`). */
export interface OpenBaoSecretsOptions {
  /** KV mount (default `config.kvMount`, i.e. `secret`). */
  mount?: string;
  /** Base path inside the mount that names are relative to (default `""`). */
  path?: string;
  /** Data field that holds the value (default `"value"`). */
  valueField?: string;
}

/** Concurrency of per-key metadata reads in `list()` (DECISIONS.md #2). */
export const LIST_METADATA_CONCURRENCY = 8;

const ENCODING_FIELD = "encoding";

function isMissing(err: unknown): boolean {
  return isOpenBaoError(err, ErrorCode.NotFound);
}

async function orNull<T>(p: Promise<T>): Promise<T | null> {
  try {
    return await p;
  } catch (err) {
    if (isMissing(err)) return null;
    throw err;
  }
}

async function mapLimit<T, R>(
  items: readonly T[],
  limit: number,
  fn: (item: T) => Promise<R>,
): Promise<R[]> {
  const out = new Array<R>(items.length);
  let next = 0;
  const worker = async (): Promise<void> => {
    while (next < items.length) {
      const i = next++;
      out[i] = await fn(items[i] as T);
    }
  };
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
  return out;
}

/** `true` when the current version of a KV v2 secret is deleted or destroyed. */
function currentGone(meta: KvMetadata): boolean {
  const current = meta.versions[String(meta.currentVersion)];
  return current === undefined || current.deletionTime !== null || current.destroyed;
}

/**
 * {@link SecretsProvider} over an OpenBao KV mount (v1 or v2, auto-detected).
 *
 * - `get(name)` reads `<path>/<name>`; KV v2 versions are the SecretValue version.
 * - `set` returns the new KV v2 version (`""` on KV v1); `cas` and `tags` (custom metadata)
 *   need KV v2.
 * - `delete` soft-deletes the latest version (KV v2), `versions` deletes those versions,
 *   `permanent` removes all versions and metadata.
 * - `list(prefix)` lists one folder level (sub-folders skipped); on KV v2 each entry carries
 *   its metadata and secrets whose current version is deleted are skipped.
 */
export class OpenBaoSecretsProvider extends BaseSecretsProvider {
  /** Capabilities for the conformance runner. */
  static readonly capabilities: readonly string[] = ["write", "versions", "delete"];

  /** The KV mount. */
  readonly kv: KvMount;
  /** Base path inside the mount. */
  readonly path: string;
  /** Data field that holds the value. */
  readonly valueField: string;
  readonly #onClose: (() => void) | undefined;

  /** @internal Use `client.secrets(options)`. */
  constructor(kv: KvMount, options: OpenBaoSecretsOptions = {}, onClose?: () => void) {
    super();
    this.kv = kv;
    this.path = trimSlashes(options.path ?? "");
    this.valueField = options.valueField ?? "value";
    this.#onClose = onClose;
  }

  /** The KV path of a secret: `<options.path ?? provider path>/<name>`. */
  fullPath(name: string, path?: string): string {
    const base = trimSlashes(path ?? this.path);
    const n = trimSlashes(name);
    return base === "" ? n : n === "" ? base : `${base}/${n}`;
  }

  async #engine(path: string, signal?: AbortSignal): Promise<Kv & { version: KvVersion }> {
    return (await this.kv.engine(path, signal === undefined ? {} : { signal })) as Kv & {
      version: KvVersion;
    };
  }

  #decode(data: Record<string, unknown>, version: string | undefined): SecretValue {
    const raw = data[this.valueField];
    let value: string | Uint8Array;
    if (raw === undefined) value = JSON.stringify(data);
    else if (typeof raw !== "string") value = JSON.stringify(raw);
    else if (data[ENCODING_FIELD] === "base64") value = fromBase64(raw);
    else value = raw;
    return new SecretValue(value, version);
  }

  #payload(value: SecretInput): Record<string, unknown> {
    if (value instanceof Uint8Array) {
      return { [this.valueField]: toBase64(value), [ENCODING_FIELD]: "base64" };
    }
    return { [this.valueField]: typeof value === "string" ? value : JSON.stringify(value) };
  }

  protected async fetchSecret(name: string, options: GetOptions): Promise<SecretValue | null> {
    const path = this.fullPath(name, options.path);
    const engine = await this.#engine(path, options.signal);
    let version: number | undefined;
    if (options.version !== undefined) {
      if (engine.version === 1) {
        throw new ValidationError(`secrets.get ${name}: versions need a KV version 2 mount`);
      }
      version = Number(options.version);
      if (!Number.isInteger(version) || version <= 0) {
        throw new ValidationError(`secrets.get ${name}: version must be a positive integer`);
      }
    }
    const secret = await orNull(
      engine.read(path, {
        ...(version === undefined ? {} : { version }),
        ...(options.signal === undefined ? {} : { signal: options.signal }),
      }),
    );
    if (secret === null) return null;
    const current = secret.metadata === undefined ? undefined : String(secret.metadata.version);
    return this.#decode(secret.data, current);
  }

  protected async listSecrets(
    prefixOrPath: string | undefined,
    options: SignalOptions,
  ): Promise<SecretMetadata[]> {
    const prefix = trimSlashes(prefixOrPath ?? "");
    const folder = this.fullPath(prefix);
    const engine = await this.#engine(folder, options.signal);
    const keys = (await engine.list(folder, options)).filter((k) => !k.endsWith("/")).sort();
    const names = keys.map((k) => (prefix === "" ? k : `${prefix}/${k}`));
    if (engine.version === 1) {
      return names.map((name) => this.#basicMeta(name));
    }
    const metas = await mapLimit(names, LIST_METADATA_CONCURRENCY, (name) =>
      this.#metaV2(engine, name, undefined, options.signal),
    );
    return metas.filter((m): m is SecretMetadata => m !== null);
  }

  /** Metadata skeleton; `path` is the parent folder of `name` (omitted at the top level). */
  #basicMeta(name: string): SecretMetadata {
    const n = trimSlashes(name);
    const slash = n.lastIndexOf("/");
    return { name: n, ...(slash > 0 ? { path: n.slice(0, slash) } : {}), tags: {}, extra: {} };
  }

  async #metaV2(
    engine: Kv,
    name: string,
    path: string | undefined,
    signal: AbortSignal | undefined,
  ): Promise<SecretMetadata | null> {
    const meta = await orNull(
      engine.readMetadata(this.fullPath(name, path), signal === undefined ? {} : { signal }),
    );
    if (meta === null || currentGone(meta)) return null;
    const out: SecretMetadata = {
      ...this.#basicMeta(name),
      version: String(meta.currentVersion),
      tags: meta.customMetadata,
      versions: Object.keys(meta.versions).length,
      extra: {
        maxVersions: String(meta.maxVersions),
        casRequired: String(meta.casRequired),
        deleteVersionAfterMs: String(meta.deleteVersionAfterMs),
        oldestVersion: String(meta.oldestVersion),
      },
    };
    if (meta.createdTime !== null) out.createdAt = meta.createdTime;
    if (meta.updatedTime !== null) out.updatedAt = meta.updatedTime;
    return out;
  }

  /**
   * Writes a secret. Strings are stored as is, `Uint8Array` as base64 (with
   * `encoding: "base64"`), objects JSON-encoded. Returns the new version (`""` on KV v1).
   */
  override async set(name: string, value: SecretInput, options: SetOptions = {}): Promise<string> {
    throwIfAborted(options.signal, `secrets.set ${name}`);
    return this.#write(name, this.#payload(value), options);
  }

  /** Byte form used by the base class: UTF-8 text is stored as text, other bytes as base64. */
  protected putSecret(name: string, value: Uint8Array, options: SetOptions): Promise<string> {
    return this.#write(
      name,
      this.#payload(isUtf8(value) ? new TextDecoder().decode(value) : value),
      options,
    );
  }

  async #write(name: string, data: Record<string, unknown>, options: SetOptions): Promise<string> {
    const path = this.fullPath(name, options.path);
    const engine = await this.#engine(path, options.signal);
    const signal = options.signal === undefined ? {} : { signal: options.signal };
    const custom =
      options.tags === undefined && options.description === undefined
        ? undefined
        : {
            ...options.tags,
            ...(options.description === undefined ? {} : { description: options.description }),
          };
    if (engine.version === 1) {
      if (options.cas !== undefined || custom !== undefined) {
        throw new UnsupportedError(
          `secrets.set ${name}: cas, tags and description need a KV version 2 mount`,
        );
      }
      await engine.write(path, data, signal);
      return "";
    }
    const meta = await engine.write(path, data, {
      ...signal,
      ...(options.cas === undefined ? {} : { cas: options.cas }),
    });
    if (custom !== undefined) {
      await engine.writeMetadata(path, { customMetadata: custom, ...signal });
    }
    return meta === null ? "" : String(meta.version);
  }

  protected async removeSecret(name: string, options: DeleteOptions): Promise<void> {
    const path = this.fullPath(name, options.path);
    const engine = await this.#engine(path, options.signal);
    const signal = options.signal === undefined ? {} : { signal: options.signal };
    const notFound = (): NotFoundError => new NotFoundError(`secrets.delete ${name}: not found`);
    // KV DELETE answers 204 for missing paths, so check first (DECISIONS.md #6).
    if (engine.version === 1) {
      if (options.versions !== undefined && options.versions.length > 0) {
        throw new UnsupportedError(`secrets.delete ${name}: versions need a KV version 2 mount`);
      }
      if ((await orNull(engine.read(path, signal))) === null) throw notFound();
      await engine.delete(path, signal);
      return;
    }
    const versions = (options.versions ?? []).map(Number);
    if (versions.some((v) => !Number.isInteger(v) || v <= 0)) {
      throw new ValidationError(`secrets.delete ${name}: versions must be positive integers`);
    }
    if (versions.length > 0 || options.permanent === true) {
      if ((await orNull(engine.readMetadata(path, signal))) === null) throw notFound();
      if (options.permanent === true) await engine.deleteMetadata(path, signal);
      else await engine.deleteVersions(path, versions, signal);
      return;
    }
    if ((await orNull(engine.read(path, signal))) === null) throw notFound();
    await engine.delete(path, signal);
  }

  protected async fetchMetadata(name: string, options: GetOptions): Promise<SecretMetadata | null> {
    const path = this.fullPath(name, options.path);
    const engine = await this.#engine(path, options.signal);
    if (engine.version === 2) return this.#metaV2(engine, name, options.path, options.signal);
    const signal = options.signal === undefined ? {} : { signal: options.signal };
    const secret = await orNull(engine.read(path, signal));
    return secret === null ? null : this.#basicMeta(name);
  }

  /** Stops watchers and detaches from the client. Idempotent. */
  override async close(): Promise<void> {
    await super.close();
    this.#onClose?.();
  }
}
