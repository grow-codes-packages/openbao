// Service-owned. Transit secrets engine: encryption as a service (API.md §5).

import { ValidationError } from "./core/index.js";
import {
  type ClientContext,
  compact,
  encodePath,
  fromBase64,
  optDuration,
  parseVaultDuration,
  requireText,
  strings,
  toBase64,
  trimSlashes,
  unexpected,
} from "./http.js";

/** Per-call options. */
export interface TransitCallOptions {
  /** Cancels the call (`CancelledError`). */
  signal?: AbortSignal;
}

/** Transit key types. */
export type TransitKeyType =
  | "aes128-gcm96"
  | "aes256-gcm96"
  | "chacha20-poly1305"
  | "xchacha20-poly1305"
  | "ed25519"
  | "ecdsa-p256"
  | "ecdsa-p384"
  | "ecdsa-p521"
  | "rsa-2048"
  | "rsa-3072"
  | "rsa-4096"
  | "hmac"
  | (string & {});

/** Plaintext/input accepted by transit: UTF-8 text or bytes (sent base64-encoded). */
export type TransitInput = string | Uint8Array;

/** Options of `createKey()`. */
export interface CreateKeyOptions extends TransitCallOptions {
  /** Key type (default `aes256-gcm96`). */
  type?: TransitKeyType;
  /** Allow exporting the key. */
  exportable?: boolean;
  /** Key derivation (requires a `context` on every operation). */
  derived?: boolean;
  /** Automatic rotation period in ms (`0` = off). */
  autoRotatePeriodMs?: number;
  /** Allow plaintext backups. */
  allowPlaintextBackup?: boolean;
  /** Key size in bytes for `hmac` keys. */
  keySize?: number;
}

/** A transit key. */
export interface TransitKey {
  /** Key name. */
  name: string;
  /** Key type, e.g. `aes256-gcm96`. */
  type: string;
  /** Key versions → creation time (or public key for asymmetric keys, as JSON text). */
  keys: Record<string, string>;
  /** Latest key version. */
  latestVersion: number;
  /** Oldest key version allowed to decrypt. */
  minDecryptionVersion: number;
  /** Key version used to encrypt (`0` = latest). */
  minEncryptionVersion: number;
  /** Oldest version still stored (`0` = all). */
  minAvailableVersion: number;
  /** Whether the key may be deleted. */
  deletionAllowed: boolean;
  /** Whether the key can be exported. */
  exportable: boolean;
  /** Whether key derivation is enabled. */
  derived: boolean;
  /** Whether the key can encrypt. */
  supportsEncryption: boolean;
  /** Whether the key can decrypt. */
  supportsDecryption: boolean;
  /** Whether the key can sign. */
  supportsSigning: boolean;
  /** Whether the key supports derivation. */
  supportsDerivation: boolean;
  /** Automatic rotation period in ms (`0` = off). */
  autoRotatePeriodMs: number;
}

/** Options of `updateKeyConfig()`. */
export interface KeyConfig extends TransitCallOptions {
  /** Whether the key may be deleted. */
  deletionAllowed?: boolean;
  /** Oldest key version allowed to decrypt. */
  minDecryptionVersion?: number;
  /** Key version used to encrypt (`0` = latest). */
  minEncryptionVersion?: number;
  /** Whether the key can be exported. */
  exportable?: boolean;
  /** Allow plaintext backups of the key. */
  allowPlaintextBackup?: boolean;
  /** Automatic rotation period in ms (`0` = off). */
  autoRotatePeriodMs?: number;
}

/** Options of `encrypt()`. */
export interface EncryptOptions extends TransitCallOptions {
  /** Derivation context (derived keys). */
  context?: TransitInput;
  /** Encrypt with this key version (default latest). */
  keyVersion?: number;
  /** Additional authenticated data (AEAD keys). */
  associatedData?: TransitInput;
}

/** Ciphertext `vault:v<n>:<base64>` and the key version that produced it. */
export interface Ciphertext {
  /** Ciphertext `vault:v<n>:<base64>`. */
  ciphertext: string;
  /** Key version used. */
  keyVersion: number;
}

/** Options of `decrypt()` / `rewrap()`. */
export interface DecryptOptions extends TransitCallOptions {
  /** Key derivation context (derived keys). */
  context?: TransitInput;
  /** Additional authenticated data (AEAD keys). */
  associatedData?: TransitInput;
}

/** Options of `rewrap()`. */
export interface RewrapOptions extends DecryptOptions {
  /** Rewrap to this key version (default latest). */
  keyVersion?: number;
}

/** One item of `encryptBatch()`. */
export interface EncryptBatchItem {
  /** Plaintext bytes (text is UTF-8 encoded). */
  plaintext: TransitInput;
  /** Key derivation context (derived keys). */
  context?: TransitInput;
  /** Echoed back in the result. */
  reference?: string;
}

/** One item of `decryptBatch()`. */
export interface DecryptBatchItem {
  /** Ciphertext `vault:v<n>:<base64>`. */
  ciphertext: string;
  /** Key derivation context (derived keys). */
  context?: TransitInput;
  /** Caller reference echoed in the result. */
  reference?: string;
}

/** Result of one `encryptBatch()` item; `error` is set when this item failed. */
export interface EncryptBatchResult {
  /** Ciphertext `vault:v<n>:<base64>`. */
  ciphertext?: string;
  /** Key version used. */
  keyVersion?: number;
  /** Caller reference echoed in the result. */
  reference?: string;
  /** Error text, `null`/absent on success. */
  error?: string;
}

/** Result of one `decryptBatch()` item; `error` is set when this item failed. */
export interface DecryptBatchResult {
  /** Plaintext bytes (text is UTF-8 encoded). */
  plaintext?: Uint8Array;
  /** Caller reference echoed in the result. */
  reference?: string;
  /** Error text, `null`/absent on success. */
  error?: string;
}

/** Options of `generateDataKey()`. */
export interface DataKeyOptions extends TransitCallOptions {
  /** Return the plaintext key too (default `true`); `false` = wrapped only. */
  plaintext?: boolean;
  /** Key size in bits: 128, 256 (default) or 512. */
  bits?: 128 | 256 | 512;
  /** Key derivation context (derived keys). */
  context?: TransitInput;
}

/** A data key: `ciphertext` decrypts (with the transit key) to `plaintext`. */
export interface DataKey extends Ciphertext {
  /** Present unless `plaintext: false` was requested. */
  plaintext?: Uint8Array;
}

/** Hash algorithms accepted by `hmac`, `sign`, `verify` and `hash`. */
export type HashAlgorithm =
  | "sha1"
  | "sha2-224"
  | "sha2-256"
  | "sha2-384"
  | "sha2-512"
  | "sha3-224"
  | "sha3-256"
  | "sha3-384"
  | "sha3-512"
  | (string & {});

/** Options of `hmac()`. */
export interface HmacOptions extends TransitCallOptions {
  /** Hash algorithm (default `sha2-256`). */
  algorithm?: HashAlgorithm;
  /** Key version used. */
  keyVersion?: number;
}

/** Options of `sign()`. */
export interface SignOptions extends TransitCallOptions {
  /** Hash algorithm (default `sha2-256`). */
  hashAlgorithm?: HashAlgorithm;
  /** RSA only: `pss` (default) or `pkcs1v15`. */
  signatureAlgorithm?: "pss" | "pkcs1v15";
  /** The input is already a hash. */
  prehashed?: boolean;
  /** Key version used. */
  keyVersion?: number;
  /** Key derivation context (derived keys). */
  context?: TransitInput;
}

/** A signature `vault:v<n>:<base64>`. */
export interface Signature {
  /** Signature `vault:v<n>:<base64>`. */
  signature: string;
  /** Key version used. */
  keyVersion: number;
}

/** What `verify()` checks: a signature or an HMAC. */
export type VerifyTarget =
  | {
      /** Signature `vault:v<n>:<base64>` from `sign()`. */
      signature: string;
    }
  | {
      /** HMAC `vault:v<n>:<base64>` from `hmac()`. */
      hmac: string;
    };

/** Options of `verify()`. */
export interface VerifyOptions extends TransitCallOptions {
  /** Hash algorithm (default `sha2-256`). */
  hashAlgorithm?: HashAlgorithm;
  /** RSA only: `pss` (default) or `pkcs1v15`. */
  signatureAlgorithm?: "pss" | "pkcs1v15";
  /** The input is already a hash. */
  prehashed?: boolean;
  /** Key derivation context (derived keys). */
  context?: TransitInput;
}

/** Options of `hash()` / `randomBytes()`. */
export interface FormatOptions extends TransitCallOptions {
  /** Output encoding: `hex` (hash default) or `base64` (random default). */
  format?: "hex" | "base64";
}

/** Options of `hash()`. */
export interface HashOptions extends FormatOptions {
  /** Default `sha2-256`. */
  algorithm?: HashAlgorithm;
}

/** Options of `listKeys()`. */
export interface ListKeysOptions extends TransitCallOptions {
  /** Start listing after this key. */
  after?: string;
  /** Return at most this many entries. */
  limit?: number;
}

function num(v: unknown): number {
  return typeof v === "number" ? v : 0;
}

function toKey(d: Record<string, unknown>): TransitKey {
  const keys: Record<string, string> = {};
  if (d.keys !== null && typeof d.keys === "object") {
    for (const [v, value] of Object.entries(d.keys as Record<string, unknown>)) {
      keys[v] = typeof value === "string" ? value : JSON.stringify(value);
    }
  }
  return {
    name: typeof d.name === "string" ? d.name : "",
    type: typeof d.type === "string" ? d.type : "",
    keys,
    latestVersion: num(d.latest_version),
    minDecryptionVersion: num(d.min_decryption_version),
    minEncryptionVersion: num(d.min_encryption_version),
    minAvailableVersion: num(d.min_available_version),
    deletionAllowed: d.deletion_allowed === true,
    exportable: d.exportable === true,
    derived: d.derived === true,
    supportsEncryption: d.supports_encryption === true,
    supportsDecryption: d.supports_decryption === true,
    supportsSigning: d.supports_signing === true,
    supportsDerivation: d.supports_derivation === true,
    autoRotatePeriodMs: parseVaultDuration(d.auto_rotate_period) ?? 0,
  };
}

function opt64(value: TransitInput | undefined): string | undefined {
  return value === undefined ? undefined : toBase64(value);
}

function ciphertextOf(d: Record<string, unknown>, op: string): Ciphertext {
  if (typeof d.ciphertext !== "string") throw unexpected(op, "no ciphertext");
  return { ciphertext: d.ciphertext, keyVersion: num(d.key_version) };
}

/** Transit engine on one mount: `client.transit(mount = "transit")`. */
export class Transit {
  /** Mount path. */
  readonly mount: string;
  readonly #ctx: ClientContext;

  /** @internal */
  constructor(ctx: ClientContext, mount = "transit") {
    this.#ctx = ctx;
    this.mount = trimSlashes(mount);
  }

  #p(...parts: string[]): string {
    return encodePath(this.mount, ...parts);
  }

  #name(name: string, op: string): string {
    return requireText(name, "key name", `transit.${op}`);
  }

  async #post<T>(
    path: string,
    op: string,
    json: Record<string, unknown>,
    signal: AbortSignal | undefined,
    idempotent = false,
  ): Promise<T> {
    return this.#ctx.http.data<T>({
      method: "POST",
      path,
      operation: `transit.${op}`,
      json: compact(json),
      signal,
      idempotent,
    });
  }

  /**
   * Creates a key (idempotent: an existing key is returned unchanged). `type` defaults to
   * `aes256-gcm96`; it may also be given as `options.type` (positional wins).
   */
  async createKey(
    name: string,
    typeOrOptions?: TransitKeyType | CreateKeyOptions,
    options: CreateKeyOptions = {},
  ): Promise<TransitKey> {
    if (typeof typeOrOptions === "object") options = typeOrOptions;
    else if (typeOrOptions !== undefined) options = { ...options, type: typeOrOptions };
    const res = await this.#ctx.http.call<Record<string, unknown>>({
      method: "POST",
      path: this.#p("keys", this.#name(name, "createKey")),
      operation: `transit.createKey ${name}`,
      json: compact({
        type: options.type ?? "aes256-gcm96",
        exportable: options.exportable,
        derived: options.derived,
        auto_rotate_period: optDuration(options.autoRotatePeriodMs),
        allow_plaintext_backup: options.allowPlaintextBackup,
        key_size: options.keySize,
      }),
      signal: options.signal,
    });
    const data = res.body?.data;
    return data === undefined || data === null ? this.readKey(name, options) : toKey(data);
  }

  /** Reads a key; `NotFoundError` when missing. */
  async readKey(name: string, options: TransitCallOptions = {}): Promise<TransitKey> {
    const d = await this.#ctx.http.data<Record<string, unknown>>({
      method: "GET",
      path: this.#p("keys", this.#name(name, "readKey")),
      operation: `transit.readKey ${name}`,
      signal: options.signal,
    });
    return toKey(d);
  }

  /** Key names (sorted); `[]` when there is none. */
  async listKeys(options: ListKeysOptions = {}): Promise<string[]> {
    try {
      const d = await this.#ctx.http.data<{ keys?: unknown }>({
        method: "GET",
        path: this.#p("keys") + "/",
        operation: "transit.listKeys",
        list: true,
        query: { after: options.after, limit: options.limit },
        signal: options.signal,
      });
      return strings(d.keys);
    } catch (err) {
      if ((err as { code?: unknown }).code === "NOT_FOUND") return [];
      throw err;
    }
  }

  /** Adds a new key version; returns the updated key. */
  async rotateKey(name: string, options: TransitCallOptions = {}): Promise<TransitKey> {
    const d = await this.#post<Record<string, unknown>>(
      this.#p("keys", this.#name(name, "rotateKey"), "rotate"),
      `rotateKey ${name}`,
      {},
      options.signal,
    );
    return toKey(d);
  }

  /** Updates key settings; returns the updated key. */
  async updateKeyConfig(name: string, config: KeyConfig): Promise<TransitKey> {
    const d = await this.#post<Record<string, unknown>>(
      this.#p("keys", this.#name(name, "updateKeyConfig"), "config"),
      `updateKeyConfig ${name}`,
      {
        deletion_allowed: config.deletionAllowed,
        min_decryption_version: config.minDecryptionVersion,
        min_encryption_version: config.minEncryptionVersion,
        exportable: config.exportable,
        allow_plaintext_backup: config.allowPlaintextBackup,
        auto_rotate_period: optDuration(config.autoRotatePeriodMs),
      },
      config.signal,
      true,
    );
    return toKey(d);
  }

  /** Deletes a key (needs `deletionAllowed: true`, else `ValidationError`). */
  async deleteKey(name: string, options: TransitCallOptions = {}): Promise<void> {
    await this.#ctx.http.send({
      method: "DELETE",
      path: this.#p("keys", this.#name(name, "deleteKey")),
      operation: `transit.deleteKey ${name}`,
      signal: options.signal,
    });
  }

  /** Encrypts `plaintext` (text is UTF-8 encoded). */
  async encrypt(
    name: string,
    plaintext: TransitInput,
    options: EncryptOptions = {},
  ): Promise<Ciphertext> {
    const op = `encrypt ${name}`;
    const d = await this.#post<Record<string, unknown>>(
      this.#p("encrypt", this.#name(name, "encrypt")),
      op,
      {
        plaintext: toBase64(plaintext),
        context: opt64(options.context),
        key_version: options.keyVersion,
        associated_data: opt64(options.associatedData),
      },
      options.signal,
    );
    return ciphertextOf(d, `transit.${op}`);
  }

  /** Decrypts a `vault:v<n>:` ciphertext and returns the plaintext bytes. */
  async decrypt(
    name: string,
    ciphertext: string,
    options: DecryptOptions = {},
  ): Promise<Uint8Array> {
    const d = await this.#post<{ plaintext?: unknown }>(
      this.#p("decrypt", this.#name(name, "decrypt")),
      `decrypt ${name}`,
      {
        ciphertext: requireText(ciphertext, "ciphertext", "transit.decrypt"),
        context: opt64(options.context),
        associated_data: opt64(options.associatedData),
      },
      options.signal,
      true,
    );
    return fromBase64(typeof d.plaintext === "string" ? d.plaintext : "");
  }

  /** Re-encrypts a ciphertext with the latest (or given) key version without revealing it. */
  async rewrap(name: string, ciphertext: string, options: RewrapOptions = {}): Promise<Ciphertext> {
    const op = `rewrap ${name}`;
    const d = await this.#post<Record<string, unknown>>(
      this.#p("rewrap", this.#name(name, "rewrap")),
      op,
      {
        ciphertext: requireText(ciphertext, "ciphertext", "transit.rewrap"),
        context: opt64(options.context),
        key_version: options.keyVersion,
      },
      options.signal,
    );
    return ciphertextOf(d, `transit.${op}`);
  }

  async #batch(
    kind: "encrypt" | "decrypt",
    name: string,
    input: Record<string, unknown>[],
    signal: AbortSignal | undefined,
  ): Promise<Record<string, unknown>[]> {
    const op = `${kind}Batch ${name}`;
    if (input.length === 0) return [];
    // 207 instead of 400 when some items fail, so per-item results are always readable.
    const d = await this.#post<{ batch_results?: unknown }>(
      this.#p(kind, this.#name(name, `${kind}Batch`)),
      op,
      { batch_input: input, partial_failure_response_code: 207 },
      signal,
      kind === "decrypt",
    );
    if (!Array.isArray(d.batch_results)) throw unexpected(`transit.${op}`, "no batch_results");
    return d.batch_results as Record<string, unknown>[];
  }

  /**
   * Encrypts many items in one request. Results are in input order; a failed item has `error`
   * set (the call itself only fails when the whole request fails).
   */
  async encryptBatch(
    name: string,
    items: readonly EncryptBatchItem[],
    options: TransitCallOptions = {},
  ): Promise<EncryptBatchResult[]> {
    const results = await this.#batch(
      "encrypt",
      name,
      items.map((i) =>
        compact({
          plaintext: toBase64(i.plaintext),
          context: opt64(i.context),
          reference: i.reference,
        }),
      ),
      options.signal,
    );
    return results.map((r) => {
      const out: EncryptBatchResult = {};
      if (typeof r.ciphertext === "string" && r.ciphertext !== "") out.ciphertext = r.ciphertext;
      if (typeof r.key_version === "number") out.keyVersion = r.key_version;
      if (typeof r.reference === "string" && r.reference !== "") out.reference = r.reference;
      if (typeof r.error === "string" && r.error !== "") out.error = r.error;
      return out;
    });
  }

  /** Decrypts many items in one request; see {@link encryptBatch} for error handling. */
  async decryptBatch(
    name: string,
    items: readonly DecryptBatchItem[],
    options: TransitCallOptions = {},
  ): Promise<DecryptBatchResult[]> {
    const results = await this.#batch(
      "decrypt",
      name,
      items.map((i) =>
        compact({ ciphertext: i.ciphertext, context: opt64(i.context), reference: i.reference }),
      ),
      options.signal,
    );
    return results.map((r) => {
      const out: DecryptBatchResult = {};
      if (typeof r.reference === "string" && r.reference !== "") out.reference = r.reference;
      if (typeof r.error === "string" && r.error !== "") out.error = r.error;
      else if (typeof r.plaintext === "string") out.plaintext = fromBase64(r.plaintext);
      return out;
    });
  }

  /** Generates a data key encrypted with the transit key (plus its plaintext by default). */
  async generateDataKey(name: string, options: DataKeyOptions = {}): Promise<DataKey> {
    const kind = options.plaintext === false ? "wrapped" : "plaintext";
    const op = `generateDataKey ${name}`;
    const d = await this.#post<Record<string, unknown>>(
      this.#p("datakey", kind, this.#name(name, "generateDataKey")),
      op,
      { bits: options.bits ?? 256, context: opt64(options.context) },
      options.signal,
    );
    const key: DataKey = ciphertextOf(d, `transit.${op}`);
    if (typeof d.plaintext === "string" && d.plaintext !== "")
      key.plaintext = fromBase64(d.plaintext);
    return key;
  }

  /** HMAC of `input` (`vault:v<n>:<base64>`). */
  async hmac(name: string, input: TransitInput, options: HmacOptions = {}): Promise<string> {
    const d = await this.#post<{ hmac?: unknown }>(
      this.#p("hmac", this.#name(name, "hmac"), options.algorithm ?? ""),
      `hmac ${name}`,
      { input: toBase64(input), key_version: options.keyVersion },
      options.signal,
      true,
    );
    if (typeof d.hmac !== "string") throw unexpected(`transit.hmac ${name}`, "no hmac");
    return d.hmac;
  }

  /** Signs `input` with an asymmetric key. */
  async sign(name: string, input: TransitInput, options: SignOptions = {}): Promise<Signature> {
    const d = await this.#post<Record<string, unknown>>(
      this.#p("sign", this.#name(name, "sign"), options.hashAlgorithm ?? ""),
      `sign ${name}`,
      {
        input: toBase64(input),
        signature_algorithm: options.signatureAlgorithm,
        prehashed: options.prehashed,
        key_version: options.keyVersion,
        context: opt64(options.context),
      },
      options.signal,
    );
    if (typeof d.signature !== "string") throw unexpected(`transit.sign ${name}`, "no signature");
    return { signature: d.signature, keyVersion: num(d.key_version) };
  }

  /**
   * Verifies a signature (`{ signature }`) or an HMAC (`{ hmac }`). Returns `false` for an
   * invalid signature (not an error).
   */
  async verify(
    name: string,
    input: TransitInput,
    target: VerifyTarget,
    options: VerifyOptions = {},
  ): Promise<boolean> {
    const signature = "signature" in target ? target.signature : undefined;
    const hmac = "hmac" in target ? target.hmac : undefined;
    if ((signature === undefined) === (hmac === undefined)) {
      throw new ValidationError("transit.verify: pass exactly one of signature or hmac");
    }
    const d = await this.#post<{ valid?: unknown }>(
      this.#p("verify", this.#name(name, "verify"), options.hashAlgorithm ?? ""),
      `verify ${name}`,
      {
        input: toBase64(input),
        signature,
        hmac,
        signature_algorithm: options.signatureAlgorithm,
        prehashed: options.prehashed,
        context: opt64(options.context),
      },
      options.signal,
      true,
    );
    return d.valid === true;
  }

  /** Hash of `input` (default `sha2-256`, hex). */
  async hash(input: TransitInput, options: HashOptions = {}): Promise<string> {
    const d = await this.#post<{ sum?: unknown }>(
      this.#p("hash", options.algorithm ?? ""),
      "hash",
      { input: toBase64(input), format: options.format },
      options.signal,
      true,
    );
    if (typeof d.sum !== "string") throw unexpected("transit.hash", "no sum");
    return d.sum;
  }

  /** `bytes` random bytes from the server, encoded as `base64` (default) or `hex`. */
  async randomBytes(bytes: number, options: FormatOptions = {}): Promise<string> {
    if (!Number.isInteger(bytes) || bytes <= 0) {
      throw new ValidationError("transit.randomBytes: bytes must be a positive integer");
    }
    const d = await this.#post<{ random_bytes?: unknown }>(
      this.#p("random"),
      "randomBytes",
      { bytes, format: options.format ?? "base64" },
      options.signal,
      true,
    );
    if (typeof d.random_bytes !== "string")
      throw unexpected("transit.randomBytes", "no random_bytes");
    return d.random_bytes;
  }
}
