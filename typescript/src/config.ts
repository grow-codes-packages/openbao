// Service-owned: generated once by sdk-kit, then maintained in this repository.

import {
  type CommonConfig,
  type CommonConfigOptions,
  type CommonVendorEnv,
  ConfigError,
  type EnvMap,
  EnvReader,
  type Hooks,
  type ClientLogger,
  REDACTED,
  type RetryPolicy,
  Secret,
  type TlsOptions,
  describeCommonConfig,
  mergeOptions,
  readCommonEnv,
  resolveCommonConfig,
  secretValues,
  validateCommonConfig,
} from "./core/index.js";

const INSPECT = Symbol.for("nodejs.util.inspect.custom");

/** Port text from the stack catalog; the default URL uses its first number. */
const CATALOG_PORT = "8200";

/** KV secrets engine version: `1` (unversioned) or `2` (versioned). */
export type KvVersion = 1 | 2;

/** Options accepted by {@link OpenBaoConfig} (all optional). */
export interface OpenBaoConfigOptions extends CommonConfigOptions {
  /**
   * Client token sent as `X-Vault-Token` (env `GROW_OPENBAO_TOKEN`, `BAO_TOKEN`, `VAULT_TOKEN`).
   * Leave it unset when the client logs in with an auth method (`client.auth.login(...)`).
   */
  token?: string | Secret;
  /**
   * Namespace sent as `X-Vault-Namespace` (env `GROW_OPENBAO_NAMESPACE`, `BAO_NAMESPACE`,
   * `VAULT_NAMESPACE`).
   */
  namespace?: string;
  /** Default KV mount used by `client.kv()` and `client.secrets()` (default `"secret"`). */
  kvMount?: string;
  /**
   * KV version of every mount, skipping auto-detection (`sys/internal/ui/mounts`). Set it for
   * tokens that cannot read the mount preflight endpoint. Default: auto-detect per mount.
   */
  kvVersion?: KvVersion;
}

/**
 * Vendor environment variables read after `GROW_OPENBAO_*`, in order: the OpenBao (`BAO_*`)
 * name first, then the HashiCorp Vault compatible (`VAULT_*`) name.
 */
export const VENDOR_ENV: CommonVendorEnv & {
  /** Vendor variables for the token. */
  token: readonly string[];
  /** Namespace sent as `X-Vault-Namespace`. */
  namespace: readonly string[];
} = {
  /** Endpoint base URL. */
  url: ["BAO_ADDR", "VAULT_ADDR"],
  token: ["BAO_TOKEN", "VAULT_TOKEN"],
  /** Namespace sent as `X-Vault-Namespace`. */
  namespace: ["BAO_NAMESPACE", "VAULT_NAMESPACE"],
  caCert: ["BAO_CACERT", "VAULT_CACERT"],
  clientCert: ["BAO_CLIENT_CERT", "VAULT_CLIENT_CERT"],
  clientKey: ["BAO_CLIENT_KEY", "VAULT_CLIENT_KEY"],
  insecureSkipVerify: ["BAO_SKIP_VERIFY", "VAULT_SKIP_VERIFY"],
};

/** Immutable configuration of {@link OpenBaoClient}. */
export class OpenBaoConfig implements CommonConfig {
  /** Default endpoint (`http://127.0.0.1:8200`). */
  static readonly DEFAULT_URL = `http://127.0.0.1:${/\d+/.exec(CATALOG_PORT)?.[0] ?? "8080"}`;
  /** Prefix of every environment variable. */
  static readonly ENV_PREFIX = "GROW_OPENBAO_";
  /** Default KV mount. */
  static readonly DEFAULT_KV_MOUNT = "secret";

  /** Endpoint base URL. */
  readonly url: string;
  /** Connection setup timeout in ms. */
  readonly connectTimeoutMs: number;
  /** Per-attempt timeout in ms. */
  readonly requestTimeoutMs: number;
  /** Whole-call timeout in ms, including retries. */
  readonly totalTimeoutMs: number;
  /** Retry policy. */
  readonly retry: RetryPolicy;
  /** TLS settings. */
  readonly tls: Readonly<TlsOptions>;
  /** Proxy URL (environment proxies are ignored). */
  readonly proxy?: string;
  /** Extra request headers (values redacted in debug output). */
  readonly headers: Readonly<Record<string, string>>;
  /** Appended after the standard User-Agent. */
  readonly userAgentSuffix?: string;
  /** Request/response hooks. */
  readonly hooks?: Hooks;
  /** Diagnostic logger (silent by default). */
  readonly logger?: ClientLogger;
  /** Client token (redacted in every string form). */
  readonly token?: Secret;
  /** Namespace (`X-Vault-Namespace`). */
  readonly namespace?: string;
  /** Default KV mount. */
  readonly kvMount: string;
  /** Fixed KV version, or `undefined` for auto-detection. */
  readonly kvVersion?: KvVersion;

  /** Applies defaults, validates (throws {@link ConfigError}) and freezes. */
  constructor(options: OpenBaoConfigOptions = {}) {
    const common = resolveCommonConfig(options, OpenBaoConfig.DEFAULT_URL);
    this.url = common.url;
    this.connectTimeoutMs = common.connectTimeoutMs;
    this.requestTimeoutMs = common.requestTimeoutMs;
    this.totalTimeoutMs = common.totalTimeoutMs;
    this.retry = common.retry;
    this.tls = common.tls;
    this.headers = common.headers;
    if (common.proxy !== undefined) this.proxy = common.proxy;
    if (common.userAgentSuffix !== undefined) this.userAgentSuffix = common.userAgentSuffix;
    if (common.hooks !== undefined) this.hooks = common.hooks;
    if (common.logger !== undefined) this.logger = common.logger;
    const token = Secret.from(options.token);
    if (token !== undefined) this.token = token;
    if (options.namespace !== undefined && options.namespace !== "") {
      this.namespace = options.namespace;
    }
    this.kvMount = options.kvMount ?? OpenBaoConfig.DEFAULT_KV_MOUNT;
    if (options.kvVersion !== undefined) this.kvVersion = options.kvVersion;
    this.validate();
    Object.freeze(this);
  }

  /** Returns `options` when it already is a config, otherwise builds one. */
  static from(options: OpenBaoConfigOptions = {}): OpenBaoConfig {
    if (options instanceof OpenBaoConfig) return options;
    return new OpenBaoConfig(options);
  }

  /**
   * Builds a config from the environment. Precedence: explicit `overrides` >
   * `GROW_OPENBAO_<NAME>` > vendor variables ({@link VENDOR_ENV}: `BAO_*`, then `VAULT_*`) >
   * defaults. Reads `URL`, `TOKEN`, `NAMESPACE`, `CA_CERT`, `CLIENT_CERT`, `CLIENT_KEY`,
   * `INSECURE_SKIP_VERIFY`, `PROXY`, the timeouts and `MAX_RETRIES`.
   */
  static fromEnv(overrides: OpenBaoConfigOptions = {}, env: EnvMap = process.env): OpenBaoConfig {
    const reader = new EnvReader(OpenBaoConfig.ENV_PREFIX, env);
    const fromEnv: OpenBaoConfigOptions = readCommonEnv(reader, VENDOR_ENV);
    const token = reader.secret("TOKEN", VENDOR_ENV.token);
    if (token !== undefined) fromEnv.token = token;
    const namespace = reader.string("NAMESPACE", VENDOR_ENV.namespace);
    if (namespace !== undefined) fromEnv.namespace = namespace;
    const merged = mergeOptions<OpenBaoConfigOptions>(fromEnv, overrides);
    return new OpenBaoConfig(merged);
  }

  /** Throws {@link ConfigError} when a setting is invalid. */
  validate(): void {
    validateCommonConfig(this);
    if (this.token?.reveal().trim() === "")
      throw new ConfigError("invalid configuration: token must not be blank");
    if (this.kvMount.replace(/^\/+|\/+$/g, "") === "")
      throw new ConfigError("invalid configuration: kvMount must not be empty");
    const kvVersion: unknown = this.kvVersion;
    if (kvVersion !== undefined && kvVersion !== 1 && kvVersion !== 2)
      throw new ConfigError("invalid configuration: kvVersion must be 1 or 2");
  }

  /** Credential values to redact from error messages and logs. */
  knownSecrets(): string[] {
    return secretValues(this.token);
  }

  /** Debug form with every credential redacted. */
  toJSON(): Record<string, unknown> {
    return {
      ...describeCommonConfig(this),
      token: this.token === undefined ? null : REDACTED,
      namespace: this.namespace ?? null,
      kvMount: this.kvMount,
      kvVersion: this.kvVersion ?? null,
    };
  }

  toString(): string {
    return `OpenBaoConfig(${JSON.stringify(this.toJSON())})`;
  }

  /** `util.inspect` form (credentials redacted). */
  [INSPECT](): string {
    return this.toString();
  }
}
