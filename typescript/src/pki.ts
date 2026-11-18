// Service-owned. PKI secrets engine: issue, sign, revoke, read and tidy certificates
// (API.md §7).

import { ErrorCode, Secret, isOpenBaoError, pollUntil } from "./core/index.js";
import {
  type ClientContext,
  compact,
  encodePath,
  optDuration,
  parseTime,
  requireText,
  strings,
  trimSlashes,
  unexpected,
} from "./http.js";

/** Per-call options. */
export interface PkiCallOptions {
  /** Cancels the call (`CancelledError`). */
  signal?: AbortSignal;
}

/** Options of `issueCertificate()`. */
export interface IssueOptions extends PkiCallOptions {
  /** DNS/email subject alternative names. */
  altNames?: string[];
  /** IP subject alternative names. */
  ipSans?: string[];
  /** URI subject alternative names. */
  uriSans?: string[];
  /** Certificate TTL in ms (role default when omitted). */
  ttlMs?: number;
  /** `pem` (default), `der` or `pem_bundle`. */
  format?: "pem" | "der" | "pem_bundle";
  /** Private key encoding: `der` (default) or `pkcs8`. */
  privateKeyFormat?: "der" | "pkcs8";
  /** Leave the common name out of the SANs. */
  excludeCnFromSans?: boolean;
}

/** Options of `signCsr()`. */
export interface SignCsrOptions extends Omit<IssueOptions, "privateKeyFormat"> {
  /** Overrides the CSR common name. */
  commonName?: string;
}

/** A certificate issued or signed by the PKI engine. */
export interface SignedCertificate {
  /** PEM certificate. */
  certificate: string;
  /** PEM issuing CA. */
  issuingCa: string;
  /** PEM CA chain. */
  caChain: string[];
  /** Colon-separated hex serial, e.g. `1b:51:...`. */
  serialNumber: string;
  /** Expiry time of the certificate. */
  expiration: Date | null;
}

/** An issued certificate with its private key (redacted in every string form). */
export interface IssuedCertificate extends SignedCertificate {
  /** PEM private key (redacted in every string form). */
  privateKey: Secret;
  /** `rsa`, `ec` or `ed25519`. */
  privateKeyType: string;
}

/** Result of `revokeCertificate()`. */
export interface RevocationInfo {
  /** Revocation time, `null` when not revoked. */
  revocationTime: Date | null;
  /** `revoked` when present. */
  state: string;
}

/** Result of `readCertificate()`. */
export interface CertificateInfo {
  /** PEM certificate. */
  certificate: string;
  /** Revocation time, `null` when not revoked. */
  revocationTime: Date | null;
}

/** Options of `tidy()`. */
export interface TidyOptions extends PkiCallOptions {
  /** Remove expired certificates from storage (default `true`). */
  tidyCertStore?: boolean;
  /** Remove expired revoked certificates (default `true`). */
  tidyRevokedCerts?: boolean;
  /** Only tidy certificates expired for longer than this, in ms (server default 72 h). */
  safetyBufferMs?: number;
  /** Wait until the tidy run finishes (default `true`). */
  wait?: boolean;
  /** Longest wait in ms (default 60 000). */
  timeoutMs?: number;
  /** Poll interval in ms (default 500). */
  intervalMs?: number;
}

/** Tidy progress from `pki/tidy-status`. */
export interface TidyStatus {
  /** `Inactive`, `Running`, `Finished`, `Error` or `Cancelled`. */
  state: string;
  /** Error text, `null`/absent on success. */
  error: string | null;
  /** Certificates removed from storage by the last run. */
  certStoreDeletedCount: number;
  /** Revoked certificates removed by the last run. */
  revokedCertDeletedCount: number;
  /** Start of the last run. */
  timeStarted: Date | null;
  /** End of the last run. */
  timeFinished: Date | null;
}

function signed(d: Record<string, unknown>, op: string): SignedCertificate {
  if (typeof d.certificate !== "string") throw unexpected(op, "no certificate");
  return {
    certificate: d.certificate,
    issuingCa: typeof d.issuing_ca === "string" ? d.issuing_ca : "",
    caChain: strings(d.ca_chain),
    serialNumber: typeof d.serial_number === "string" ? d.serial_number : "",
    expiration: parseTime(d.expiration),
  };
}

function join(values: string[] | undefined): string | undefined {
  return values === undefined || values.length === 0 ? undefined : values.join(",");
}

const TIDY_DONE: ReadonlySet<string> = new Set(["Finished", "Error", "Cancelled"]);

function count(v: unknown): number {
  return typeof v === "number" ? v : 0;
}

/** PKI engine on one mount: `client.pki(mount = "pki")`. */
export class Pki {
  /** Mount path. */
  readonly mount: string;
  readonly #ctx: ClientContext;

  /** @internal */
  constructor(ctx: ClientContext, mount = "pki") {
    this.#ctx = ctx;
    this.mount = trimSlashes(mount);
  }

  /** Issues a certificate and private key for a role: `POST <mount>/issue/<role>`. */
  async issueCertificate(
    role: string,
    commonName: string,
    options: IssueOptions = {},
  ): Promise<IssuedCertificate> {
    const op = `pki.issueCertificate ${role}`;
    const d = await this.#ctx.http.data<Record<string, unknown>>({
      method: "POST",
      path: encodePath(this.mount, "issue", requireText(role, "role", op)),
      operation: op,
      json: compact({
        common_name: requireText(commonName, "commonName", op),
        alt_names: join(options.altNames),
        ip_sans: join(options.ipSans),
        uri_sans: join(options.uriSans),
        ttl: optDuration(options.ttlMs),
        format: options.format,
        private_key_format: options.privateKeyFormat,
        exclude_cn_from_sans: options.excludeCnFromSans,
      }),
      signal: options.signal,
    });
    return {
      ...signed(d, op),
      privateKey: new Secret(typeof d.private_key === "string" ? d.private_key : ""),
      privateKeyType: typeof d.private_key_type === "string" ? d.private_key_type : "",
    };
  }

  /** Signs a PEM CSR for a role: `POST <mount>/sign/<role>`. */
  async signCsr(
    role: string,
    csr: string,
    options: SignCsrOptions = {},
  ): Promise<SignedCertificate> {
    const op = `pki.signCsr ${role}`;
    const d = await this.#ctx.http.data<Record<string, unknown>>({
      method: "POST",
      path: encodePath(this.mount, "sign", requireText(role, "role", op)),
      operation: op,
      json: compact({
        csr: requireText(csr, "csr", op),
        common_name: options.commonName,
        alt_names: join(options.altNames),
        ip_sans: join(options.ipSans),
        uri_sans: join(options.uriSans),
        ttl: optDuration(options.ttlMs),
        format: options.format,
        exclude_cn_from_sans: options.excludeCnFromSans,
      }),
      signal: options.signal,
    });
    return signed(d, op);
  }

  /** Revokes a certificate by serial (`aa:bb:...`). Unknown serials raise `ValidationError`. */
  async revokeCertificate(serial: string, options: PkiCallOptions = {}): Promise<RevocationInfo> {
    const op = `pki.revokeCertificate ${serial}`;
    const d = await this.#ctx.http.data<Record<string, unknown>>({
      method: "POST",
      path: encodePath(this.mount, "revoke"),
      operation: op,
      json: { serial_number: requireText(serial, "serial", op) },
      signal: options.signal,
      idempotent: true,
    });
    return {
      revocationTime: parseTime(d.revocation_time_rfc3339) ?? parseTime(d.revocation_time),
      state: typeof d.state === "string" ? d.state : "revoked",
    };
  }

  /** The CA chain as PEM text (`GET <mount>/ca_chain`, raw PEM). */
  async readCaChain(options: PkiCallOptions = {}): Promise<string> {
    const res = await this.#ctx.http.call<never>({
      method: "GET",
      path: encodePath(this.mount, "ca_chain"),
      operation: "pki.readCaChain",
      responseType: "text",
      signal: options.signal,
    });
    return typeof res.body === "string" ? res.body : "";
  }

  /** A certificate by serial; `NotFoundError` when unknown. */
  async readCertificate(serial: string, options: PkiCallOptions = {}): Promise<CertificateInfo> {
    const op = `pki.readCertificate ${serial}`;
    const d = await this.#ctx.http.data<Record<string, unknown>>({
      method: "GET",
      path: encodePath(this.mount, "cert", requireText(serial, "serial", op)),
      operation: op,
      signal: options.signal,
    });
    if (typeof d.certificate !== "string" || d.certificate === "") {
      throw unexpected(op, "no certificate");
    }
    return {
      certificate: d.certificate,
      revocationTime: parseTime(d.revocation_time_rfc3339) ?? parseTime(d.revocation_time),
    };
  }

  /** Serials of all stored certificates; `[]` when there is none. */
  async listCertificates(options: PkiCallOptions = {}): Promise<string[]> {
    try {
      const d = await this.#ctx.http.data<{ keys?: unknown }>({
        method: "GET",
        path: encodePath(this.mount, "certs") + "/",
        operation: "pki.listCertificates",
        list: true,
        signal: options.signal,
      });
      return strings(d.keys);
    } catch (err) {
      if (isOpenBaoError(err, ErrorCode.NotFound)) return [];
      throw err;
    }
  }

  /** Current tidy progress: `GET <mount>/tidy-status`. */
  async tidyStatus(options: PkiCallOptions = {}): Promise<TidyStatus> {
    const d = await this.#ctx.http.data<Record<string, unknown>>({
      method: "GET",
      path: encodePath(this.mount, "tidy-status"),
      operation: "pki.tidyStatus",
      signal: options.signal,
    });
    return {
      state: typeof d.state === "string" ? d.state : "",
      error: typeof d.error === "string" && d.error !== "" ? d.error : null,
      certStoreDeletedCount: count(d.cert_store_deleted_count),
      revokedCertDeletedCount: count(d.revoked_cert_deleted_count),
      timeStarted: parseTime(d.time_started),
      timeFinished: parseTime(d.time_finished),
    };
  }

  /**
   * Starts a tidy run (`POST <mount>/tidy`, 202) and, unless `wait: false`, polls
   * `tidy-status` until it is `Finished`, `Error` or `Cancelled`. Returns the last status.
   */
  async tidy(options: TidyOptions = {}): Promise<TidyStatus> {
    await this.#ctx.http.send({
      method: "POST",
      path: encodePath(this.mount, "tidy"),
      operation: "pki.tidy",
      json: compact({
        tidy_cert_store: options.tidyCertStore ?? true,
        tidy_revoked_certs: options.tidyRevokedCerts ?? true,
        safety_buffer: optDuration(options.safetyBufferMs),
      }),
      signal: options.signal,
    });
    const signal = options.signal === undefined ? {} : { signal: options.signal };
    if (options.wait === false) return this.tidyStatus(signal);
    return pollUntil(
      () => this.tidyStatus(signal),
      (s) => TIDY_DONE.has(s.state),
      {
        timeoutMs: options.timeoutMs ?? 60_000,
        intervalMs: options.intervalMs ?? 500,
        operation: "pki.tidy",
        ...signal,
      },
    );
  }
}
