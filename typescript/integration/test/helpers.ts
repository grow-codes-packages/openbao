// Shared helpers for the integration tests (real OpenBao from docker/compose.yml).

import assert from "node:assert/strict";
import { createPrivateKey, generateKeyPairSync, randomBytes, sign } from "node:crypto";
import { OpenBaoClient, type OpenBaoConfigOptions } from "@grow-codes/openbao";
import { loadBootstrapEnv, runId } from "./env.ts";

loadBootstrapEnv();

/** A required variable from /bootstrap/env (fails the test when missing). */
export function env(name: string): string {
  const value = process.env[name];
  assert.ok(value !== undefined && value !== "", `${name} must be set (see /bootstrap/env)`);
  return value;
}

/** A unique lowercase id for names created by this run. */
export function uid(prefix = "ts"): string {
  return `${prefix}-${runId
    .replace(/[^a-z0-9]/gi, "")
    .slice(0, 8)
    .toLowerCase()}-${randomBytes(4).toString("hex")}`;
}

/** A client with the bootstrap root token (GROW_OPENBAO_URL / GROW_OPENBAO_TOKEN). */
export function rootClient(options: OpenBaoConfigOptions = {}): OpenBaoClient {
  return OpenBaoClient.fromEnv(options);
}

/** A client without any token (for logins). */
export function anonClient(options: OpenBaoConfigOptions = {}): OpenBaoClient {
  const client = OpenBaoClient.fromEnv(options);
  client.setToken(undefined);
  return client;
}

/** Runs `fn` with a client and always closes it. */
export async function withClient<T>(
  client: OpenBaoClient,
  fn: (client: OpenBaoClient) => Promise<T>,
): Promise<T> {
  try {
    return await fn(client);
  } finally {
    await client.close();
  }
}

/** Retries `fn` until it stops throwing (new KV v2 mounts answer 400 for a moment). */
export async function eventually<T>(fn: () => Promise<T>, timeoutMs = 15_000): Promise<T> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    try {
      return await fn();
    } catch (err) {
      if (Date.now() > deadline) throw err;
      await new Promise((r) => setTimeout(r, 250));
    }
  }
}

// --- minimal DER encoder for a PKCS#10 CSR (EC P-256, CN only) ---------------------------

function der(tag: number, content: Buffer): Buffer {
  const len = content.length;
  const head =
    len < 0x80
      ? Buffer.from([tag, len])
      : len < 0x100
        ? Buffer.from([tag, 0x81, len])
        : Buffer.from([tag, 0x82, len >> 8, len & 0xff]);
  return Buffer.concat([head, content]);
}

const seq = (...parts: Buffer[]): Buffer => der(0x30, Buffer.concat(parts));

/** A PEM CSR for `commonName` and its private key (PEM). */
export function makeCsr(commonName: string): { csr: string; spkiDer: Buffer } {
  const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const spkiDer = publicKey.export({ type: "spki", format: "der" });
  const cnOid = Buffer.from([0x06, 0x03, 0x55, 0x04, 0x03]);
  const subject = seq(der(0x31, seq(cnOid, der(0x0c, Buffer.from(commonName, "utf8")))));
  const info = seq(Buffer.from([0x02, 0x01, 0x00]), subject, spkiDer, Buffer.from([0xa0, 0x00]));
  const signature = sign("sha256", info, {
    key: createPrivateKey(privateKey.export({ type: "pkcs8", format: "pem" })),
    dsaEncoding: "der",
  });
  const ecdsaSha256 = seq(
    Buffer.from([0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02]),
  );
  const csrDer = seq(info, ecdsaSha256, der(0x03, Buffer.concat([Buffer.from([0]), signature])));
  const b64 = csrDer.toString("base64").replace(/(.{64})(?=.)/g, "$1\n");
  return {
    csr: `-----BEGIN CERTIFICATE REQUEST-----\n${b64}\n-----END CERTIFICATE REQUEST-----\n`,
    spkiDer,
  };
}
