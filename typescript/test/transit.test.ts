import { describe, expect, it } from "vitest";
import {
  NO_CONTENT,
  data,
  errors,
  fixture,
  fromFixtures,
  rejection,
  vault,
} from "./support/vault.js";

const K = "sdk-f43633d7";
const BIN = Buffer.from("Z3JvdwD/YmluYXJ5LWY0MzYzM2Q3", "base64");

describe("Transit keys", () => {
  it("createKey (200 with key body, idempotent) and readKey", async () => {
    const m = await vault({
      [`POST /v1/transit/keys/${K}`]: [
        "transit.createKey.ok",
        "transit.createKey.exists",
        NO_CONTENT,
      ],
      [`GET /v1/transit/keys/${K}`]: "transit.readKey.ok",
      "GET /v1/transit/keys/missing-f43633d7": "transit.readKey.not-found",
    });
    const t = m.client().transit();
    expect(t.mount).toBe("transit");
    const key = await t.createKey(K);
    expect(m.body()).toEqual({ type: "aes256-gcm96" });
    expect(key).toMatchObject({
      name: K,
      type: "aes256-gcm96",
      latestVersion: 1,
      supportsEncryption: true,
      supportsSigning: false,
      deletionAllowed: false,
      autoRotatePeriodMs: 0,
    });
    expect(Number(key.keys["1"])).toBeGreaterThan(0);
    expect((await t.createKey(K, { type: "aes256-gcm96" })).name).toBe(K);
    // an empty 204 answer falls back to readKey
    const read = await t.createKey(K, {
      type: "ed25519",
      exportable: true,
      derived: false,
      autoRotatePeriodMs: 3_600_000,
      allowPlaintextBackup: false,
      keySize: 32,
    });
    expect(m.body(-2)).toEqual({
      type: "ed25519",
      exportable: true,
      derived: false,
      auto_rotate_period: "3600s",
      allow_plaintext_backup: false,
      key_size: 32,
    });
    expect(read.name).toBe(K);
    expect((await rejection(t.readKey("missing-f43633d7"))).code).toBe("NOT_FOUND");
    await expect(t.readKey("")).rejects.toMatchObject({ code: "VALIDATION" });
  });

  it("asymmetric key versions are kept as JSON text", async () => {
    const m = await vault({
      "GET /v1/transit/keys/sdk-sign": data({
        name: "sdk-sign",
        type: "ed25519",
        keys: { "1": { public_key: "pk", creation_time: "t" } },
        auto_rotate_period: "1h0m0s",
      }),
      "GET /v1/transit/keys/empty": data({ keys: null }),
    });
    const key = await m.client().transit().readKey("sdk-sign");
    expect(JSON.parse(key.keys["1"] ?? "{}")).toMatchObject({ public_key: "pk" });
    expect(key.autoRotatePeriodMs).toBe(3_600_000);
    expect(await m.client().transit().readKey("empty")).toMatchObject({ name: "", keys: {} });
  });

  it("listKeys (with limit), rotateKey, updateKeyConfig, deleteKey", async () => {
    const m = await vault({
      "LIST /v1/transit/keys": (req) =>
        req.url.includes("limit=1") ? "transit.listKeys.paginated" : "transit.listKeys.ok",
      "LIST /v1/othertransit/keys": errors(404),
      "LIST /v1/denied/keys": errors(403, "1 error occurred: * permission denied"),
      ...fromFixtures("transit.rotateKey.ok", "transit.updateKeyConfig.ok"),
      [`DELETE /v1/transit/keys/${K}`]: ["transit.deleteKey.not-allowed", "transit.deleteKey.ok"],
    });
    const c = m.client();
    const t = c.transit();
    expect(await t.listKeys()).toEqual(["sdk-aes", "sdk-f43633d7", "sdk-rsa", "sdk-sign"]);
    expect(await t.listKeys({ limit: 1 })).toEqual(["sdk-aes"]);
    expect(await c.transit("othertransit").listKeys()).toEqual([]);
    expect((await rejection(c.transit("denied").listKeys())).code).toBe("PERMISSION_DENIED");
    expect((await t.rotateKey(K)).latestVersion).toBe(2);
    const updated = await t.updateKeyConfig(K, { minDecryptionVersion: 2 });
    expect(m.body()).toEqual({ min_decryption_version: 2 });
    expect(updated.minDecryptionVersion).toBe(2);
    await t.updateKeyConfig(K, {
      deletionAllowed: true,
      minEncryptionVersion: 0,
      exportable: false,
      allowPlaintextBackup: false,
      autoRotatePeriodMs: 0,
    });
    expect(m.body()).toEqual({
      deletion_allowed: true,
      min_encryption_version: 0,
      exportable: false,
      allow_plaintext_backup: false,
      auto_rotate_period: "0s",
    });
    const notAllowed = await rejection(t.deleteKey(K));
    expect(notAllowed.code).toBe("VALIDATION");
    expect(notAllowed.message).toContain("deletion is not allowed");
    await t.deleteKey(K);
  });
});

describe("Transit crypto", () => {
  it("encrypt / decrypt / rewrap round trip with binary data", async () => {
    const m = await vault({
      ...fromFixtures("transit.encrypt.ok", "transit.rewrap.ok"),
      [`POST /v1/transit/decrypt/${K}`]: [
        "transit.decrypt.ok",
        "transit.decrypt.invalid",
        "transit.decrypt.below-min-version",
        data({}),
      ],
    });
    const t = m.client().transit();
    const ct = await t.encrypt(K, new Uint8Array(BIN));
    expect(m.body()).toEqual(fixture("transit.encrypt.ok").request.body);
    expect(ct).toEqual({
      ciphertext: "vault:v1:5235Me5AzswhXGKGJJELxkbSRJ/1az7V2rJI5hC9QbYHPSaqfJxGWffKLCZqhbggDQ==",
      keyVersion: 1,
    });
    const pt = await t.decrypt(K, ct.ciphertext);
    expect(Buffer.from(pt).equals(BIN)).toBe(true);
    expect((await rejection(t.decrypt(K, "vault:v1:AAAA"))).code).toBe("VALIDATION");
    expect((await rejection(t.decrypt(K, ct.ciphertext))).message).toContain("too old");
    expect(await t.decrypt(K, ct.ciphertext)).toEqual(new Uint8Array());
    const rewrapped = await t.rewrap(K, ct.ciphertext);
    expect(rewrapped.keyVersion).toBe(2);
    expect(rewrapped.ciphertext).toMatch(/^vault:v2:/);
    await expect(t.decrypt(K, "")).rejects.toMatchObject({ code: "VALIDATION" });
  });

  it("encrypt options: text input, context, key version, associated data", async () => {
    const m = await vault({
      "POST /v1/transit/encrypt/derived": data({ ciphertext: "vault:v3:x", key_version: 3 }),
      "POST /v1/transit/decrypt/derived": data({ plaintext: "aGk=" }),
      "POST /v1/transit/rewrap/derived": data({ ciphertext: "vault:v3:y", key_version: 3 }),
      "POST /v1/transit/encrypt/broken": data({ key_version: 1 }),
    });
    const t = m.client().transit();
    await t.encrypt("derived", "hi", {
      context: "ctx",
      keyVersion: 3,
      associatedData: new Uint8Array([1, 2]),
    });
    expect(m.body()).toEqual({
      plaintext: "aGk=",
      context: "Y3R4",
      key_version: 3,
      associated_data: "AQI=",
    });
    await t.decrypt("derived", "vault:v3:x", { context: "ctx", associatedData: "ad" });
    expect(m.body()).toEqual({
      ciphertext: "vault:v3:x",
      context: "Y3R4",
      associated_data: "YWQ=",
    });
    await t.rewrap("derived", "vault:v1:x", { context: "ctx", keyVersion: 3 });
    expect(m.body()).toEqual({ ciphertext: "vault:v1:x", context: "Y3R4", key_version: 3 });
    expect((await rejection(t.encrypt("broken", "x"))).message).toContain("no ciphertext");
  });

  it("encryptBatch / decryptBatch keep order, references and per-item errors", async () => {
    const m = await vault({
      [`POST /v1/transit/encrypt/${K}`]: "transit.encryptBatch.ok",
      [`POST /v1/transit/decrypt/${K}`]: [
        "transit.decryptBatch.ok",
        "transit.decryptBatch.partial-207",
        data({}),
      ],
    });
    const t = m.client().transit();
    const enc = await t.encryptBatch(K, [
      { plaintext: "one" },
      { plaintext: "two", reference: "r2", context: "c" },
    ]);
    expect(m.body()).toEqual({
      batch_input: [{ plaintext: "b25l" }, { plaintext: "dHdv", context: "Yw==", reference: "r2" }],
      partial_failure_response_code: 207,
    });
    expect(enc).toHaveLength(2);
    expect(enc[0]).toMatchObject({ keyVersion: 2 });
    expect(enc[0]?.reference).toBeUndefined();
    expect(enc[1]?.reference).toBe("r2");
    const dec = await t.decryptBatch(
      K,
      enc.map((e) => ({ ciphertext: e.ciphertext ?? "", reference: e.reference, context: "c" })),
    );
    expect(dec.map((d) => Buffer.from(d.plaintext ?? []).toString())).toEqual(["one", "two"]);
    const partial = await t.decryptBatch(K, [{ ciphertext: "a" }, { ciphertext: "vault:v1:AAAA" }]);
    expect(Buffer.from(partial[0]?.plaintext ?? []).toString()).toBe("one");
    expect(partial[1]).toEqual({ error: "invalid ciphertext length" });
    expect((await rejection(t.decryptBatch(K, [{ ciphertext: "a" }]))).message).toContain(
      "no batch_results",
    );
    expect(await t.encryptBatch(K, [])).toEqual([]);
    expect(await t.decryptBatch(K, [])).toEqual([]);
  });

  it("generateDataKey plaintext and wrapped", async () => {
    const m = await vault(
      fromFixtures(
        "transit.generateDataKey.plaintext",
        "transit.generateDataKey.wrapped",
        "transit.decrypt.datakey",
      ),
    );
    const t = m.client().transit();
    const dk = await t.generateDataKey("sdk-aes");
    expect(m.body()).toEqual({ bits: 256 });
    expect(dk.plaintext).toHaveLength(32);
    expect(Buffer.from(await t.decrypt("sdk-aes", dk.ciphertext))).toEqual(
      Buffer.from(dk.plaintext ?? []),
    );
    const wrapped = await t.generateDataKey("sdk-aes", {
      plaintext: false,
      bits: 128,
      context: "c",
    });
    expect(m.body(-1)).toEqual({ bits: 128, context: "Yw==" });
    expect(wrapped.plaintext).toBeUndefined();
    expect(wrapped.keyVersion).toBe(1);
  });

  it("hmac, sign, verify (signature and hmac)", async () => {
    const m = await vault({
      ...fromFixtures(
        "transit.hmac.ok",
        "transit.sign.ed25519",
        "transit.sign.rsa-pkcs1v15",
        "transit.verify.rsa-valid",
        "transit.verify.hmac-valid",
      ),
      "POST /v1/transit/verify/sdk-sign": ["transit.verify.valid", "transit.verify.invalid"],
      [`POST /v1/transit/sign/${K}`]: "transit.sign.unsupported-key-type",
      "POST /v1/transit/hmac/bad": data({}),
      "POST /v1/transit/sign/bad": data({}),
    });
    const t = m.client().transit();
    const mac = await t.hmac(K, "hmac-me", { algorithm: "sha2-256" });
    expect(mac).toMatch(/^vault:v2:/);
    expect(await t.verify(K, "hmac-me", { hmac: mac }, { hashAlgorithm: "sha2-256" })).toBe(true);
    expect(m.body()).toEqual(fixture("transit.verify.hmac-valid").request.body);
    const sig = await t.sign("sdk-sign", "sign-me");
    expect(sig.keyVersion).toBe(1);
    expect(await t.verify("sdk-sign", "sign-me", { signature: sig.signature })).toBe(true);
    expect(await t.verify("sdk-sign", "tampered", { signature: sig.signature })).toBe(false);
    const rsa = await t.sign("sdk-rsa", "sign-me", {
      hashAlgorithm: "sha2-256",
      signatureAlgorithm: "pkcs1v15",
    });
    expect(m.body()).toEqual(fixture("transit.sign.rsa-pkcs1v15").request.body);
    expect(
      await t.verify(
        "sdk-rsa",
        "sign-me",
        { signature: rsa.signature },
        {
          hashAlgorithm: "sha2-256",
          signatureAlgorithm: "pkcs1v15",
          prehashed: false,
          context: "c",
        },
      ),
    ).toBe(true);
    expect((await rejection(t.sign(K, "x"))).code).toBe("VALIDATION");
    await t.hmac(K, "x", { keyVersion: 1, algorithm: "sha2-256" });
    expect(m.body()).toEqual({ input: "eA==", key_version: 1 });
    expect((await rejection(t.hmac("bad", "x"))).message).toContain("no hmac");
    expect(
      (await rejection(t.sign("bad", "x", { prehashed: true, keyVersion: 1, context: "c" })))
        .message,
    ).toContain("no signature");
    await expect(t.verify(K, "x", {} as never)).rejects.toMatchObject({ code: "VALIDATION" });
  });

  it("hash and randomBytes", async () => {
    const m = await vault({
      "POST /v1/transit/hash": ["transit.hash.default-hex", data({})],
      "POST /v1/transit/hash/sha2-256": "transit.hash.base64",
      "POST /v1/transit/random": ["transit.randomBytes.base64", data({})],
    });
    const t = m.client().transit();
    expect(await t.hash("abc")).toBe(
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    );
    expect(m.body()).toEqual({ input: "YWJj" });
    expect(await t.hash("abc", { algorithm: "sha2-256", format: "base64" })).toBe(
      "ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0=",
    );
    expect((await rejection(t.hash("abc"))).message).toContain("no sum");
    const rnd = await t.randomBytes(16);
    expect(m.body()).toEqual({ bytes: 16, format: "base64" });
    expect(Buffer.from(rnd, "base64")).toHaveLength(16);
    expect((await rejection(t.randomBytes(16, { format: "hex" }))).message).toContain(
      "no random_bytes",
    );
    await expect(t.randomBytes(0)).rejects.toMatchObject({ code: "VALIDATION" });
  });
});
