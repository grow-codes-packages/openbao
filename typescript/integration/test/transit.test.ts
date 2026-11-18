// Transit engine against the real OpenBao.

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { test } from "node:test";
import { env, rootClient, uid, withClient } from "./helpers.ts";

test("keys: create/read/list/rotate/updateKeyConfig/delete", async () => {
  await withClient(rootClient(), async (client) => {
    const t = client.transit(env("GROW_OPENBAO_TEST_TRANSIT_MOUNT"));
    const name = uid("key");
    const created = await t.createKey(name, { type: "aes256-gcm96" });
    assert.equal(created.name, name);
    assert.equal(created.latestVersion, 1);
    assert.equal((await t.createKey(name)).latestVersion, 1, "createKey is idempotent");
    assert.equal((await t.readKey(name)).type, "aes256-gcm96");
    assert.ok((await t.listKeys()).includes(name));
    assert.equal((await t.listKeys({ limit: 1 })).length, 1);
    assert.equal((await t.rotateKey(name)).latestVersion, 2);
    await assert.rejects(t.deleteKey(name), { code: "VALIDATION" });
    const cfg = await t.updateKeyConfig(name, { deletionAllowed: true, minDecryptionVersion: 1 });
    assert.equal(cfg.deletionAllowed, true);
    await t.deleteKey(name);
    await assert.rejects(t.readKey(name), { code: "NOT_FOUND" });
  });
});

test("encrypt/decrypt/rewrap, min_decryption_version, batches with per-item errors", async () => {
  await withClient(rootClient(), async (client) => {
    const t = client.transit();
    const name = uid("enc");
    await t.createKey(name);
    const binary = new Uint8Array([0x67, 0x72, 0x6f, 0x77, 0x00, 0xff, 0x01]);
    const ct = await t.encrypt(name, binary);
    assert.match(ct.ciphertext, /^vault:v1:/);
    assert.deepEqual([...(await t.decrypt(name, ct.ciphertext))], [...binary]);
    await t.rotateKey(name);
    const rewrapped = await t.rewrap(name, ct.ciphertext);
    assert.equal(rewrapped.keyVersion, 2);
    assert.deepEqual([...(await t.decrypt(name, rewrapped.ciphertext))], [...binary]);
    await t.updateKeyConfig(name, { minDecryptionVersion: 2 });
    await assert.rejects(t.decrypt(name, ct.ciphertext), { code: "VALIDATION" });
    await assert.rejects(t.decrypt(name, "vault:v2:AAAA"), { code: "VALIDATION" });

    const enc = await t.encryptBatch(name, [
      { plaintext: "one" },
      { plaintext: "two", reference: "r2" },
    ]);
    assert.equal(enc.length, 2);
    assert.equal(enc[1]?.reference, "r2");
    const dec = await t.decryptBatch(name, [
      { ciphertext: enc[0]?.ciphertext ?? "" },
      { ciphertext: "vault:v2:AAAA", reference: "bad" },
      { ciphertext: enc[1]?.ciphertext ?? "", reference: "r2" },
    ]);
    assert.equal(Buffer.from(dec[0]?.plaintext ?? []).toString(), "one");
    assert.ok(dec[1]?.error !== undefined);
    assert.equal(dec[1]?.reference, "bad");
    assert.equal(Buffer.from(dec[2]?.plaintext ?? []).toString(), "two");
  });
});

test("generateDataKey (plaintext + wrapped), hmac, sign/verify, hash, randomBytes", async () => {
  await withClient(rootClient(), async (client) => {
    const t = client.transit();
    const aes = env("GROW_OPENBAO_TEST_TRANSIT_AES_KEY");
    const dk = await t.generateDataKey(aes);
    assert.equal(dk.plaintext?.length, 32);
    assert.deepEqual([...(await t.decrypt(aes, dk.ciphertext))], [...(dk.plaintext ?? [])]);
    const wrapped = await t.generateDataKey(aes, { plaintext: false, bits: 128 });
    assert.equal(wrapped.plaintext, undefined);
    assert.equal((await t.decrypt(aes, wrapped.ciphertext)).length, 16);

    const mac = await t.hmac(aes, "hmac-me", { algorithm: "sha2-256" });
    assert.match(mac, /^vault:v\d+:/);
    assert.equal(
      await t.verify(aes, "hmac-me", { hmac: mac }, { hashAlgorithm: "sha2-256" }),
      true,
    );
    assert.equal(await t.verify(aes, "other", { hmac: mac }, { hashAlgorithm: "sha2-256" }), false);

    const ed = env("GROW_OPENBAO_TEST_TRANSIT_SIGN_KEY");
    const sig = await t.sign(ed, "sign-me");
    assert.equal(await t.verify(ed, "sign-me", { signature: sig.signature }), true);
    assert.equal(await t.verify(ed, "tampered", { signature: sig.signature }), false);
    const rsa = env("GROW_OPENBAO_TEST_TRANSIT_RSA_KEY");
    const rsaSig = await t.sign(rsa, "sign-me", {
      hashAlgorithm: "sha2-256",
      signatureAlgorithm: "pkcs1v15",
    });
    assert.equal(
      await t.verify(
        rsa,
        "sign-me",
        { signature: rsaSig.signature },
        { hashAlgorithm: "sha2-256", signatureAlgorithm: "pkcs1v15" },
      ),
      true,
    );
    await assert.rejects(t.sign(aes, "x"), { code: "VALIDATION" });

    const expected = createHash("sha256").update("abc").digest();
    assert.equal(await t.hash("abc"), expected.toString("hex"));
    assert.equal(
      await t.hash("abc", { algorithm: "sha2-256", format: "base64" }),
      expected.toString("base64"),
    );
    assert.equal(Buffer.from(await t.randomBytes(16), "base64").length, 16);
    assert.match(await t.randomBytes(8, { format: "hex" }), /^[0-9a-f]{16}$/);
  });
});
