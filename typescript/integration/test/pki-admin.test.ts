// PKI, policies/mounts/auth methods/AppRole admin and response wrapping against the real OpenBao.

import assert from "node:assert/strict";
import { X509Certificate } from "node:crypto";
import { test } from "node:test";
import { AppRoleAuth, OpenBaoClient } from "@grow-codes/openbao";
import { anonClient, env, eventually, makeCsr, rootClient, uid, withClient } from "./helpers.ts";

test("PKI: issue, sign CSR, read, list, revoke, CA chain, tidy", async () => {
  await withClient(rootClient(), async (client) => {
    const pki = client.pki(env("GROW_OPENBAO_TEST_PKI_MOUNT"));
    const role = env("GROW_OPENBAO_TEST_PKI_ROLE");
    const domain = env("GROW_OPENBAO_TEST_PKI_DOMAIN");
    const cn = `${uid("svc")}.${domain}`;
    const issued = await pki.issueCertificate(role, cn, {
      altNames: [`alt.${domain}`],
      ipSans: ["127.0.0.1"],
      ttlMs: 3_600_000,
    });
    const x509 = new X509Certificate(issued.certificate);
    assert.match(x509.subject, new RegExp(`CN=${cn}`));
    assert.ok(x509.subjectAltName?.includes(`DNS:alt.${domain}`));
    const chain = await pki.readCaChain();
    assert.ok(
      x509.verify(new X509Certificate(chain).publicKey),
      "issued cert verifies against the CA chain",
    );
    assert.ok(issued.privateKey.reveal().includes("PRIVATE KEY"));
    assert.ok(!JSON.stringify(issued).includes(issued.privateKey.reveal()));
    assert.equal(issued.privateKeyType, "ec");
    await assert.rejects(pki.issueCertificate(role, "evil.example.com"), { code: "VALIDATION" });

    const { csr, spkiDer } = makeCsr(`csr.${domain}`);
    const signed = await pki.signCsr(role, csr, { ttlMs: 3_600_000 });
    const signedX509 = new X509Certificate(signed.certificate);
    assert.deepEqual(signedX509.publicKey.export({ type: "spki", format: "der" }), spkiDer);
    await assert.rejects(pki.signCsr(role, "not a csr"), { code: "VALIDATION" });

    const read = await pki.readCertificate(issued.serialNumber);
    assert.equal(read.certificate.trim(), issued.certificate.trim());
    assert.equal(read.revocationTime, null);
    assert.ok((await pki.listCertificates()).includes(issued.serialNumber));
    const revoked = await pki.revokeCertificate(issued.serialNumber);
    assert.ok(revoked.revocationTime instanceof Date);
    assert.ok((await pki.readCertificate(issued.serialNumber)).revocationTime instanceof Date);
    await assert.rejects(pki.revokeCertificate("ff:ff:ff:ff"), { code: "VALIDATION" });
    await assert.rejects(pki.readCertificate("ff:ff:ff:ff"), { code: "NOT_FOUND" });

    const tidy = await pki.tidy({ safetyBufferMs: 1000, timeoutMs: 60_000 });
    assert.equal(tidy.state, "Finished");
    assert.equal((await pki.tidyStatus()).state, "Finished");
  });
});

test("policies: write/read/list/delete", async () => {
  await withClient(rootClient(), async (client) => {
    const name = uid("pol");
    const hcl = `path "secret/data/sdk/${name}/*" { capabilities = ["read"] }`;
    await client.sys.writePolicy(name, hcl);
    assert.deepEqual(await client.sys.readPolicy(name), { name, policy: hcl });
    assert.ok((await client.sys.listPolicies()).includes(name));
    await assert.rejects(client.sys.writePolicy(uid("bad"), "path { nonsense"), {
      code: "VALIDATION",
    });
    await client.sys.deletePolicy(name);
    await assert.rejects(client.sys.readPolicy(name), { code: "NOT_FOUND" });
    assert.ok(!(await client.sys.listPolicies()).includes(name));
  });
});

test("mounts and auth methods: enable/list/disable", async () => {
  await withClient(rootClient(), async (client) => {
    const mounts = await client.sys.listMounts();
    assert.equal(mounts["secret/"]?.type, "kv");
    assert.equal(mounts["secret/"]?.options.version, "2");
    const path = uid("tmp");
    await client.sys.enableSecretsEngine(path, "kv", {
      options: { version: "2" },
      description: "sdk temp",
    });
    assert.equal((await client.sys.listMounts())[`${path}/`]?.description, "sdk temp");
    await assert.rejects(client.sys.enableSecretsEngine(path, "kv"), { code: "VALIDATION" });
    await client.sys.disableSecretsEngine(path);
    assert.equal((await client.sys.listMounts())[`${path}/`], undefined);

    assert.equal((await client.sys.listAuthMethods())["approle/"]?.type, "approle");
    const auth = uid("ar");
    await client.sys.enableAuthMethod(auth, "approle", { description: "sdk temp" });
    assert.equal((await client.sys.listAuthMethods())[`${auth}/`]?.type, "approle");
    await client.sys.disableAuthMethod(auth);
    assert.equal((await client.sys.listAuthMethods())[`${auth}/`], undefined);
  });
});

test("AppRole admin: createAppRole/readRoleId/generateSecretId/listAppRoles/deleteAppRole + login", async () => {
  await withClient(rootClient(), async (client) => {
    const mount = uid("ar");
    const policy = uid("pol");
    const dir = `sdk/${uid("scoped")}`;
    await client.sys.enableAuthMethod(mount, "approle");
    await client.sys.writePolicy(policy, `path "secret/data/${dir}/*" { capabilities = ["read"] }`);
    try {
      await client.sys.createAppRole("r1", {
        mount,
        tokenPolicies: [policy],
        secretIdNumUses: 1,
        tokenTtlMs: 600_000,
      });
      assert.deepEqual(await client.sys.listAppRoles({ mount }), ["r1"]);
      const roleId = await client.sys.readRoleId("r1", { mount });
      assert.match(roleId, /^[0-9a-f-]{36}$/);
      await assert.rejects(client.sys.readRoleId("missing", { mount }), { code: "NOT_FOUND" });
      const sid = await client.sys.generateSecretId("r1", { mount, metadata: { purpose: "sdk" } });
      assert.equal(sid.secretIdNumUses, 1);
      await eventually(() => client.kv().write(`${dir}/item`, { v: "scoped" }));
      await withClient(anonClient(), async (app) => {
        const info = await app.auth.login(new AppRoleAuth(roleId, sid.secretId, { mount }));
        assert.ok(info.policies.includes(policy));
        assert.equal(info.metadata.purpose, "sdk");
        assert.deepEqual((await app.kv().read(`${dir}/item`)).data, { v: "scoped" });
        await assert.rejects(app.kv().read(env("GROW_OPENBAO_TEST_ALLOWED_PATH")), {
          code: "PERMISSION_DENIED",
        });
        // single-use secret id
        await assert.rejects(app.auth.login(new AppRoleAuth(roleId, sid.secretId, { mount })), {
          code: "AUTHENTICATION",
        });
      });
      await client.sys.deleteAppRole("r1", { mount });
      assert.deepEqual(await client.sys.listAppRoles({ mount }), []);
    } finally {
      await client.kvV2("secret").deleteMetadata(`${dir}/item`);
      await client.sys.deletePolicy(policy);
      await client.sys.disableAuthMethod(mount);
    }
  });
});

test("wrapping: wrap -> lookupWrapping -> unwrap (single use)", async () => {
  await withClient(rootClient(), async (client) => {
    const payload = { secret: uid("wrapped"), n: 1 };
    const info = await client.wrapping.wrap(payload, 60_000);
    assert.equal(info.ttlMs, 60_000);
    assert.equal(info.creationPath, "sys/wrapping/wrap");
    const lookup = await client.wrapping.lookupWrapping(info.token);
    assert.equal(lookup.creationTtlMs, 60_000);
    assert.equal(lookup.creationPath, "sys/wrapping/wrap");
    // unwrap needs no client token: the wrapping token authenticates the call
    await withClient(OpenBaoClient.fromEnv({ token: "unused-token" }), async (other) => {
      other.setToken(undefined);
      const unwrapped = await other.wrapping.unwrap(info.token);
      assert.deepEqual(unwrapped.data, payload);
      await assert.rejects(other.wrapping.unwrap(info.token), { code: "VALIDATION" });
      await assert.rejects(other.wrapping.lookupWrapping(info.token), { code: "VALIDATION" });
    });
  });
});
