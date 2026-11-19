// KV v1 + v2 (explicit and auto-detected mounts) against the real OpenBao.

import assert from "node:assert/strict";
import { test } from "node:test";
import { KvV1, KvV2, OpenBaoClient } from "@grow-codes/openbao";
import { env, eventually, rootClient, uid, withClient } from "./helpers.ts";

test("KvV2: write/read/patch/versions/delete/undelete/destroy/list/metadata round trip", async () => {
  await withClient(rootClient(), async (client) => {
    const kv = client.kvV2(env("GROW_OPENBAO_TEST_KV2_MOUNT"));
    const dir = `sdk/test/${uid()}`;
    const p = `${dir}/alpha`;
    const v1 = await kv.write(p, { a: "1", b: "2" }, { cas: 0 });
    assert.equal(v1.version, 1);
    await assert.rejects(kv.write(p, { a: "x" }, { cas: 0 }), { code: "CONFLICT" });
    const v2 = await kv.write(p, { a: "1", b: "3" }, { cas: 1 });
    assert.equal(v2.version, 2);
    const latest = await kv.read(p);
    assert.deepEqual(latest.data, { a: "1", b: "3" });
    assert.equal(latest.metadata?.version, 2);
    assert.deepEqual((await kv.read(p, { version: 1 })).data, { a: "1", b: "2" });
    const patched = await kv.patch(p, { c: "4", b: null });
    assert.equal(patched.version, 3);
    assert.deepEqual((await kv.read(p)).data, { a: "1", c: "4" });
    await assert.rejects(kv.patch(p, { d: "x" }, { cas: 1 }), { code: "CONFLICT" });
    await kv.write(`${dir}/beta`, { v: "b" });
    await kv.write(`${dir}/sub/gamma`, { v: "g" });
    assert.deepEqual(await kv.list(dir), ["alpha", "beta", "sub/"]);
    assert.deepEqual(await kv.list(dir, { limit: 1 }), ["alpha"]);
    assert.deepEqual(await kv.list(dir, { after: "alpha", limit: 1 }), ["beta"]);
    assert.deepEqual(await kv.list(`${dir}/nothing-here`), []);

    await kv.writeMetadata(p, {
      maxVersions: 5,
      casRequired: false,
      deleteVersionAfterMs: 720 * 3_600_000,
      customMetadata: { owner: "sdk" },
    });
    const md = await kv.readMetadata(p);
    assert.equal(md.currentVersion, 3);
    assert.equal(md.maxVersions, 5);
    assert.equal(md.deleteVersionAfterMs, 720 * 3_600_000);
    assert.deepEqual(md.customMetadata, { owner: "sdk" });
    assert.deepEqual(Object.keys(md.versions).sort(), ["1", "2", "3"]);

    await kv.delete(p);
    await assert.rejects(kv.read(p), { code: "NOT_FOUND" });
    assert.ok((await kv.readMetadata(p)).versions["3"]?.deletionTime instanceof Date);
    await kv.undelete(p, [3]);
    assert.deepEqual((await kv.read(p)).data, { a: "1", c: "4" });
    await kv.deleteVersions(p, [2]);
    await assert.rejects(kv.read(p, { version: 2 }), { code: "NOT_FOUND" });
    await kv.destroy(p, [1]);
    assert.equal((await kv.readMetadata(p)).versions["1"]?.destroyed, true);
    await assert.rejects(kv.read(p, { version: 1 }), { code: "NOT_FOUND" });
    await kv.deleteMetadata(p);
    await assert.rejects(kv.readMetadata(p), { code: "NOT_FOUND" });
    assert.deepEqual(await kv.list(dir), ["beta", "sub/"]);
    // deleting a missing path is not an error at the KV level (204)
    await kv.delete(`${dir}/never-existed`);
    await kv.deleteMetadata(`${dir}/never-existed`);
  });
});

test("KvV1: write/read/list/delete; v2-only operations are UNSUPPORTED", async () => {
  await withClient(rootClient(), async (client) => {
    const kv = client.kvV1(env("GROW_OPENBAO_TEST_KV1_MOUNT"));
    const dir = `sdk/test/${uid()}`;
    assert.equal(await kv.write(`${dir}/alpha`, { a: "1", n: 2 }), null);
    assert.deepEqual((await kv.read(`${dir}/alpha`)).data, { a: "1", n: 2 });
    await kv.write(`${dir}/alpha`, { a: "2" });
    assert.deepEqual((await kv.read(`${dir}/alpha`)).data, { a: "2" });
    await kv.write(`${dir}/with space`, { v: "s" });
    assert.deepEqual((await kv.read(`${dir}/with space`)).data, { v: "s" });
    assert.deepEqual(await kv.list(dir), ["alpha", "with space"]);
    await assert.rejects(kv.patch(), { code: "UNSUPPORTED" });
    await assert.rejects(kv.read(`${dir}/alpha`, { version: 1 }), { code: "UNSUPPORTED" });
    await kv.delete(`${dir}/alpha`);
    await assert.rejects(kv.read(`${dir}/alpha`), { code: "NOT_FOUND" });
    await kv.delete(`${dir}/never-existed`);
    assert.deepEqual(await kv.list(`${dir}/nothing`), []);
    // the server itself rejects PATCH on KV v1 with 405 -> UNSUPPORTED
    await assert.rejects(
      client.request("PATCH", `${kv.mount}/${dir}/with space`, {
        json: { v: "x" },
        headers: { "content-type": "application/merge-patch+json" },
      }),
      {
        code: "UNSUPPORTED",
      },
    );
  });
});

test("KvMount auto-detects v1/v2 (also for a restricted token) and kvVersion skips detection", async () => {
  await withClient(rootClient(), async (client) => {
    const v2 = client.kv(env("GROW_OPENBAO_TEST_KV2_MOUNT"));
    assert.equal(await v2.version({ path: env("GROW_OPENBAO_TEST_ALLOWED_PATH") }), 2);
    assert.ok((await v2.engine()) instanceof KvV2);
    const v1 = client.kv(env("GROW_OPENBAO_TEST_KV1_MOUNT"));
    assert.equal((await v1.read(env("GROW_OPENBAO_TEST_ALLOWED_PATH"))).data.value, "world");
    assert.ok((await v1.engine()) instanceof KvV1);
    await assert.rejects(v1.readMetadata("x"), { code: "UNSUPPORTED" });
    await assert.rejects(client.kv("no-such-mount").read("x"), { code: "PERMISSION_DENIED" });

    // a scoped token detects through sys/internal/ui/mounts/<mount>/<path>
    const child = await client.auth.createToken({
      policies: [env("GROW_OPENBAO_TEST_POLICY")],
      ttlMs: 600_000,
    });
    await withClient(OpenBaoClient.fromEnv({ token: child.clientToken }), async (scoped) => {
      const kv = scoped.kv();
      assert.equal((await kv.read(env("GROW_OPENBAO_TEST_ALLOWED_PATH"))).data.value, "world");
      assert.equal(await kv.version(), 2);
      const p = `sdk/allowed/${uid()}`;
      await kv.write(p, { v: "scoped" });
      assert.deepEqual((await kv.read(p)).data, { v: "scoped" });
      assert.ok((await kv.list("sdk/allowed")).includes(p.split("/").at(-1) ?? ""));
      await kv.patch(p, { w: "2" });
      await kv.delete(p);
      assert.equal((await kv.readMetadata(p)).currentVersion, 2);
      // the sdk-app policy has no capability on secret/destroy/*
      await assert.rejects(kv.destroy(p, [1]), { code: "PERMISSION_DENIED" });
      await kv.deleteMetadata(p);
      await assert.rejects(kv.writeMetadata(p, { maxVersions: 1 }), { code: "PERMISSION_DENIED" });
    });
    await withClient(rootClient({ kvVersion: 2 }), async (fixed) => {
      assert.equal(await fixed.kv().version(), 2);
      assert.equal(
        (await fixed.kv().read(env("GROW_OPENBAO_TEST_SENTINEL_PATH"))).data.value,
        "survives-restart",
      );
    });
  });
});

test("a freshly enabled KV v2 mount works after its upgrade window", async () => {
  await withClient(rootClient(), async (client) => {
    const mount = uid("kv");
    await client.sys.enableSecretsEngine(mount, "kv", { options: { version: "2" } });
    try {
      const kv = client.kv(mount);
      await eventually(() => kv.write("a", { v: "1" }));
      assert.equal(await kv.version(), 2);
      assert.deepEqual((await kv.read("a")).data, { v: "1" });
    } finally {
      await client.sys.disableSecretsEngine(mount);
    }
  });
});
