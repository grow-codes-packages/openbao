// SecretsProvider extras on the real OpenBao (beyond the conformance scenarios): bytes, objects,
// versions, cas, tags/description, delete modes, list metadata, SecretCache, watch, loadEnv.

import assert from "node:assert/strict";
import { test } from "node:test";
import { SecretCache } from "@grow-codes/openbao";
import { env, rootClient, uid, withClient } from "./helpers.ts";

test("provider on KV v2: values, versions, cas, tags, metadata, list, delete modes", async () => {
  await withClient(rootClient(), async (client) => {
    const base = `sdk/test/${uid("prov")}`;
    const p = client.secrets({ mount: env("GROW_OPENBAO_TEST_KV2_MOUNT"), path: base });
    assert.equal(await p.set("text", "s3cret"), "1");
    assert.equal(await p.set("text", "s3cret-2", { cas: 1 }), "2");
    await assert.rejects(p.set("text", "x", { cas: 1 }), { code: "CONFLICT" });
    assert.equal((await p.get("text"))?.reveal(), "s3cret-2");
    assert.equal((await p.get("text", { version: "1" }))?.reveal(), "s3cret");
    assert.equal((await p.get("text"))?.version, "2");
    // stored shape is {"value": ...} (DECISIONS #1)
    assert.deepEqual((await client.kvV2().read(`${base}/text`)).data, { value: "s3cret-2" });

    await p.set("bin", new Uint8Array([0, 255, 1]));
    assert.deepEqual((await client.kvV2().read(`${base}/bin`)).data, {
      value: "AP8B",
      encoding: "base64",
    });
    assert.deepEqual([...((await p.get("bin"))?.revealBytes() ?? [])], [0, 255, 1]);
    await p.set("obj", { a: 1, b: "two" });
    assert.deepEqual(await p.getJson("obj"), { a: 1, b: "two" });
    await client.kvV2().write(`${base}/multi`, { user: "u", pass: "p" });
    assert.deepEqual(await p.getJson("multi"), { user: "u", pass: "p" });

    await p.set("tagged", "v", { tags: { owner: "sdk" }, description: "desc" });
    const meta = await p.metadata("tagged");
    assert.deepEqual(meta?.tags, { owner: "sdk", description: "desc" });
    assert.equal(meta?.version, "1");
    assert.ok(meta?.createdAt instanceof Date);

    await p.set("dir/nested", "n");
    const listed = await p.list();
    assert.deepEqual(
      listed.map((m) => m.name),
      ["bin", "multi", "obj", "tagged", "text"],
    );
    assert.equal(listed.find((m) => m.name === "text")?.versions, 2);
    assert.deepEqual(
      (await p.list("dir")).map((m) => m.name),
      ["dir/nested"],
    );

    await p.delete("text", { versions: ["1"] });
    assert.equal(await p.get("text", { version: "1" }), null);
    assert.equal((await p.get("text"))?.reveal(), "s3cret-2");
    await p.delete("text");
    assert.equal(await p.get("text"), null);
    assert.equal(await p.metadata("text"), null);
    await assert.rejects(p.delete("text"), { code: "NOT_FOUND" });
    await p.delete("obj", { permanent: true });
    await assert.rejects(client.kvV2().readMetadata(`${base}/obj`), { code: "NOT_FOUND" });
    for (const name of ["bin", "multi", "tagged", "dir/nested"])
      await p.delete(name, { permanent: true });
  });
});

test("provider on KV v1: unversioned semantics", async () => {
  await withClient(rootClient(), async (client) => {
    const p = client.secrets({
      mount: env("GROW_OPENBAO_TEST_KV1_MOUNT"),
      path: `sdk/test/${uid("v1")}`,
    });
    assert.equal(await p.set("a", "1"), "");
    assert.equal((await p.get("a"))?.version, undefined);
    await assert.rejects(p.set("a", "2", { cas: 0 }), { code: "UNSUPPORTED" });
    await assert.rejects(p.get("a", { version: "1" }), { code: "VALIDATION" });
    assert.deepEqual(await p.metadata("a"), { name: "a", tags: {}, extra: {} });
    await p.delete("a");
    await assert.rejects(p.delete("a"), { code: "NOT_FOUND" });
  });
});

test("SecretCache, watch and loadEnv over the provider", async () => {
  await withClient(rootClient(), async (client) => {
    const p = client.secrets({ path: `sdk/test/${uid("cache")}` });
    await p.set("api-key", "k1");
    const cache = new SecretCache(p, { ttlMs: 60_000 });
    assert.equal(await cache.getString("api-key"), "k1");
    assert.equal(await cache.getString("api-key"), "k1");
    assert.equal(cache.stats().hits, 1);

    const changes: (string | null)[] = [];
    const handle = p.watch("api-key", 100, (n) => {
      changes.push(n?.reveal() ?? null);
    });
    await handle.ready;
    await p.set("api-key", "k2");
    const deadline = Date.now() + 5000;
    while (!changes.includes("k2") && Date.now() < deadline)
      await new Promise((r) => setTimeout(r, 50));
    assert.ok(changes.includes("k2"), JSON.stringify(changes));

    const target: Record<string, string | undefined> = {};
    assert.deepEqual(await p.loadEnv("", { env: target, prefix: "TS_" }), {
      TS_API_KEY: "api-key",
    });
    assert.equal(target.TS_API_KEY, "k2");
    await p.delete("api-key", { permanent: true });
  });
});
