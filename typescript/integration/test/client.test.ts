// Client surface, system backend and lifecycle helpers against the real OpenBao
// (docker/compose.yml). Every public function is called with a round-trip assertion.

import assert from "node:assert/strict";
import { test } from "node:test";
import { OpenBaoClient, OpenBaoError, PermissionDeniedError } from "@grow-codes/openbao";
import { init, initStatus, seal, unseal, waitForActive } from "@grow-codes/openbao/testing";
import { env, rootClient, uid, withClient } from "./helpers.ts";

test("health reports an active node with details", async () => {
  await withClient(rootClient(), async (client) => {
    const health = await client.health();
    assert.equal(health.healthy, true, JSON.stringify(health));
    assert.equal(health.status, "active");
    assert.equal(health.details.version, env("GROW_OPENBAO_TEST_SERVER_VERSION"));
    assert.equal(health.details.sealed, "false");
  });
});

test("ping succeeds with the bootstrap credentials", async () => {
  await withClient(rootClient(), async (client) => {
    const latency = await client.ping();
    assert.equal(typeof latency, "number");
    assert.ok(latency >= 0);
  });
});

test("ping with a wrong token raises AUTHENTICATION and never leaks it", async () => {
  const wrong = "wrong-token-for-integration";
  await withClient(OpenBaoClient.fromEnv({ token: wrong }), async (client) => {
    await assert.rejects(client.ping(), (err: unknown) => {
      assert.ok(err instanceof OpenBaoError);
      assert.equal(err.code, "AUTHENTICATION");
      assert.equal(err.httpStatus, 403);
      assert.ok(!err.message.includes(wrong));
      return true;
    });
    // the same plain 403 on a data path is AUTHENTICATION too
    await assert.rejects(client.kvV2("secret").read(env("GROW_OPENBAO_TEST_ALLOWED_PATH")), {
      code: "AUTHENTICATION",
    });
  });
});

test("serverVersion, sys.version, sys.health, sealStatus and leader", async () => {
  const client = rootClient();
  try {
    const version = env("GROW_OPENBAO_TEST_SERVER_VERSION");
    assert.equal(await client.serverVersion(), version);
    assert.equal(await client.sys.version(), version);
    const h = await client.sys.health();
    assert.equal(h.state, "active");
    assert.equal(h.version, version);
    assert.ok(h.serverTime instanceof Date);
    const seal = await client.sys.sealStatus();
    assert.equal(seal.sealed, false);
    assert.equal(seal.initialized, true);
    assert.equal(seal.type, "static");
    assert.equal(seal.version, version);
    const leader = await client.sys.leader();
    assert.equal(leader.isSelf, true);
    assert.equal(leader.haEnabled, true);
    assert.match(leader.leaderAddress, /^http/);
  } finally {
    await client.close();
    await client.close();
  }
  assert.equal(client.closed, true);
  await assert.rejects(client.ping(), { code: "CONFIG" });
});

test("setToken and token: switching identities", async () => {
  await withClient(rootClient(), async (client) => {
    const child = await client.auth.createToken({ policies: ["default"], ttlMs: 600_000 });
    const root = client.token;
    client.setToken(child.clientToken);
    assert.equal(client.token?.reveal(), child.clientToken.reveal());
    const self = await client.auth.lookupSelf();
    assert.deepEqual(self.policies, ["default"]);
    client.setToken(root);
    assert.ok((await client.auth.lookupSelf()).policies.includes("root"));
  });
});

test("request(): raw API call with list and wrapping", async () => {
  await withClient(rootClient(), async (client) => {
    const history = await client.request<{ keys: string[] }>("GET", "sys/version-history", {
      list: true,
    });
    assert.ok(history.data?.keys.includes(env("GROW_OPENBAO_TEST_SERVER_VERSION")));
    const wrapped = await client.request(
      "GET",
      `secret/data/${env("GROW_OPENBAO_TEST_ALLOWED_PATH")}`,
      {
        wrapTtlMs: 60_000,
      },
    );
    assert.equal(wrapped.data, null);
    assert.ok(wrapped.wrapInfo !== undefined);
    const unwrapped = await client.wrapping.unwrap<{ data: { value: string } }>(
      wrapped.wrapInfo.token,
    );
    assert.equal(unwrapped.data?.data.value, "world");
  });
});

test("namespace header (X-Vault-Namespace) reaches the namespace mount", async (t) => {
  const ns = process.env.GROW_OPENBAO_TEST_NAMESPACE ?? "";
  if (ns === "") {
    t.skip("namespaces not available in this server");
    return;
  }
  await withClient(rootClient({ namespace: ns }), async (client) => {
    const s = await client.kv().read("sdk/in-namespace");
    assert.equal(s.data.value, "ns-only");
  });
  await withClient(rootClient(), async (client) => {
    await assert.rejects(client.kvV2("secret").read("sdk/in-namespace"), { code: "NOT_FOUND" });
  });
});

test("policy denial is PERMISSION_DENIED (not AUTHENTICATION)", async () => {
  await withClient(rootClient(), async (root) => {
    const child = await root.auth.createToken({
      policies: [env("GROW_OPENBAO_TEST_POLICY")],
      ttlMs: 600_000,
    });
    await withClient(OpenBaoClient.fromEnv({ token: child.clientToken }), async (client) => {
      const ok = await client.kv().read(env("GROW_OPENBAO_TEST_ALLOWED_PATH"));
      assert.equal(ok.data.value, "world");
      await assert.rejects(
        client.kv().read(env("GROW_OPENBAO_TEST_DENIED_PATH")),
        (err: unknown) => {
          assert.ok(err instanceof PermissionDeniedError);
          return true;
        },
      );
    });
  });
});

test("testing helpers: initStatus -> init -> unseal -> waitForActive -> seal -> unseal (Shamir)", async () => {
  const url = env("GROW_OPENBAO_TEST_SHAMIR_URL");
  await withClient(OpenBaoClient.fromEnv({ url, token: "unused" }), async (client) => {
    client.setToken(undefined);
    assert.equal(await initStatus(client), false);
    assert.equal((await client.health()).status, "uninitialized");
    const keys = await init(client, { secretShares: 1, secretThreshold: 1 });
    assert.equal(keys.keys.length, 1);
    assert.equal(keys.keysBase64.length, 1);
    assert.ok(!JSON.stringify(keys).includes(keys.rootToken.reveal()));
    assert.equal(await initStatus(client), true);
    await assert.rejects(init(client), { code: "VALIDATION" });
    assert.equal((await client.health()).status, "sealed");
    await assert.rejects(unseal(client, "not-a-key!"), { code: "VALIDATION" });
    const status = await unseal(client, keys.keys[0] ?? "");
    assert.equal(status.sealed, false);
    const active = await waitForActive(client, { timeoutMs: 30_000 });
    assert.equal(active.state, "active");
    assert.equal((await client.health()).healthy, true);
    client.setToken(keys.rootToken);
    await client.ping();
    await seal(client);
    assert.equal((await client.sys.sealStatus()).sealed, true);
    assert.equal((await client.health()).status, "sealed");
    const reset = await unseal(client, "", { reset: true });
    assert.equal(reset.progress, 0);
    assert.equal((await unseal(client, keys.keysBase64[0] ?? "")).sealed, false);
    await waitForActive(client);
  });
});

test("unique ids differ per call", () => {
  assert.notEqual(uid(), uid());
});
