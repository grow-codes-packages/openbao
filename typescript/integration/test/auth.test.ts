// Auth methods, token self-service and token renewal against the real OpenBao.

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  AppRoleAuth,
  AuthenticationError,
  JwtAuth,
  KubernetesAuth,
  OpenBaoClient,
  TokenAuth,
  UserpassAuth,
} from "@grow-codes/openbao";
import { anonClient, env, rootClient, withClient } from "./helpers.ts";

const allowed = () => env("GROW_OPENBAO_TEST_ALLOWED_PATH");
const denied = () => env("GROW_OPENBAO_TEST_DENIED_PATH");

async function scopedReadWorks(client: OpenBaoClient): Promise<void> {
  assert.equal((await client.kv().read(allowed())).data.value, "world");
  await assert.rejects(client.kv().read(denied()), { code: "PERMISSION_DENIED" });
}

test("AppRoleAuth: login sets a scoped token; bad secret is AUTHENTICATION", async () => {
  await withClient(anonClient(), async (client) => {
    const info = await client.auth.login(
      new AppRoleAuth(
        env("GROW_OPENBAO_TEST_APPROLE_ROLE_ID"),
        env("GROW_OPENBAO_TEST_APPROLE_SECRET_ID"),
        {
          mount: env("GROW_OPENBAO_TEST_APPROLE_MOUNT"),
        },
      ),
    );
    assert.equal(info.metadata.role_name, env("GROW_OPENBAO_TEST_APPROLE_ROLE"));
    assert.ok(info.policies.includes(env("GROW_OPENBAO_TEST_POLICY")));
    assert.equal(client.token?.reveal(), info.clientToken.reveal());
    await scopedReadWorks(client);
    await assert.rejects(
      client.auth.login(
        new AppRoleAuth(env("GROW_OPENBAO_TEST_APPROLE_ROLE_ID"), "wrong-secret-id"),
      ),
      (err: unknown) =>
        err instanceof AuthenticationError && !err.message.includes("wrong-secret-id"),
    );
  });
});

test("UserpassAuth: login and wrong password", async () => {
  await withClient(anonClient(), async (client) => {
    const info = await client.auth.login(
      new UserpassAuth(
        env("GROW_OPENBAO_TEST_USERPASS_USER"),
        env("GROW_OPENBAO_TEST_USERPASS_PASSWORD"),
        {
          mount: env("GROW_OPENBAO_TEST_USERPASS_MOUNT"),
        },
      ),
    );
    assert.equal(info.metadata.username, env("GROW_OPENBAO_TEST_USERPASS_USER"));
    await scopedReadWorks(client);
    await assert.rejects(
      client.auth.login(new UserpassAuth(env("GROW_OPENBAO_TEST_USERPASS_USER"), "nope")),
      {
        code: "AUTHENTICATION",
      },
    );
  });
});

test("JwtAuth: login with the static test key; expired JWT is AUTHENTICATION", async () => {
  await withClient(anonClient(), async (client) => {
    const info = await client.auth.login(
      new JwtAuth(env("GROW_OPENBAO_TEST_JWT_ROLE"), env("GROW_OPENBAO_TEST_JWT"), {
        mount: env("GROW_OPENBAO_TEST_JWT_MOUNT"),
      }),
    );
    assert.equal(info.metadata.role, env("GROW_OPENBAO_TEST_JWT_ROLE"));
    await scopedReadWorks(client);
    await assert.rejects(
      client.auth.login(
        new JwtAuth(env("GROW_OPENBAO_TEST_JWT_ROLE"), env("GROW_OPENBAO_TEST_JWT_EXPIRED")),
      ),
      { code: "AUTHENTICATION" },
    );
  });
});

test("KubernetesAuth: request reaches the server (no Kubernetes API -> AUTHENTICATION)", async () => {
  // The fixture has no Kubernetes API for TokenReview; the success path is unit-tested.
  await withClient(anonClient(), async (client) => {
    await assert.rejects(
      client.auth.login(
        new KubernetesAuth(env("GROW_OPENBAO_TEST_K8S_ROLE"), {
          jwt: env("GROW_OPENBAO_TEST_K8S_JWT"),
          mount: env("GROW_OPENBAO_TEST_K8S_MOUNT"),
        }),
      ),
      (err: unknown) => err instanceof AuthenticationError && err.httpStatus === 403,
    );
    assert.equal(client.token, undefined);
  });
});

test("TokenAuth, createToken, lookupSelf, renewSelf, revokeSelf", async () => {
  await withClient(rootClient(), async (root) => {
    const child = await root.auth.createToken({
      policies: [env("GROW_OPENBAO_TEST_POLICY")],
      ttlMs: 600_000,
      explicitMaxTtlMs: 3_600_000,
      renewable: true,
      displayName: "ts-int",
      meta: { suite: "typescript" },
      numUses: 0,
    });
    assert.equal(child.renewable, true);
    assert.equal(child.leaseDurationMs, 600_000);
    assert.deepEqual(child.metadata, { suite: "typescript" });
    const orphan = await root.auth.createToken({
      policies: ["default"],
      noParent: true,
      ttlMs: 60_000,
    });
    assert.equal(orphan.orphan, true);

    await withClient(anonClient(), async (client) => {
      const info = await client.auth.login(new TokenAuth(child.clientToken));
      assert.ok(info.policies.includes(env("GROW_OPENBAO_TEST_POLICY")));
      const self = await client.auth.lookupSelf();
      assert.equal(self.displayName, "token-ts-int");
      assert.deepEqual(self.meta, { suite: "typescript" });
      assert.equal(self.renewable, true);
      assert.ok(self.ttlMs > 0 && self.ttlMs <= 600_000);
      assert.equal(self.explicitMaxTtlMs, 3_600_000);
      const renewed = await client.auth.renewSelf(1_200_000);
      assert.equal(renewed.leaseDurationMs, 1_200_000);
      assert.ok((await client.auth.lookupSelf()).ttlMs > 600_000);
      // a scoped token cannot create tokens
      await assert.rejects(client.auth.createToken({ policies: ["default"] }), {
        code: "PERMISSION_DENIED",
      });
      await client.auth.revokeSelf();
      assert.equal(client.token, undefined);
      await assert.rejects(client.auth.login(new TokenAuth(child.clientToken)), {
        code: "AUTHENTICATION",
      });
    });
    const nonRenewable = await root.auth.createToken({
      policies: ["default"],
      renewable: false,
      ttlMs: 60_000,
    });
    await withClient(OpenBaoClient.fromEnv({ token: nonRenewable.clientToken }), async (client) => {
      await assert.rejects(client.auth.renewSelf(60_000), { code: "VALIDATION" });
    });
  });
});

test("TokenRenewer: startRenewer renews a short token; login autoRenew re-logs in", async () => {
  await withClient(rootClient(), async (root) => {
    const child = await root.auth.createToken({
      policies: ["default"],
      ttlMs: 3000,
      renewable: true,
    });
    await withClient(OpenBaoClient.fromEnv({ token: child.clientToken }), async (client) => {
      const renewed = new Promise<number>((resolve) => {
        void client.auth.startRenewer({ incrementMs: 3000, onRenew: (r) => resolve(r.ttlMs) });
      });
      const ttl = await Promise.race([
        renewed,
        new Promise<number>((_, j) => setTimeout(() => j(new Error("no renewal")), 10_000)),
      ]);
      assert.ok(ttl > 0);
      assert.equal(client.auth.activeRenewers, 1);
    });
  });
  // userpass tokens are renewable up to token_max_ttl; autoRenew keeps the login alive
  await withClient(anonClient(), async (client) => {
    await client.auth.login(
      new UserpassAuth(
        env("GROW_OPENBAO_TEST_USERPASS_USER"),
        env("GROW_OPENBAO_TEST_USERPASS_PASSWORD"),
      ),
      { autoRenew: true },
    );
    assert.equal(client.auth.activeRenewers, 1);
    await client.ping();
  });
});
