// Database engine (PostgreSQL sidecar) and leases against the real OpenBao.

import assert from "node:assert/strict";
import { test } from "node:test";
import { env, eventually, rootClient, uid, withClient } from "./helpers.ts";

const RO_SQL = [
  `CREATE ROLE "{{name}}" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}';`,
  `GRANT SELECT ON public.sdk_probe TO "{{name}}";`,
];

test("configureConnection/readConnection/createRole/readRole/getCredentials/delete*", async () => {
  await withClient(rootClient(), async (client) => {
    const db = client.database(env("GROW_OPENBAO_TEST_DB_MOUNT"));
    const conn = uid("pg");
    const role = uid("ro");
    const url = `postgresql://{{username}}:{{password}}@${env("GROW_OPENBAO_TEST_PG_HOST")}:${env("GROW_OPENBAO_TEST_PG_PORT")}/${env("GROW_OPENBAO_TEST_PG_DB")}?sslmode=disable`;
    await db.configureConnection(conn, {
      pluginName: "postgresql-database-plugin",
      connectionUrl: url,
      username: env("GROW_OPENBAO_TEST_PG_ADMIN_USER"),
      password: env("GROW_OPENBAO_TEST_PG_ADMIN_PASSWORD"),
      allowedRoles: [role],
      verifyConnection: true,
    });
    const info = await db.readConnection(conn);
    assert.equal(info.pluginName, "postgresql-database-plugin");
    assert.deepEqual(info.allowedRoles, [role]);
    assert.equal(info.connectionDetails.username, env("GROW_OPENBAO_TEST_PG_ADMIN_USER"));
    assert.ok(!JSON.stringify(info).includes(env("GROW_OPENBAO_TEST_PG_ADMIN_PASSWORD")));
    await assert.rejects(
      db.configureConnection(uid("pgbad"), {
        pluginName: "postgresql-database-plugin",
        connectionUrl: url,
        username: "postgres",
        password: "definitely-wrong-password",
      }),
      (err: unknown) =>
        (err as { code?: string }).code === "VALIDATION" &&
        !String(err).includes("definitely-wrong-password"),
    );

    await db.createRole(role, {
      dbName: conn,
      creationStatements: RO_SQL,
      defaultTtlMs: 3_600_000,
      maxTtlMs: 7_200_000,
    });
    const r = await db.readRole(role);
    assert.equal(r.dbName, conn);
    assert.equal(r.defaultTtlMs, 3_600_000);
    assert.equal(r.maxTtlMs, 7_200_000);
    assert.equal(r.creationStatements.length, 2);

    const lease = await db.getCredentials(role);
    assert.ok(lease.leaseId.startsWith(`${db.mount}/creds/${role}/`));
    assert.equal(lease.renewable, true);
    assert.equal(lease.leaseDurationMs, 3_600_000);
    assert.match(lease.data.username, /^v-/);
    assert.ok(lease.data.password.reveal().length > 8);
    assert.ok(!JSON.stringify(lease).includes(lease.data.password.reveal()));

    const looked = await client.leases.lookup(lease.leaseId);
    assert.equal(looked.id, lease.leaseId);
    assert.equal(looked.renewable, true);
    const renewed = await client.leases.renew(lease.leaseId, 600_000);
    assert.equal(renewed.leaseDurationMs, 600_000);
    const capped = await client.leases.renew(lease.leaseId, 100 * 3_600_000);
    assert.ok(capped.leaseDurationMs <= 7_200_000);
    assert.ok(capped.warnings.some((w) => w.includes("capped")));
    await client.leases.revoke(lease.leaseId);
    await assert.rejects(client.leases.lookup(lease.leaseId), { code: "VALIDATION" });
    await assert.rejects(client.leases.renew(lease.leaseId), { code: "VALIDATION" });

    const a = await db.getCredentials(role);
    await client.leases.revokePrefix(`${db.mount}/creds/${role}`);
    await assert.rejects(client.leases.lookup(a.leaseId), { code: "VALIDATION" });
    await assert.rejects(db.getCredentials(uid("no-such-role")), { code: "VALIDATION" });

    await db.deleteRole(role);
    await assert.rejects(db.readRole(role), { code: "NOT_FOUND" });
    await db.deleteConnection(conn);
    await assert.rejects(db.readConnection(conn), { code: "NOT_FOUND" });
  });
});

test("LeaseManager.manage renews a short lease and fires onExpire once at max TTL", async () => {
  await withClient(rootClient(), async (client) => {
    const db = client.database(env("GROW_OPENBAO_TEST_DB_MOUNT"));
    // sdk-short: default_ttl 10 s, max_ttl 30 s
    const lease = await db.getCredentials(env("GROW_OPENBAO_TEST_DB_SHORT_ROLE"));
    assert.equal(lease.leaseDurationMs, 10_000);
    let renewals = 0;
    let expired = 0;
    let errorsSeen = 0;
    const done = new Promise<void>((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error("onExpire did not fire")), 45_000);
      client.leases.manage(lease, {
        incrementMs: 10_000,
        onRenew: () => {
          renewals++;
        },
        onError: () => {
          errorsSeen++;
        },
        onExpire: () => {
          expired++;
          clearTimeout(timer);
          resolve();
        },
      });
    });
    await done;
    assert.ok(renewals >= 1, `renewals: ${renewals}`);
    assert.equal(expired, 1);
    assert.equal(client.leases.activeLeases, 0);
    assert.equal(errorsSeen, 0);
    // the server revokes expired leases asynchronously
    await eventually(() =>
      assert.rejects(client.leases.lookup(lease.leaseId), { code: "VALIDATION" }),
    );
  });
});

test("manage with revokeOnStop revokes when the client closes", async () => {
  const client = rootClient();
  const lease = await client.database().getCredentials(env("GROW_OPENBAO_TEST_DB_ROLE"));
  const handle = client.leases.manage(lease, { revokeOnStop: true });
  assert.equal(handle.running, true);
  await client.close();
  assert.equal(handle.running, false);
  await withClient(rootClient(), async (check) => {
    await assert.rejects(check.leases.lookup(lease.leaseId), { code: "VALIDATION" });
  });
});
