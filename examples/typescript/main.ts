// OpenBao TypeScript SDK tour: configuration from the environment, health, KV v2 (auto-detected),
// the SecretsProvider, transit encryption, dynamic database credentials (optional) and errors.
//
//   (cd ../../typescript && npm install && npm run build)   # or use the published package
//   npm install
//   BAO_ADDR=http://127.0.0.1:8200 BAO_TOKEN=... npm start
//   # optional: EXAMPLE_DB_ROLE=readonly (a database secrets engine role at database/)

import { OpenBaoClient, OpenBaoError } from "@grow-codes/openbao";

const client = OpenBaoClient.fromEnv({
  // Warnings only; the default logger is silent and never prints tokens.
  logger: { debug() {}, info() {}, warn: console.warn, error: console.error },
  hooks: {
    onError(info) {
      if (info.willRetry)
        console.error(`retrying ${info.method} ${info.url} (attempt ${info.attempt})`);
    },
  },
});
console.log(`config: ${client.config}`); // the token prints as [REDACTED]

const run = Math.random().toString(36).slice(2, 10);

try {
  const health = await client.health(); // never throws for a sealed or unreachable server
  console.log("health:", health.status, health.details.version);
  if (!health.healthy) throw new Error(`OpenBao is not active (${health.status})`);
  console.log(
    `ping: ${(await client.ping({ signal: AbortSignal.timeout(10_000) })).toFixed(1)} ms`,
  );
  console.log("server version:", await client.serverVersion());

  // KV: the version of the mount (v1/v2) is detected on first use.
  const kv = client.kv("secret");
  const path = `examples/${run}/db`;
  const written = await kv.write(path, { username: "app", password: "s3cret" });
  console.log(`kv: wrote ${path} version ${written?.version}`);
  const secret = await kv.read(path);
  console.log("kv: read back", Object.keys(secret.data), "version", secret.metadata?.version);
  await kv.patch(path, { password: "rotated" });
  console.log("kv: versions", Object.keys((await kv.readMetadata(path)).versions));

  // SecretsProvider: one value per path, redacting SecretValue, typed getters.
  const secrets = client.secrets({ path: `examples/${run}/app` });
  const version = await secrets.set("api-key", "k-123", { tags: { owner: "example" } });
  const value = await secrets.require("api-key");
  console.log(`secrets: api-key v${version} = ${value} (reveal length ${value.reveal().length})`);
  console.log(
    "secrets: list",
    (await secrets.list()).map((m) => `${m.name}@${m.version}`),
  );

  // Transit: encryption as a service (the key is created if missing).
  const transit = client.transit();
  await transit.createKey(`example-${run}`);
  const ct = await transit.encrypt(`example-${run}`, "hello transit");
  const pt = new TextDecoder().decode(await transit.decrypt(`example-${run}`, ct.ciphertext));
  console.log(`transit: ${ct.ciphertext.slice(0, 16)}… -> ${pt}`);
  await transit.updateKeyConfig(`example-${run}`, { deletionAllowed: true });
  await transit.deleteKey(`example-${run}`);

  // Dynamic database credentials kept alive by the LeaseManager (optional).
  const dbRole = process.env.EXAMPLE_DB_ROLE;
  if (dbRole !== undefined && dbRole !== "") {
    const lease = await client.database().getCredentials(dbRole);
    console.log(`database: user ${lease.data.username}, lease ${lease.leaseDurationMs / 1000}s`);
    client.leases.manage(lease, {
      revokeOnStop: true, // revoked by client.close()
      onExpire: () => console.log("database: credentials expired"),
    });
  }

  // Errors carry a canonical code; a missing secret is NOT_FOUND.
  try {
    await kv.read(`examples/${run}/missing`);
  } catch (err) {
    if (err instanceof OpenBaoError) console.log(`expected error: ${err.code}: ${err.message}`);
  }

  await kv.deleteMetadata(path);
  await secrets.delete("api-key", { permanent: true });
} catch (err) {
  if (err instanceof OpenBaoError) {
    // Canonical code + HTTP status; the message never contains credentials.
    console.error(`${err.code}: ${err.message}`, { httpStatus: err.httpStatus });
    process.exitCode = 1;
  } else {
    throw err;
  }
} finally {
  await client.close(); // stops renewers and managed leases, releases connections
}
