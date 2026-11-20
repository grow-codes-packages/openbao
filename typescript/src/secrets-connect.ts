// Service-owned: generated once by sdk-kit, then maintained in this repository.
// Connector used by `loadConfig()` (secrets/load-config.ts): a client from the GROW_SECRETS_*
// bootstrap (address, KV mount) and the package's own variables, an AppRole login when
// GROW_SECRETS_AUTH=approle, and the KV provider rooted at the mount.

import { AppRoleAuth } from "./auth.js";
import { OpenBaoClient } from "./client.js";
import type { OpenBaoConfigOptions } from "./config.js";
import type { SecretsBootstrap, SecretsConnection } from "./secrets/load-config.js";

/**
 * Builds `OpenBaoClient.fromEnv()` with `GROW_SECRETS_ADDR`/`GROW_SECRETS_KV_MOUNT` (KV v2 forced for
 * AppRole tokens, which may not read the mount preflight endpoint), logs in with AppRole when
 * `GROW_SECRETS_AUTH=approle` and returns `client.secrets({ path: "" })`; `loadConfig` reads
 * `GROW_SECRETS_PATH` below the mount.
 */
export async function connectSecrets(
  bootstrap: SecretsBootstrap,
  env: Readonly<Record<string, string | undefined>>,
): Promise<SecretsConnection> {
  const overrides: OpenBaoConfigOptions = {};
  if (bootstrap.addr !== undefined) overrides.url = bootstrap.addr;
  if (bootstrap.kvMount !== undefined) overrides.kvMount = bootstrap.kvMount;
  if (bootstrap.auth === "approle" && env["GROW_OPENBAO_KV_VERSION"] === undefined)
    overrides.kvVersion = 2;
  const client = OpenBaoClient.fromEnv(overrides);
  try {
    if (bootstrap.auth === "approle" && bootstrap.roleId !== undefined) {
      await client.auth.login(new AppRoleAuth(bootstrap.roleId.reveal(), bootstrap.secretId));
    }
  } catch (err) {
    await client.close();
    throw err;
  }
  return {
    provider: client.secrets({ path: "" }),
    path: bootstrap.path,
    close: () => client.close(),
  };
}
