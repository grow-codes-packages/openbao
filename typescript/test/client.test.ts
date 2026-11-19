import { inspect } from "node:util";
import { describe, expect, it } from "vitest";
import {
  ConfigError,
  ErrorCode,
  NotFoundError,
  PACKAGE_KEY,
  PermissionDeniedError,
  REDACTED,
  RetryPolicy,
  Secret,
  UnavailableError,
  VENDOR_ENV,
  OpenBaoClient,
  OpenBaoConfig,
  OpenBaoError,
} from "../src/index.js";
import { mapVaultError } from "../src/http.js";
import { closedPort } from "./helpers/server.js";
import { NO_CONTENT, data, errors, fixture, fx, rejection, vault } from "./support/vault.js";

describe("OpenBaoConfig", () => {
  it("uses defaults and freezes", () => {
    const c = new OpenBaoConfig();
    expect(c.url).toBe("http://127.0.0.1:8200");
    expect(c.requestTimeoutMs).toBe(30_000);
    expect(c.retry).toBeInstanceOf(RetryPolicy);
    expect(c.token).toBeUndefined();
    expect(c.namespace).toBeUndefined();
    expect(c.kvMount).toBe("secret");
    expect(c.kvVersion).toBeUndefined();
    expect(Object.isFrozen(c)).toBe(true);
    expect(OpenBaoConfig.from(c)).toBe(c);
    expect(OpenBaoConfig.from().url).toBe(c.url);
    expect(OpenBaoConfig.ENV_PREFIX).toBe(`GROW_${PACKAGE_KEY.toUpperCase()}_`);
  });

  it("keeps optional settings", () => {
    const hooks = {};
    const logger = { debug() {}, info() {}, warn() {}, error() {} };
    const c = new OpenBaoConfig({
      proxy: "http://p:1",
      userAgentSuffix: "s",
      hooks,
      logger,
      token: new Secret("abcd"),
      namespace: "team-a",
      kvMount: "/kv/",
      kvVersion: 1,
    });
    expect(c.proxy).toBe("http://p:1");
    expect(c.userAgentSuffix).toBe("s");
    expect(c.hooks).toBe(hooks);
    expect(c.logger).toBe(logger);
    expect(c.knownSecrets()).toEqual(["abcd"]);
    expect(c.namespace).toBe("team-a");
    expect(c.kvVersion).toBe(1);
    expect(new OpenBaoConfig({ namespace: "" }).namespace).toBeUndefined();
  });

  it("validate() raises ConfigError", () => {
    expect(() => new OpenBaoConfig({ url: "ftp://x" })).toThrow(ConfigError);
    expect(() => new OpenBaoConfig({ token: "   " })).toThrow(ConfigError);
    expect(() => new OpenBaoConfig({ kvMount: "//" })).toThrow(/kvMount/);
    expect(() => new OpenBaoConfig({ kvVersion: 3 as never })).toThrow(/kvVersion/);
  });

  it("core.redaction.config: toString/JSON/inspect hide credentials", () => {
    const c = new OpenBaoConfig({
      token: "super-secret-tok",
      headers: { "x-api-key": "hdr-secret" },
    });
    for (const form of [String(c), JSON.stringify(c), inspect(c), `${c.token}`]) {
      expect(form).not.toContain("super-secret-tok");
      expect(form).not.toContain("hdr-secret");
    }
    expect(String(c)).toContain(REDACTED);
    expect(String(c)).toMatch(/^OpenBaoConfig\(/);
    expect(new OpenBaoConfig().toJSON()).toMatchObject({
      token: null,
      namespace: null,
      kvMount: "secret",
      kvVersion: null,
    });
  });

  it("vendor variables: BAO_* before VAULT_*", () => {
    expect(VENDOR_ENV.url).toEqual(["BAO_ADDR", "VAULT_ADDR"]);
    expect(VENDOR_ENV.token).toEqual(["BAO_TOKEN", "VAULT_TOKEN"]);
    expect(VENDOR_ENV.namespace).toEqual(["BAO_NAMESPACE", "VAULT_NAMESPACE"]);
    expect(VENDOR_ENV.caCert).toEqual(["BAO_CACERT", "VAULT_CACERT"]);
  });

  it("core.config.env-precedence: explicit > GROW_* > vendor > default", () => {
    const env = {
      GROW_OPENBAO_URL: "http://grow:1",
      BAO_ADDR: "http://bao:2",
      VAULT_ADDR: "http://vault:3",
      VAULT_TOKEN: "vault-token",
      GROW_OPENBAO_REQUEST_TIMEOUT: "5s",
      GROW_OPENBAO_MAX_RETRIES: "7",
      VAULT_NAMESPACE: "ns-vault",
      BAO_CACERT: "/ca.pem",
      VAULT_CLIENT_CERT: "/c.pem",
      VAULT_CLIENT_KEY: "/k.pem",
      VAULT_SKIP_VERIFY: "true",
    };
    const c = OpenBaoConfig.fromEnv({}, env);
    expect(c.url).toBe("http://grow:1");
    expect(c.token?.reveal()).toBe("vault-token");
    expect(c.requestTimeoutMs).toBe(5000);
    expect(c.retry.maxRetries).toBe(7);
    expect(c.namespace).toBe("ns-vault");
    expect(c.tls).toMatchObject({
      caCertPath: "/ca.pem",
      clientCertPath: "/c.pem",
      clientKeyPath: "/k.pem",
      insecureSkipVerify: true,
    });
    expect(
      OpenBaoConfig.fromEnv({}, { BAO_ADDR: "http://bao:2", VAULT_ADDR: "http://v:3" }).url,
    ).toBe("http://bao:2");
    expect(
      OpenBaoConfig.fromEnv({}, { BAO_TOKEN: "bao", VAULT_TOKEN: "vault" }).token?.reveal(),
    ).toBe("bao");
    expect(
      OpenBaoConfig.fromEnv({}, { GROW_OPENBAO_NAMESPACE: "g", BAO_NAMESPACE: "b" }).namespace,
    ).toBe("g");
    const explicit = OpenBaoConfig.fromEnv(
      { url: "http://explicit:3", token: "explicit-token", namespace: "x" },
      env,
    );
    expect(explicit.url).toBe("http://explicit:3");
    expect(explicit.token?.reveal()).toBe("explicit-token");
    expect(explicit.namespace).toBe("x");
    expect(OpenBaoConfig.fromEnv({}, {}).url).toBe(OpenBaoConfig.DEFAULT_URL);
    expect(OpenBaoConfig.fromEnv().url).toBeTypeOf("string");
    const err = (() => {
      try {
        OpenBaoConfig.fromEnv({}, { GROW_OPENBAO_TOTAL_TIMEOUT: "forever-and-secret" });
      } catch (e) {
        return e as Error;
      }
      return undefined;
    })();
    expect(err).toBeInstanceOf(ConfigError);
    expect(err?.message).toContain("GROW_OPENBAO_TOTAL_TIMEOUT");
    expect(err?.message).not.toContain("forever-and-secret");
  });

  it("reads the KV settings of client.secrets() from the environment", async () => {
    const c = OpenBaoConfig.fromEnv(
      {},
      {
        GROW_OPENBAO_KV_MOUNT: "kv1",
        GROW_OPENBAO_KV_VERSION: "1",
        GROW_OPENBAO_SECRETS_PATH: "/apps/web/",
      },
    );
    expect([c.kvMount, c.kvVersion, c.secretsPath, c.valueField]).toEqual([
      "kv1",
      1,
      "apps/web",
      "value",
    ]);
    expect(OpenBaoConfig.fromEnv({}, { GROW_OPENBAO_KV_VERSION: "0" }).kvVersion).toBeUndefined();
    expect(OpenBaoConfig.fromEnv({ kvMount: "x" }, { GROW_OPENBAO_KV_MOUNT: "y" }).kvMount).toBe(
      "x",
    );
    expect(() => OpenBaoConfig.fromEnv({}, { GROW_OPENBAO_KV_VERSION: "3" })).toThrow(
      /GROW_OPENBAO_KV_VERSION/,
    );
    expect(() => new OpenBaoConfig({ valueField: " " })).toThrow(ConfigError);
    const client = new OpenBaoClient(
      new OpenBaoConfig({ url: "http://127.0.0.1:1", secretsPath: "base", valueField: "v" }),
    );
    const p = client.secrets();
    expect([p.path, p.valueField]).toEqual(["base", "v"]);
    expect(client.secrets({ path: "other", valueField: "w" }).path).toBe("other");
    await client.close();
  });
});

describe("OpenBaoClient basics", () => {
  it("health maps every node state and never throws", async () => {
    const m = await vault({
      "GET /v1/sys/health": [
        "health.active",
        fx("health.sealed", (b) => ({ ...b })),
        fx("health.uninitialized"),
        data(null, {}),
      ],
    });
    // sys/health answers 200 in every state thanks to the custom status codes.
    const c = m.client();
    const active = await c.health();
    expect(active).toMatchObject({ healthy: true, status: "active" });
    expect(active.details).toMatchObject({ version: "2.7.2", sealed: "false" });
    expect(new URL(m.req(0).url, "http://x").searchParams.get("sealedcode")).toBe("200");
    expect(m.req(0).headers["x-vault-token"]).toBe("root-token-test");
  });

  it("health derives sealed/uninitialized/standby/perfstandby from the body", async () => {
    const sealed = fixture("health.sealed").response.body as Record<string, unknown>;
    const uninit = fixture("health.uninitialized").response.body as Record<string, unknown>;
    const m = await vault({
      "GET /v1/sys/health": [
        { status: 200, body: sealed },
        { status: 200, body: uninit },
        { status: 200, body: { initialized: true, sealed: false, standby: true } },
        {
          status: 200,
          body: { initialized: true, sealed: false, standby: true, performance_standby: true },
        },
        { status: 200, body: "" },
        { status: 500, body: { errors: ["boom"] } },
      ],
    });
    const c = m.client();
    expect(await c.health()).toMatchObject({ healthy: false, status: "sealed" });
    expect(await c.health()).toMatchObject({ healthy: false, status: "uninitialized" });
    expect(await c.health()).toMatchObject({ healthy: false, status: "standby" });
    expect(await c.health()).toMatchObject({ healthy: false, status: "perfstandby" });
    expect(await c.health()).toMatchObject({ healthy: false, status: "unreachable" });
    expect(await c.health()).toMatchObject({
      healthy: false,
      status: "unreachable",
      details: { httpStatus: "500" },
    });
  });

  it("core.health.unreachable: closed port -> unreachable; cancellation rethrows", async () => {
    const port = await closedPort();
    const c = new OpenBaoClient({ url: `http://127.0.0.1:${port}`, retry: { maxRetries: 0 } });
    expect(await c.health()).toEqual({
      healthy: false,
      status: "unreachable",
      details: { error: "UNAVAILABLE" },
    });
    await expect(c.health({ signal: AbortSignal.abort() })).rejects.toMatchObject({
      code: "CANCELLED",
    });
    await c.close();
  });

  it("ping uses lookup-self; a bad token is AUTHENTICATION and never leaks", async () => {
    const m = await vault({
      "GET /v1/auth/token/lookup-self": ["lookupSelf.ok", "ping.invalid-token", errors(400, "x")],
    });
    const c = m.client({ token: "wrong-token-xyz" });
    expect(await c.ping()).toBeGreaterThanOrEqual(0);
    const err = await rejection(c.ping());
    expect(err).toBeInstanceOf(OpenBaoError);
    expect(err.code).toBe("AUTHENTICATION");
    expect(err.httpStatus).toBe(403);
    expect(err.message).not.toContain("wrong-token-xyz");
    expect((await rejection(c.ping())).code).toBe("AUTHENTICATION");
  });

  it("serverVersion and sys.version read sys/health", async () => {
    const m = await vault({
      "GET /v1/sys/health": ["health.active", { status: 200, body: { initialized: true } }],
    });
    const c = m.client();
    expect(await c.serverVersion()).toBe("2.7.2");
    await expect(c.serverVersion()).rejects.toMatchObject({ code: "UNSUPPORTED" });
  });

  it("core.close.idempotent: close twice; calls after close raise CONFIG", async () => {
    const m = await vault({ "GET /v1/sys/health": "health.active" });
    const c = m.client();
    await c.health();
    expect(c.closed).toBe(false);
    await c.close();
    await c.close();
    expect(c.closed).toBe(true);
    await expect(c.ping()).rejects.toMatchObject({ code: "CONFIG" });
  });

  it("fromEnv builds from GROW_* variables; namespace header is sent", async () => {
    const m = await vault({ "GET /v1/auth/token/lookup-self": "lookupSelf.ok" });
    process.env.GROW_OPENBAO_URL = m.url;
    process.env.GROW_OPENBAO_NAMESPACE = "sdk-ns";
    try {
      const c = OpenBaoClient.fromEnv({ token: "env-token" });
      expect(c.config.url).toBe(m.url);
      await c.ping();
      expect(m.req().headers["x-vault-namespace"]).toBe("sdk-ns");
      expect(m.req().headers["x-vault-token"]).toBe("env-token");
      expect(m.req().headers["user-agent"]).toMatch(/^grow-codes-openbao\/\S+ \(typescript\)$/);
      await c.close();
    } finally {
      delete process.env.GROW_OPENBAO_URL;
      delete process.env.GROW_OPENBAO_NAMESPACE;
    }
  });

  it("setToken replaces and removes the token", async () => {
    const m = await vault({ "GET /v1/auth/token/lookup-self": "lookupSelf.ok" });
    const c = m.client();
    c.setToken("other");
    expect(String(c.token)).toBe(REDACTED);
    await c.ping();
    expect(m.req().headers["x-vault-token"]).toBe("other");
    c.setToken(undefined);
    expect(c.token).toBeUndefined();
    await c.ping();
    expect(m.req().headers["x-vault-token"]).toBeUndefined();
    expect(c.transport.userAgent).toContain("grow-codes-openbao/");
  });

  it("request() calls any path with list, query, wrapping and envelope decoding", async () => {
    const m = await vault({
      "LIST /v1/sys/version-history": "version.history",
      "GET /v1/secret/data/a%20b": fx("wrapping.wrapResponse.kv2"),
      "DELETE /v1/kv1/x": NO_CONTENT,
      "PUT /v1/sys/leases/renew": "leases.renew.capped",
    });
    const c = m.client();
    const history = await c.request<{ keys: string[] }>("GET", "/sys/version-history", {
      list: true,
    });
    expect(history.data?.keys).toEqual(["2.7.2"]);
    const wrapped = await c.request("GET", "secret/data/a b", { wrapTtlMs: 60_000 });
    expect(m.req().headers["x-vault-wrap-ttl"]).toBe("60s");
    expect(wrapped.data).toBeNull();
    expect(wrapped.wrapInfo?.ttlMs).toBe(60_000);
    expect(String(wrapped.wrapInfo?.token)).toBe(REDACTED);
    const del = await c.request("DELETE", "kv1/x");
    expect(del).toMatchObject({ status: 204, data: null, leaseId: "", warnings: [] });
    const renewed = await c.request("PUT", "sys/leases/renew", { json: { lease_id: "l" } });
    expect(renewed.leaseDurationMs).toBe(7_200_000);
    expect(renewed.renewable).toBe(true);
    expect(renewed.warnings[0]).toContain("capped");
  });
});

describe("error mapping", () => {
  it("403: plain 'permission denied' = AUTHENTICATION, policy denial = PERMISSION_DENIED", async () => {
    const m = await vault({
      "GET /v1/secret/data/sdk/denied/hello": "kvV2.read.permission-denied",
      "GET /v1/secret/data/sdk/allowed/hello": "kvV2.read.missing-token",
      "GET /v1/secret/data/x": errors(403, "invalid token"),
    });
    const c = m.client({ kvVersion: 2 });
    const denied = await rejection(c.kv().read("sdk/denied/hello"));
    expect(denied).toBeInstanceOf(PermissionDeniedError);
    expect(denied.message).toMatch(
      /^kv\.read secret\/sdk\/denied\/hello: 1 error occurred: \* permission denied +\(HTTP 403\)$/,
    );
    expect((await rejection(c.kv().read("sdk/allowed/hello"))).code).toBe("AUTHENTICATION");
    expect((await rejection(c.kv().read("x"))).code).toBe("AUTHENTICATION");
  });

  it("400 CAS mismatch = CONFLICT, 405 = UNSUPPORTED, 501 = UNAVAILABLE, 429 = RATE_LIMITED", async () => {
    const m = await vault({
      "POST /v1/secret/data/a": "kvV2.write.cas-mismatch",
      "PATCH /v1/kv1/a": "kvV1.patch.unsupported",
      "GET /v1/secret/data/b": errors(501, "Vault is not initialized"),
      "GET /v1/kv1/sdk/allowed/hello": "errors.rate-limited",
      "GET /v1/secret/data/c": errors(400, "bad"),
    });
    const c = m.client({ kvVersion: 2 });
    const cas = await rejection(c.kv().write("a", { v: 1 }, { cas: 9 }));
    expect(cas.code).toBe("CONFLICT");
    expect(cas.httpStatus).toBe(400);
    expect((await rejection(c.request("PATCH", "kv1/a", { json: {} }))).code).toBe("UNSUPPORTED");
    const unavailable = await rejection(c.kv().read("b"));
    expect(unavailable).toBeInstanceOf(UnavailableError);
    const limited = await rejection(c.kvV1("kv1").read("sdk/allowed/hello"));
    expect(limited.code).toBe("RATE_LIMITED");
    expect(limited.retryAfterMs).toBe(29_000);
    expect((await rejection(c.kv().read("c"))).code).toBe("VALIDATION");
  });

  it("404 = NOT_FOUND; mapVaultError keeps other errors", () => {
    const e = new NotFoundError("x");
    expect(mapVaultError(e)).toBe(e);
    const p = new PermissionDeniedError("op: 1 error occurred (HTTP 403)", { httpStatus: 403 });
    expect(mapVaultError(p)).toBe(p);
    const login = mapVaultError(
      new OpenBaoError(ErrorCode.Validation, "op: invalid role (HTTP 400)", {
        httpStatus: 400,
        requestId: "r1",
        retryAfterMs: 5,
        cause: new Error("c"),
      }),
      true,
    );
    expect(login).toMatchObject({ code: "AUTHENTICATION", requestId: "r1", retryAfterMs: 5 });
  });

  it("transient 5xx is retried for idempotent requests", async () => {
    const m = await vault({
      "GET /v1/sys/seal-status": [errors(502, "bad gateway"), "sealStatus.unsealed"],
    });
    const c = m.client({ retry: { maxRetries: 2, initialBackoffMs: 1 } });
    expect((await c.sys.sealStatus()).sealed).toBe(false);
    expect(m.requests).toHaveLength(2);
  });
});
