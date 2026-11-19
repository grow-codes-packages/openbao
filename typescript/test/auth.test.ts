import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { inspect } from "node:util";
import { describe, expect, it, vi } from "vitest";
import {
  AppRoleAuth,
  AuthenticationError,
  ConfigError,
  JwtAuth,
  KubernetesAuth,
  REDACTED,
  Secret,
  TokenAuth,
  TokenRenewer,
  UserpassAuth,
} from "../src/index.js";
import { ManualScheduler } from "./support/clock.js";
import {
  NO_CONTENT,
  errors,
  fixture,
  fx,
  fromFixtures,
  rejection,
  vault,
} from "./support/vault.js";

/** A login response whose token is `token`. */
function loginWith(name: string, token: string, ttl?: number, renewable?: boolean) {
  return fx(name, (b) => ({
    ...b,
    auth: {
      ...b.auth,
      client_token: token,
      ...(ttl === undefined ? {} : { lease_duration: ttl }),
      ...(renewable === undefined ? {} : { renewable }),
    },
  }));
}

describe("auth methods", () => {
  it("AppRoleAuth posts role_id/secret_id without a token and sets the new token", async () => {
    const m = await vault({
      "POST /v1/auth/approle/login": loginWith("appRoleLogin.ok", "s.approle"),
      "GET /v1/auth/token/lookup-self": "lookupSelf.ok",
    });
    const c = m.client();
    const method = new AppRoleAuth("role-1", "secret-1");
    const info = await c.auth.login(method);
    expect(m.req(0).headers["x-vault-token"]).toBeUndefined();
    expect(m.body(0)).toEqual({ role_id: "role-1", secret_id: "secret-1" });
    expect(info.clientToken.reveal()).toBe("s.approle");
    expect(info.metadata).toEqual({ role_name: "sdk-app" });
    expect(info.policies).toEqual(["default", "sdk-app"]);
    expect(info.leaseDurationMs).toBe(3_600_000);
    expect(info.renewable).toBe(true);
    expect(info.tokenType).toBe("service");
    expect(String(info.accessor)).toBe(REDACTED);
    expect(JSON.stringify(info)).not.toContain("s.approle");
    expect(String(method)).not.toContain("secret-1");
    await c.ping();
    expect(m.req().headers["x-vault-token"]).toBe("s.approle");
  });

  it("AppRoleAuth with a custom mount, no secret id, setToken=false", async () => {
    const m = await vault(fromFixtures("appRoleLogin.custom-mount"));
    const c = m.client();
    const info = await c.auth.login(
      new AppRoleAuth("0a235ec1-2d7d-fd7a-8b4f-8a684196312e", undefined, {
        mount: "/ar-f43633d7/",
      }),
      { setToken: false },
    );
    expect(m.body()).toEqual({ role_id: "0a235ec1-2d7d-fd7a-8b4f-8a684196312e" });
    expect(info.clientToken).toBeInstanceOf(Secret);
    expect(c.token?.reveal()).toBe("root-token-test");
  });

  it("failed logins raise AUTHENTICATION (400 and 403)", async () => {
    const m = await vault({
      "POST /v1/auth/approle/login": "appRoleLogin.invalid-secret",
      "POST /v1/auth/userpass/login/sdk-user": "userpassLogin.invalid-password",
      "POST /v1/auth/jwt/login": ["jwtLogin.expired", "jwtLogin.malformed"],
      "POST /v1/auth/kubernetes/login": "kubernetesLogin.no-kubernetes-api",
    });
    const c = m.client();
    const e1 = await rejection(c.auth.login(new AppRoleAuth("r", "bad-secret-value")));
    expect(e1).toBeInstanceOf(AuthenticationError);
    expect(e1.message).toBe("auth.approle.login approle: invalid role or secret ID (HTTP 400)");
    expect(e1.message).not.toContain("bad-secret-value");
    const e2 = await rejection(c.auth.login(new UserpassAuth("sdk-user", "wrong-password")));
    expect(e2.code).toBe("AUTHENTICATION");
    expect((await rejection(c.auth.login(new JwtAuth("sdk-jwt", "x.y.z")))).code).toBe(
      "AUTHENTICATION",
    );
    expect((await rejection(c.auth.login(new JwtAuth("sdk-jwt", "x.y.z")))).code).toBe(
      "AUTHENTICATION",
    );
    const k8s = await rejection(c.auth.login(new KubernetesAuth("sdk-k8s", { jwt: "sa-jwt" })));
    expect(k8s.code).toBe("AUTHENTICATION");
    expect(c.token?.reveal()).toBe("root-token-test");
  });

  it("UserpassAuth and JwtAuth request shapes", async () => {
    const m = await vault({
      "POST /v1/auth/userpass/login/sdk-user": loginWith("userpassLogin.ok", "s.up"),
      "POST /v1/auth/oidc/login": loginWith("jwtLogin.ok", "s.jwt"),
    });
    const c = m.client();
    const up = await c.auth.login(new UserpassAuth("sdk-user", new Secret("pw-1")));
    expect(m.body()).toEqual({ password: "pw-1" });
    expect(up.metadata.username).toBe("sdk-user");
    const jwt = new JwtAuth("sdk-jwt", "jwt-value", { mount: "oidc" });
    expect(inspect(jwt)).not.toContain("jwt-value");
    expect(String(jwt)).toContain("[REDACTED]");
    await c.auth.login(jwt);
    expect(m.body()).toEqual({ role: "sdk-jwt", jwt: "jwt-value" });
    expect(c.token?.reveal()).toBe("s.jwt");
    expect(String(new UserpassAuth("u", "p"))).not.toContain("=p");
  });

  it("KubernetesAuth reads the service account token file (success path, unit only)", async () => {
    const dir = mkdtempSync(join(tmpdir(), "k8s-"));
    const path = join(dir, "token");
    writeFileSync(path, "sa-token-from-file\n");
    const empty = join(dir, "empty");
    writeFileSync(empty, "  \n");
    const m = await vault({
      "POST /v1/auth/kubernetes/login": loginWith("appRoleLogin.ok", "s.k8s"),
      "POST /v1/auth/k8s/login": loginWith("appRoleLogin.ok", "s.k8s2"),
    });
    const c = m.client();
    const method = new KubernetesAuth("sdk-k8s", path);
    expect(method.jwtPath).toBe(path);
    expect(String(method)).toBe("KubernetesAuth(kubernetes, role=sdk-k8s)");
    await c.auth.login(method);
    expect(m.body()).toEqual({ role: "sdk-k8s", jwt: "sa-token-from-file" });
    expect(c.token?.reveal()).toBe("s.k8s");
    await c.auth.login(new KubernetesAuth("r", { jwtPath: path, mount: "k8s" }));
    expect(c.token?.reveal()).toBe("s.k8s2");
    expect(new KubernetesAuth("r").jwtPath).toBe(KubernetesAuth.DEFAULT_JWT_PATH);
    await expect(c.auth.login(new KubernetesAuth("r", join(dir, "missing")))).rejects.toThrow(
      ConfigError,
    );
    await expect(c.auth.login(new KubernetesAuth("r", empty))).rejects.toThrow(/is empty/);
  });

  it("TokenAuth checks the token with lookup-self", async () => {
    const m = await vault({
      "GET /v1/auth/token/lookup-self": ["lookupSelf.ok", "lookupSelf.revoked"],
    });
    const c = m.client();
    const auth = new TokenAuth("s.given");
    expect(String(auth)).toBe("TokenAuth([REDACTED])");
    const info = await c.auth.login(auth);
    expect(m.req().headers["x-vault-token"]).toBe("s.given");
    expect(info.clientToken.reveal()).toBe("s.given");
    expect(info.leaseDurationMs).toBe(3_599_000);
    expect(info.metadata).toEqual({ run: "f43633d7" });
    expect(c.token?.reveal()).toBe("s.given");
    expect((await rejection(c.auth.login(new TokenAuth("s.revoked")))).code).toBe("AUTHENTICATION");
  });

  it("constructors validate their input", () => {
    expect(() => new TokenAuth("")).toThrow(ConfigError);
    expect(() => new AppRoleAuth(" ", "s")).toThrow(/roleId/);
    expect(() => new JwtAuth("r", "")).toThrow(ConfigError);
    expect(() => new UserpassAuth("u", "")).toThrow(ConfigError);
    expect(() => new KubernetesAuth("")).toThrow(/role/);
  });

  it("a login response without auth is an unexpected response", async () => {
    const m = await vault({ "POST /v1/auth/approle/login": { status: 200, body: { auth: null } } });
    const err = await rejection(m.client().auth.login(new AppRoleAuth("r", "s")));
    expect(err.code).toBe("UNAVAILABLE");
    expect(err.message).toContain("no auth block");
  });
});

describe("token self-service", () => {
  it("lookupSelf maps every field", async () => {
    const m = await vault(fromFixtures("lookupSelf.ok"));
    const t = await m.client().auth.lookupSelf();
    expect(t).toMatchObject({
      policies: ["default", "sdk-app"],
      ttlMs: 3_599_000,
      creationTtlMs: 3_600_000,
      renewable: true,
      displayName: "token-sdk-test",
      meta: { run: "f43633d7" },
      numUses: 0,
      orphan: false,
      path: "auth/token/create",
      type: "service",
      explicitMaxTtlMs: 0,
      entityId: "",
    });
    expect(t.creationTime?.getTime()).toBe(1_795_033_729_000);
    expect(t.expireTime?.toISOString()).toBe("2026-11-18T21:28:50.039Z");
    expect(String(t.id)).toBe(REDACTED);
  });

  it("lookupSelf tolerates missing fields", async () => {
    const m = await vault({
      "GET /v1/auth/token/lookup-self": { status: 200, body: { data: {} } },
    });
    const t = await m.client().auth.lookupSelf();
    expect(t).toMatchObject({ policies: [], ttlMs: 0, displayName: "", type: "", path: "" });
    expect(t.id.reveal()).toBe("");
    expect(t.accessor).toBeUndefined();
  });

  it("renewSelf sends the increment; non-renewable is VALIDATION", async () => {
    const m = await vault({
      "POST /v1/auth/token/renew-self": ["renewSelf.ok", "renewSelf.not-renewable"],
    });
    const c = m.client();
    const info = await c.auth.renewSelf(30 * 60_000);
    expect(m.body()).toEqual({ increment: "1800s" });
    expect(info.leaseDurationMs).toBeGreaterThan(0);
    const err = await rejection(c.auth.renewSelf());
    expect(err.code).toBe("VALIDATION");
    expect(m.body()).toEqual({});
  });

  it("revokeSelf forgets the token", async () => {
    const m = await vault({ "POST /v1/auth/token/revoke-self": "revokeSelf.ok" });
    const c = m.client();
    await c.auth.revokeSelf();
    expect(m.req().headers["x-vault-token"]).toBe("root-token-test");
    expect(c.token).toBeUndefined();
  });

  it("createToken maps options to the wire body", async () => {
    const m = await vault({
      "POST /v1/auth/token/create": [
        "createToken.ok",
        "createToken.orphan",
        "createToken.permission-denied",
      ],
      "POST /v1/auth/token/create/ci": "createToken.non-renewable",
    });
    const c = m.client();
    const t = await c.auth.createToken({
      policies: ["sdk-app"],
      ttlMs: 3_600_000,
      renewable: true,
      displayName: "sdk-test",
      meta: { run: "f43633d7" },
    });
    expect(m.body()).toEqual({
      ...(fixture("createToken.ok").request.body as object),
      ttl: "3600s", // the fixture used "1h"; both are valid OpenBao durations
    });
    expect(t.metadata).toEqual({ run: "f43633d7" });
    expect(t.clientToken.reveal()).not.toBe("");
    const orphan = await c.auth.createToken({
      policies: ["sdk-app"],
      ttlMs: 3_600_000,
      explicitMaxTtlMs: 7_200_000,
      numUses: 0,
      noParent: true,
      noDefaultPolicy: false,
      periodMs: 60_000,
    });
    expect(m.body()).toEqual({
      policies: ["sdk-app"],
      ttl: "3600s",
      explicit_max_ttl: "7200s",
      num_uses: 0,
      no_parent: true,
      no_default_policy: false,
      period: "60s",
    });
    expect(orphan.orphan).toBe(true);
    expect((await rejection(c.auth.createToken({ policies: ["sdk-app"] }))).code).toBe(
      "PERMISSION_DENIED",
    );
    await c.auth.createToken({ role: "ci" });
    expect(m.keys().at(-1)).toBe("POST /v1/auth/token/create/ci");
    await expect(c.auth.createToken({ numUses: -1 })).rejects.toMatchObject({ code: "VALIDATION" });
  });
});

describe("TokenRenewer", () => {
  it("renews the client token at 2/3 of its TTL and stops on close", async () => {
    const clock = new ManualScheduler();
    const m = await vault({
      "GET /v1/auth/token/lookup-self": "lookupSelf.ok",
      "POST /v1/auth/token/renew-self": loginWith("renewSelf.ok", "s.same", 3600, true),
    });
    const c = m.client();
    const onRenew = vi.fn();
    const renewer = await c.auth.startRenewer({
      scheduler: clock,
      onRenew,
      incrementMs: 3_600_000,
    });
    expect(renewer.running).toBe(true);
    expect(c.auth.activeRenewers).toBe(1);
    expect(renewer.expiresAt).toBe(clock.now() + 3_599_000);
    await clock.advance(2_400_000);
    await vi.waitFor(() => expect(onRenew).toHaveBeenCalledTimes(1));
    expect(onRenew.mock.calls[0]?.[0]).toMatchObject({ ttlMs: 3_600_000, reauthenticated: false });
    expect(m.body()).toEqual({ increment: "3600s" });
    await renewer.start(); // already started: no-op
    await c.close();
    expect(renewer.running).toBe(false);
    expect(c.auth.activeRenewers).toBe(0);
  });

  it("login({autoRenew}) re-logs in when the token cannot be renewed", async () => {
    const clock = new ManualScheduler();
    const m = await vault({
      "POST /v1/auth/approle/login": [
        loginWith("appRoleLogin.ok", "s.first", 60, false),
        loginWith("appRoleLogin.ok", "s.second", 3600, true),
      ],
    });
    const c = m.client({ token: undefined });
    const onRenew = vi.fn();
    await c.auth.login(new AppRoleAuth("r", "s"), { autoRenew: { scheduler: clock, onRenew } });
    expect(c.token?.reveal()).toBe("s.first");
    expect(c.auth.activeRenewers).toBe(1);
    await clock.advance(40_000);
    await vi.waitFor(() => expect(onRenew).toHaveBeenCalledTimes(1));
    expect(onRenew.mock.calls[0]?.[0]).toMatchObject({ reauthenticated: true, ttlMs: 3_600_000 });
    expect(c.token?.reveal()).toBe("s.second");
    c.auth.stopRenewers();
    expect(c.auth.activeRenewers).toBe(0);
  });

  it("calls onExpire once when the token expires and no reauth is set", async () => {
    const clock = new ManualScheduler();
    const m = await vault({ "POST /v1/auth/token/revoke-self": NO_CONTENT });
    const c = m.client();
    const onExpire = vi.fn();
    const renewer = new TokenRenewer(c.auth, { scheduler: clock, onExpire });
    await renewer.start({ ttlMs: 1000, renewable: false });
    await clock.advance(1000);
    expect(onExpire).toHaveBeenCalledTimes(1);
    expect(renewer.expired).toBe(true);
    expect(renewer.running).toBe(false);
    renewer.stop();
  });

  it("login({autoRenew: true}) and a failing startRenewer", async () => {
    const m = await vault({
      "POST /v1/auth/userpass/login/u": loginWith("userpassLogin.ok", "s.u", 0, false),
      "GET /v1/auth/token/lookup-self": errors(403, "permission denied"),
    });
    const c = m.client();
    await c.auth.login(new UserpassAuth("u", "p"), { autoRenew: true });
    expect(c.auth.activeRenewers).toBe(1); // ttl 0: idle, nothing scheduled
    c.auth.stopRenewers();
    await expect(c.auth.startRenewer()).rejects.toMatchObject({ code: "AUTHENTICATION" });
    expect(c.auth.activeRenewers).toBe(0);
  });
});
