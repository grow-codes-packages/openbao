import { inspect } from "node:util";
import { describe, expect, it } from "vitest";
import { REDACTED, Secret } from "../src/index.js";
import {
  NO_CONTENT,
  data,
  errors,
  fixture,
  fromFixtures,
  fx,
  rejection,
  vault,
} from "./support/vault.js";

const SERIAL = "1b:51:42:eb:c5:7c:6c:ad:fd:ec:85:5d:e7:c1:67:10:db:61:b1:34";

describe("Pki", () => {
  it("issueCertificate returns the chain and a redacted private key", async () => {
    const m = await vault({
      "POST /v1/pki/issue/sdk-test": [
        fx("pki.issueCertificate.ok", (b) => ({
          ...b,
          data: { ...b.data, private_key: "PRIVATE-KEY-PEM" },
        })),
        "pki.issueCertificate.not-allowed",
        data({ certificate: "c" }),
        data({}),
      ],
    });
    const pki = m.client().pki();
    expect(pki.mount).toBe("pki");
    const cert = await pki.issueCertificate("sdk-test", "svc-f43633d7.example.test", {
      altNames: ["alt-f43633d7.example.test"],
      ipSans: ["127.0.0.1"],
      ttlMs: 3_600_000,
    });
    expect(m.body()).toEqual({
      ...(fixture("pki.issueCertificate.ok").request.body as object),
      ttl: "3600s",
    });
    expect(cert.certificate).toMatch(/^-----BEGIN CERTIFICATE-----/);
    expect(cert.caChain.length).toBeGreaterThan(0);
    expect(cert.issuingCa).toMatch(/BEGIN CERTIFICATE/);
    expect(cert.serialNumber).toMatch(/^[0-9a-f]{2}(:[0-9a-f]{2})+$/);
    expect(cert.privateKeyType).toBe("ec");
    expect(cert.expiration).toBeInstanceOf(Date);
    expect(cert.privateKey.reveal()).toBe("PRIVATE-KEY-PEM");
    expect(inspect(cert)).not.toContain("PRIVATE-KEY-PEM");
    const denied = await rejection(pki.issueCertificate("sdk-test", "evil.example.com"));
    expect(denied.code).toBe("VALIDATION");
    expect(denied.message).toContain("not allowed by this role");
    const minimal = await pki.issueCertificate("sdk-test", "x.example.test", {
      uriSans: ["spiffe://x"],
      format: "pem",
      privateKeyFormat: "pkcs8",
      excludeCnFromSans: true,
      altNames: [],
    });
    expect(m.body()).toEqual({
      common_name: "x.example.test",
      uri_sans: "spiffe://x",
      format: "pem",
      private_key_format: "pkcs8",
      exclude_cn_from_sans: true,
    });
    expect(minimal).toMatchObject({
      issuingCa: "",
      caChain: [],
      serialNumber: "",
      privateKeyType: "",
    });
    expect(minimal.privateKey.reveal()).toBe("");
    expect((await rejection(pki.issueCertificate("sdk-test", "y.example.test"))).message).toContain(
      "no certificate",
    );
  });

  it("signCsr, revokeCertificate, readCertificate, listCertificates, readCaChain", async () => {
    const m = await vault({
      "POST /v1/pki/sign/sdk-test": ["pki.signCsr.ok", "pki.signCsr.invalid"],
      "POST /v1/pki/revoke": [
        "pki.revokeCertificate.ok",
        "pki.revokeCertificate.not-found",
        data({ revocation_time: 1795033751 }),
      ],
      [`GET /v1/pki/cert/${SERIAL}`]: [
        "pki.readCertificate.ok",
        "pki.readCertificate.revoked",
        data({}),
      ],
      "GET /v1/pki/cert/ff:ff:ff:ff": "pki.readCertificate.not-found",
      "LIST /v1/pki/certs": "pki.listCertificates.ok",
      "LIST /v1/pki2/certs": errors(404),
      "LIST /v1/pki3/certs": errors(403, "1 error occurred: * permission denied"),
      "GET /v1/pki/ca_chain": "pki.readCaChain.pem",
      "GET /v1/pki2/ca_chain": { status: 200, body: "" },
    });
    const c = m.client();
    const pki = c.pki();
    const csr = (fixture("pki.signCsr.ok").request.body as { csr: string }).csr;
    const signed = await pki.signCsr("sdk-test", csr, {
      commonName: "csr-f43633d7.example.test",
      ttlMs: 3_600_000,
    });
    expect(m.body()).toEqual({ csr, common_name: "csr-f43633d7.example.test", ttl: "3600s" });
    expect(signed.certificate).toMatch(/BEGIN CERTIFICATE/);
    expect(signed).not.toHaveProperty("privateKey");
    expect((await rejection(pki.signCsr("sdk-test", "not a csr"))).code).toBe("VALIDATION");
    const rev = await pki.revokeCertificate(SERIAL);
    expect(m.body()).toEqual({ serial_number: SERIAL });
    expect(rev.state).toBe("revoked");
    expect(rev.revocationTime?.toISOString()).toBe("2026-11-18T20:29:11.803Z");
    expect((await rejection(pki.revokeCertificate("ff:ff:ff:ff"))).message).toContain("not found");
    expect(await pki.revokeCertificate(SERIAL)).toMatchObject({ state: "revoked" });
    const info = await pki.readCertificate(SERIAL);
    expect(info.revocationTime).toBeNull();
    expect((await pki.readCertificate(SERIAL)).revocationTime).toBeInstanceOf(Date);
    expect((await rejection(pki.readCertificate(SERIAL))).message).toContain("no certificate");
    expect((await rejection(pki.readCertificate("ff:ff:ff:ff"))).code).toBe("NOT_FOUND");
    expect(await pki.listCertificates()).toContain(SERIAL);
    expect(await c.pki("pki2").listCertificates()).toEqual([]);
    expect((await rejection(c.pki("pki3").listCertificates())).code).toBe("PERMISSION_DENIED");
    expect(await pki.readCaChain()).toMatch(/^-----BEGIN CERTIFICATE-----/);
    expect(await c.pki("pki2").readCaChain()).toBe("");
  });

  it("tidy starts (202) and waits for Finished; tidyStatus maps fields", async () => {
    const m = await vault({
      "POST /v1/pki/tidy": "pki.tidy.accepted",
      "GET /v1/pki/tidy-status": [
        data({ state: "Running" }),
        "pki.tidyStatus.finished",
        data({ state: "Error", error: "boom" }),
      ],
    });
    const pki = m.client().pki();
    const status = await pki.tidy({ safetyBufferMs: 1000, intervalMs: 1 });
    expect(m.body(0)).toEqual(fixture("pki.tidy.accepted").request.body);
    expect(status.state).toBe("Finished");
    expect(status.error).toBeNull();
    expect(status.timeFinished).toBeInstanceOf(Date);
    const started = await pki.tidy({ wait: false, tidyCertStore: false, tidyRevokedCerts: false });
    expect(m.body(-2)).toEqual({ tidy_cert_store: false, tidy_revoked_certs: false });
    expect(started).toMatchObject({ state: "Error", error: "boom", certStoreDeletedCount: 0 });
  });
});

describe("Sys", () => {
  it("sealStatus, leader, health (raw)", async () => {
    const m = await vault({
      "GET /v1/sys/seal-status": ["sealStatus.unsealed", "sealStatus.sealed", NO_CONTENT],
      "GET /v1/sys/leader": "leader.active",
      "GET /v1/sys/health": "health.active",
    });
    const sys = m.client().sys;
    expect(await sys.sealStatus()).toMatchObject({
      type: "static",
      initialized: true,
      sealed: false,
      threshold: 1,
      shares: 1,
      progress: 0,
      recoverySeal: true,
      version: "2.7.2",
      storageType: "raft",
    });
    expect((await sys.sealStatus()).sealed).toBe(true);
    expect((await rejection(sys.sealStatus())).message).toContain("empty response body");
    const leader = await sys.leader();
    expect(leader).toMatchObject({
      haEnabled: true,
      isSelf: true,
      leaderAddress: "http://openbao:8200",
    });
    expect(leader.activeTime).toBeInstanceOf(Date);
    const health = await sys.health();
    expect(health).toMatchObject({
      state: "active",
      initialized: true,
      sealed: false,
      version: "2.7.2",
    });
    expect(health.serverTime).toBeInstanceOf(Date);
    expect(m.req().headers["x-vault-token"]).toBe("root-token-test");
    expect(await sys.version()).toBe("2.7.2");
  });

  it("policies", async () => {
    const m = await vault({
      ...fromFixtures(
        "admin.writePolicy.ok",
        "admin.readPolicy.ok",
        "admin.listPolicies.ok",
        "admin.deletePolicy.ok",
      ),
      "PUT /v1/sys/policies/acl/bad-f43633d7": "admin.writePolicy.invalid",
      "GET /v1/sys/policies/acl/missing-f43633d7": "admin.readPolicy.not-found",
      "GET /v1/sys/policies/acl/noname": data({}),
    });
    const sys = m.client().sys;
    const hcl = (fixture("admin.writePolicy.ok").request.body as { policy: string }).policy;
    await sys.writePolicy("sdk-tmp-f43633d7", hcl);
    expect(m.body()).toEqual({ policy: hcl });
    expect(await sys.readPolicy("sdk-tmp-f43633d7")).toEqual({
      name: "sdk-tmp-f43633d7",
      policy: hcl,
    });
    expect(await sys.readPolicy("noname")).toEqual({ name: "noname", policy: "" });
    expect(await sys.listPolicies()).toEqual(["default", "sdk-app", "sdk-tmp-f43633d7", "root"]);
    await sys.deletePolicy("sdk-tmp-f43633d7");
    expect((await rejection(sys.writePolicy("bad-f43633d7", "path { nonsense"))).code).toBe(
      "VALIDATION",
    );
    expect((await rejection(sys.readPolicy("missing-f43633d7"))).code).toBe("NOT_FOUND");
    await expect(sys.writePolicy("x", "")).rejects.toMatchObject({ code: "VALIDATION" });
  });

  it("secrets engines and auth methods", async () => {
    const m = await vault({
      "GET /v1/sys/mounts": ["admin.listMounts.ok", "admin.listMounts.permission-denied"],
      "POST /v1/sys/mounts/tmp-f43633d7": [
        "admin.enableSecretsEngine.ok",
        "admin.enableSecretsEngine.conflict",
      ],
      ...fromFixtures(
        "admin.disableSecretsEngine.ok",
        "admin.listAuthMethods.ok",
        "admin.enableAuthMethod.ok",
        "admin.disableAuthMethod.ok",
      ),
    });
    const sys = m.client().sys;
    const mounts = await sys.listMounts();
    expect(mounts["secret/"]).toMatchObject({
      type: "kv",
      options: { version: "2" },
      description: "SDK KV v2",
    });
    expect(mounts["kv1/"]?.options.version).toBe("1");
    expect(Object.keys(mounts)).not.toContain("request_id");
    expect((await rejection(sys.listMounts())).code).toBe("PERMISSION_DENIED");
    await sys.enableSecretsEngine("tmp-f43633d7", "kv", {
      options: { version: "2" },
      description: "sdk temp",
    });
    expect(m.body()).toEqual(fixture("admin.enableSecretsEngine.ok").request.body);
    const conflict = await rejection(
      sys.enableSecretsEngine("/tmp-f43633d7/", "kv", {
        defaultLeaseTtlMs: 60_000,
        maxLeaseTtlMs: 120_000,
        local: false,
        sealWrap: false,
      }),
    );
    expect(m.body()).toEqual({
      type: "kv",
      config: { default_lease_ttl: "60s", max_lease_ttl: "120s" },
      local: false,
      seal_wrap: false,
    });
    expect(conflict.code).toBe("VALIDATION");
    expect(conflict.message).toContain("already in use");
    await sys.disableSecretsEngine("tmp-f43633d7");
    const auths = await sys.listAuthMethods();
    expect(auths["approle/"]?.type).toBe("approle");
    expect(auths["token/"]?.type).toBe("token");
    await sys.enableAuthMethod("ar-f43633d7", "approle", { description: "sdk temp" });
    expect(m.body()).toEqual(fixture("admin.enableAuthMethod.ok").request.body);
    await sys.disableAuthMethod("ar-f43633d7");
    expect(m.keys().at(-1)).toBe("DELETE /v1/sys/auth/ar-f43633d7");
  });

  it("enableAuthMethod with TTL config", async () => {
    const m = await vault({ "POST /v1/sys/auth/up2": NO_CONTENT });
    await m.client().sys.enableAuthMethod("up2", "userpass", {
      defaultLeaseTtlMs: 1000,
      maxLeaseTtlMs: 2000,
      local: true,
    });
    expect(m.body()).toEqual({
      type: "userpass",
      config: { default_lease_ttl: "1s", max_lease_ttl: "2s" },
      local: true,
    });
  });

  it("AppRole administration", async () => {
    const m = await vault({
      ...fromFixtures("admin.createAppRole.ok", "admin.readRoleId.ok", "admin.listAppRoles.ok"),
      "POST /v1/auth/ar-f43633d7/role/r1/secret-id": fx("admin.generateSecretId.ok", (b) => ({
        ...b,
        data: { ...b.data, secret_id: "sid-123", secret_id_accessor: "acc-123" },
      })),
      "GET /v1/auth/ar-f43633d7/role/missing/role-id": "admin.readRoleId.not-found",
      "LIST /v1/auth/approle/role": errors(404),
      "LIST /v1/auth/denied/role": errors(403, "1 error occurred: * permission denied"),
      "DELETE /v1/auth/approle/role/old": NO_CONTENT,
      "POST /v1/auth/approle/role/y": NO_CONTENT,
      "GET /v1/auth/approle/role/x/role-id": data({}),
      "POST /v1/auth/approle/role/x/secret-id": data({}),
    });
    const sys = m.client().sys;
    await sys.createAppRole("r1", {
      mount: "ar-f43633d7",
      tokenPolicies: ["sdk-tmp-f43633d7"],
      secretIdNumUses: 1,
      tokenTtlMs: 600_000,
    });
    expect(m.body()).toEqual({
      token_policies: ["sdk-tmp-f43633d7"],
      secret_id_num_uses: 1,
      token_ttl: "600s",
    });
    expect(await sys.readRoleId("r1", { mount: "ar-f43633d7" })).toBe(
      "0a235ec1-2d7d-fd7a-8b4f-8a684196312e",
    );
    expect((await rejection(sys.readRoleId("missing", { mount: "ar-f43633d7" }))).code).toBe(
      "NOT_FOUND",
    );
    const sid = await sys.generateSecretId("r1", {
      mount: "ar-f43633d7",
      metadata: { purpose: "sdk" },
    });
    expect(m.body()).toEqual(fixture("admin.generateSecretId.ok").request.body);
    expect(sid.secretId.reveal()).toBe("sid-123");
    expect(sid.secretIdNumUses).toBe(1);
    expect(sid.secretIdTtlMs).toBe(0);
    expect(inspect(sid)).not.toContain("sid-123");
    expect(String(sid.secretIdAccessor)).toBe(REDACTED);
    expect(await sys.listAppRoles({ mount: "ar-f43633d7" })).toEqual(["r1"]);
    expect(await sys.listAppRoles()).toEqual([]);
    expect((await rejection(sys.listAppRoles({ mount: "denied" }))).code).toBe("PERMISSION_DENIED");
    await sys.deleteAppRole("old");
    await sys.createAppRole("y", {
      tokenMaxTtlMs: 1000,
      secretIdTtlMs: 0,
      bindSecretId: true,
      tokenType: "batch",
    });
    expect(m.body()).toEqual({
      token_max_ttl: "1s",
      secret_id_ttl: "0s",
      bind_secret_id: true,
      token_type: "batch",
    });
    expect((await rejection(sys.readRoleId("x"))).message).toContain("no role_id");
    expect(
      (
        await rejection(
          sys.generateSecretId("x", { cidrList: ["10.0.0.0/8"], ttlMs: 1000, numUses: 2 }),
        )
      ).message,
    ).toContain("no secret_id");
    expect(m.body()).toEqual({ cidr_list: ["10.0.0.0/8"], ttl: "1s", num_uses: 2 });
  });
});

describe("Wrapping", () => {
  it("wrap -> lookupWrapping -> unwrap; tokens are redacted", async () => {
    const m = await vault({
      "POST /v1/sys/wrapping/wrap": [
        fx("wrapping.wrap.ok", (b) => ({
          ...b,
          wrap_info: { ...b.wrap_info, token: "wrap-tok-1" },
        })),
        "wrapping.wrap.missing-ttl",
        data(null),
      ],
      "POST /v1/sys/wrapping/lookup": [
        "wrapping.lookupWrapping.ok",
        "wrapping.lookupWrapping.used",
      ],
      "POST /v1/sys/wrapping/unwrap": ["wrapping.unwrap.ok", "wrapping.unwrap.already-used"],
    });
    const w = m.client().wrapping;
    const info = await w.wrap({ secret: "wrapped-f43633d7", n: 1 }, 60_000);
    expect(m.req().headers["x-vault-wrap-ttl"]).toBe("60s");
    expect(m.body()).toEqual({ secret: "wrapped-f43633d7", n: 1 });
    expect(info).toMatchObject({ ttlMs: 60_000, creationPath: "sys/wrapping/wrap" });
    expect(info.token.reveal()).toBe("wrap-tok-1");
    expect(inspect(info)).not.toContain("wrap-tok-1");
    const lookup = await w.lookupWrapping(info.token);
    expect(m.req().headers["x-vault-token"]).toBeUndefined();
    expect(m.body()).toEqual({ token: "wrap-tok-1" });
    expect(lookup).toMatchObject({ creationPath: "sys/wrapping/wrap", creationTtlMs: 60_000 });
    expect(lookup.creationTime).toBeInstanceOf(Date);
    const unwrapped = await w.unwrap(info.token);
    expect(m.req().headers["x-vault-token"]).toBe("wrap-tok-1");
    expect(m.req().body).toBe("");
    expect(unwrapped.data).toEqual({ n: 1, secret: "wrapped-f43633d7" });
    expect(unwrapped.auth).toBeUndefined();
    const used = await rejection(w.unwrap("wrap-tok-1"));
    expect(used.code).toBe("VALIDATION");
    expect(used.message).toContain("not valid or does not exist");
    expect((await rejection(w.lookupWrapping("wrap-tok-1"))).code).toBe("VALIDATION");
    expect((await rejection(w.wrap({ x: 1 }, 0))).code).toBe("VALIDATION");
    expect((await rejection(w.wrap({ x: 1 }, 1000))).message).toContain("no wrap_info");
    await expect(w.unwrap("")).rejects.toMatchObject({ code: "VALIDATION" });
  });

  it("unwrap of a wrapped login returns its auth block", async () => {
    const login = fixture("appRoleLogin.ok").response.body as { auth: object };
    const m = await vault({
      "POST /v1/sys/wrapping/unwrap": {
        status: 200,
        body: {
          ...login,
          auth: { ...login.auth, client_token: "s.wrapped" },
          lease_id: "l",
          lease_duration: 5,
          renewable: true,
          warnings: ["w"],
        },
      },
      "POST /v1/sys/wrapping/lookup": data({}),
    });
    const w = m.client().wrapping;
    const r = await w.unwrap(new Secret("wt"));
    expect(r.data).toBeNull();
    expect(r.auth?.clientToken.reveal()).toBe("s.wrapped");
    expect(r).toMatchObject({
      leaseId: "l",
      leaseDurationMs: 5000,
      renewable: true,
      warnings: ["w"],
    });
    expect(await w.lookupWrapping("t")).toEqual({
      creationPath: "",
      creationTime: null,
      creationTtlMs: 0,
    });
  });
});
