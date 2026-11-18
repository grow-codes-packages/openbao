import { inspect } from "node:util";
import { describe, expect, it } from "vitest";
import { Secret } from "../src/index.js";
import { init, initStatus, seal, unseal, waitForActive } from "../src/testing-entry.js";
import { data, errors, fixture, fx, rejection, vault } from "./support/vault.js";

describe("testing lifecycle helpers", () => {
  it("initStatus, init (shamir), unseal, seal", async () => {
    const m = await vault({
      "GET /v1/sys/init": ["init.status", { status: 200, body: "null" }],
      "PUT /v1/sys/init": [
        fx("init.shamir", () => ({
          keys: ["k-hex"],
          keys_base64: ["k-b64"],
          root_token: "s.root",
        })),
        "init.already-initialized",
        { status: 200, body: { keys: [] } },
      ],
      "PUT /v1/sys/unseal": ["unseal.ok", "unseal.invalid-key"],
      "PUT /v1/sys/seal": "seal.testing",
    });
    const c = m.client();
    expect(await initStatus(c)).toBe(false);
    expect(m.req().headers["x-vault-token"]).toBeUndefined();
    expect((await rejection(initStatus(c))).message).toContain("empty response body");
    const res = await init(c);
    expect(m.body()).toEqual(fixture("init.shamir").request.body);
    expect(m.req().headers["x-vault-token"]).toBeUndefined();
    expect(res.rootToken.reveal()).toBe("s.root");
    expect(res.keys.map((k) => k.reveal())).toEqual(["k-hex"]);
    expect(res.keysBase64.map((k) => k.reveal())).toEqual(["k-b64"]);
    expect(res.recoveryKeys).toEqual([]);
    expect(inspect(res)).not.toContain("s.root");
    const again = await rejection(init(c, { secretShares: 1, secretThreshold: 1 }));
    expect(again.code).toBe("VALIDATION");
    expect(again.message).toContain("already initialized");
    expect((await rejection(init(c))).message).toContain("no root_token");
    const status = await unseal(c, new Secret("k-hex"));
    expect(m.body()).toEqual({ key: "k-hex" });
    expect(status).toMatchObject({ type: "shamir", sealed: false, threshold: 1, shares: 1 });
    expect((await rejection(unseal(c, "zz"))).code).toBe("VALIDATION");
    await expect(unseal(c, " ")).rejects.toMatchObject({ code: "VALIDATION" });
    await seal(c);
    expect(m.req().headers["x-vault-token"]).toBe("root-token-test");
  });

  it("init with recovery shares and unseal reset", async () => {
    const m = await vault({
      "PUT /v1/sys/init": {
        status: 200,
        body: {
          keys: [],
          recovery_keys: ["r1", ""],
          recovery_keys_base64: ["cjE="],
          root_token: "s.r",
        },
      },
      "PUT /v1/sys/unseal": "unseal.ok",
    });
    const c = m.client();
    const res = await init(c, { recoveryShares: 1 });
    expect(m.body()).toEqual({ recovery_shares: 1, recovery_threshold: 1 });
    expect(res.recoveryKeys.map((k) => k.reveal())).toEqual(["r1"]);
    await init(c, { recoveryThreshold: 2 });
    expect(m.body()).toEqual({ recovery_shares: 1, recovery_threshold: 2 });
    await unseal(c, "", { reset: true });
    expect(m.body()).toEqual({ reset: true });
  });

  it("waitForActive polls sys/health until active", async () => {
    const m = await vault({
      "GET /v1/sys/health": [
        errors(502, "starting"),
        { status: 200, body: { initialized: true, sealed: false, standby: true } },
        "health.active",
      ],
    });
    const h = await waitForActive(m.client(), { intervalMs: 1, timeoutMs: 5000 });
    expect(h.state).toBe("active");
    expect(m.requests).toHaveLength(3);
  });

  it("waitForActive times out and stops on non-retryable errors", async () => {
    const m = await vault({
      "GET /v1/sys/health": data({ initialized: false }),
    });
    const err = await rejection(waitForActive(m.client(), { intervalMs: 5, timeoutMs: 20 }));
    expect(err.code).toBe("TIMEOUT");
    const m2 = await vault({ "GET /v1/sys/health": errors(400, "bad") });
    expect((await rejection(waitForActive(m2.client(), { intervalMs: 1 }))).code).toBe(
      "VALIDATION",
    );
  });
});
