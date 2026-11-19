import { describe, expect, it } from "vitest";
import { KvMount, KvV1, KvV2, NotFoundError, UnsupportedError } from "../src/index.js";
import {
  NO_CONTENT,
  data,
  errors,
  fixture,
  fromFixtures,
  rejection,
  vault,
} from "./support/vault.js";

const P = "sdk/test/f43633d7";

describe("KvV2", () => {
  it("read returns data and version metadata; ?version= selects a version", async () => {
    const m = await vault({
      "GET /v1/secret/data/sdk/test/f43633d7/alpha": (req) =>
        req.url.includes("version=1") ? "kvV2.read.version" : "kvV2.read.ok",
    });
    const kv = m.client().kvV2();
    expect(kv.version).toBe(2);
    expect(kv.mount).toBe("secret");
    const s = await kv.read(`${P}/alpha`);
    expect(s.data).toEqual(
      (fixture("kvV2.read.ok").response.body as { data: { data: unknown } }).data.data,
    );
    expect(s.metadata?.version).toBeGreaterThan(0);
    expect(s.metadata?.deletionTime).toBeNull();
    expect(s.metadata?.createdTime).toBeInstanceOf(Date);
    const v1 = await kv.read(`${P}/alpha`, { version: 1 });
    expect(v1.metadata?.version).toBe(1);
    expect(m.req().url).toContain("?version=1");
  });

  it("read: missing, deleted and destroyed versions are NOT_FOUND", async () => {
    const m = await vault({
      "GET /v1/secret/data/sdk/test/f43633d7/missing": "kvV2.read.not-found",
      "GET /v1/secret/data/sdk/test/f43633d7/alpha": [
        "kvV2.read.deleted",
        "kvV2.read.destroyed-version",
        data({ data: null, metadata: { version: 3, deletion_time: "2026-01-01T00:00:00Z" } }),
        data({ data: { a: 1 }, metadata: null }),
      ],
    });
    const kv = m.client().kvV2();
    expect(await rejection(kv.read(`${P}/missing`))).toBeInstanceOf(NotFoundError);
    expect((await rejection(kv.read(`${P}/alpha`))).code).toBe("NOT_FOUND");
    expect((await rejection(kv.read(`${P}/alpha`, { version: 1 }))).code).toBe("NOT_FOUND");
    // a 200 without data (defensive) is NOT_FOUND too
    expect((await rejection(kv.read(`${P}/alpha`))).message).toContain("deleted or destroyed");
    expect((await kv.read(`${P}/alpha`)).metadata).toBeUndefined();
  });

  it("write / patch send options.cas; patch uses merge-patch+json", async () => {
    const m = await vault({
      "POST /v1/secret/data/sdk/test/f43633d7/alpha": [
        "kvV2.write.cas0",
        "kvV2.write.cas-mismatch",
      ],
      "POST /v1/secret/data/sdk/test/f43633d7/beta": [
        "kvV2.write.no-options",
        "kvV2.write.cas-required",
      ],
      "PATCH /v1/secret/data/sdk/test/f43633d7/alpha": [
        "kvV2.patch.ok",
        "kvV2.patch.null-removes-key",
        "kvV2.patch.cas-mismatch",
      ],
    });
    const kv = m.client().kvV2();
    const w = await kv.write(`${P}/alpha`, { a: "1", b: "2" }, { cas: 0 });
    expect(m.body()).toEqual(fixture("kvV2.write.cas0").request.body);
    expect(w.version).toBe(1);
    expect((await rejection(kv.write(`${P}/alpha`, { a: "x" }, { cas: 0 }))).code).toBe("CONFLICT");
    await kv.write(`${P}/beta`, { v: "b" });
    expect(m.body()).toEqual({ data: { v: "b" } });
    expect((await rejection(kv.write(`${P}/beta`, { v: "no-cas" }))).code).toBe("VALIDATION");
    const p = await kv.patch(`${P}/alpha`, { b: "3", c: "4" }, { cas: 1 });
    expect(m.req().headers["content-type"]).toBe("application/merge-patch+json");
    expect(m.body()).toEqual(fixture("kvV2.patch.ok").request.body);
    expect(p.version).toBeGreaterThan(1);
    await kv.patch(`${P}/alpha`, { d: null });
    expect(m.body()).toEqual({ data: { d: null } });
    expect((await rejection(kv.patch(`${P}/alpha`, { b: "stale" }, { cas: 1 }))).code).toBe(
      "CONFLICT",
    );
  });

  it("delete, deleteVersions, undelete, destroy", async () => {
    const m = await vault(
      fromFixtures(
        "kvV2.delete.ok",
        "kvV2.deleteVersions.ok",
        "kvV2.undelete.ok",
        "kvV2.destroy.ok",
        "kvV2.delete.missing-is-204",
      ),
    );
    const kv = m.client().kvV2();
    await kv.delete(`${P}/alpha`);
    await kv.delete(`${P}/never-existed`);
    await kv.deleteVersions(`${P}/alpha`, [1]);
    expect(m.body()).toEqual({ versions: [1] });
    await kv.undelete(`${P}/alpha`, [3]);
    expect(m.body()).toEqual({ versions: [3] });
    await kv.destroy(`${P}/alpha`, [1]);
    expect(m.keys()).toEqual([
      "DELETE /v1/secret/data/sdk/test/f43633d7/alpha",
      "DELETE /v1/secret/data/sdk/test/f43633d7/never-existed",
      "POST /v1/secret/delete/sdk/test/f43633d7/alpha",
      "POST /v1/secret/undelete/sdk/test/f43633d7/alpha",
      "PUT /v1/secret/destroy/sdk/test/f43633d7/alpha",
    ]);
    await expect(kv.destroy(`${P}/alpha`, [])).rejects.toMatchObject({ code: "VALIDATION" });
    await expect(kv.undelete(`${P}/alpha`, [0])).rejects.toMatchObject({ code: "VALIDATION" });
    await expect(kv.delete("  ")).rejects.toMatchObject({ code: "VALIDATION" });
  });

  it("list: keys with folders, pagination, missing folder = []", async () => {
    const m = await vault({
      "LIST /v1/secret/metadata/sdk/test/f43633d7": (req) =>
        req.url.includes("after=") ? "kvV2.list.paginated-after" : "kvV2.list.ok",
      "LIST /v1/secret/metadata/sdk/test/f43633d7/nothing-here": "kvV2.list.not-found",
      "LIST /v1/secret/metadata/x": errors(403, "1 error occurred: * permission denied"),
      "LIST /v1/secret/metadata": data({ keys: ["sdk/"] }),
    });
    const kv = m.client().kvV2();
    expect(await kv.list(P)).toEqual(["alpha", "beta", "dir/"]);
    const page = await kv.list(P, { after: "beta", limit: 2 });
    expect(page).toEqual(
      (fixture("kvV2.list.paginated-after").response.body as { data: { keys: string[] } }).data
        .keys,
    );
    expect(m.req().url).toContain("after=beta&limit=2");
    expect(await kv.list(`${P}/nothing-here`)).toEqual([]);
    expect((await rejection(kv.list("x"))).code).toBe("PERMISSION_DENIED");
    expect(await kv.list()).toEqual(["sdk/"]);
  });

  it("readMetadata / writeMetadata / deleteMetadata", async () => {
    const m = await vault({
      ...fromFixtures("kvV2.readMetadata.ok", "kvV2.writeMetadata.ok", "kvV2.deleteMetadata.ok"),
      "GET /v1/secret/metadata/sdk/test/f43633d7/missing": "kvV2.readMetadata.not-found",
      "GET /v1/secret/metadata/odd": data({ versions: null, delete_version_after: "bogus" }),
    });
    const kv = m.client().kvV2();
    const md = await kv.readMetadata(`${P}/alpha`);
    expect(md).toMatchObject({
      currentVersion: 3,
      maxVersions: 5,
      casRequired: false,
      oldestVersion: 0,
      deleteVersionAfterMs: 720 * 3_600_000,
      customMetadata: { owner: "sdk", run: "f43633d7" },
    });
    expect(md.versions["1"]?.version).toBe(1);
    expect(md.createdTime).toBeInstanceOf(Date);
    expect((await rejection(kv.readMetadata(`${P}/missing`))).code).toBe("NOT_FOUND");
    expect(await kv.readMetadata("odd")).toMatchObject({
      versions: {},
      deleteVersionAfterMs: 0,
      currentVersion: 0,
      maxVersions: 0,
    });
    await kv.writeMetadata(`${P}/alpha`, {
      maxVersions: 5,
      casRequired: false,
      deleteVersionAfterMs: 720 * 3_600_000,
      customMetadata: { owner: "sdk" },
    });
    expect(m.body()).toEqual({
      max_versions: 5,
      cas_required: false,
      delete_version_after: "2592000s",
      custom_metadata: { owner: "sdk" },
    });
    await kv.deleteMetadata(`${P}/alpha`);
    expect(m.keys().at(-1)).toBe("DELETE /v1/secret/metadata/sdk/test/f43633d7/alpha");
  });

  it("encodes path segments", async () => {
    const m = await vault({
      "GET /v1/kv1/sdk/test/f43633d7/with%20space": "kvV1.read.encoded-path",
    });
    const s = await m.client().kvV1("kv1").read(`${P}/with space`);
    expect(s.data).toBeTypeOf("object");
  });
});

describe("KvV1", () => {
  it("read/write/delete/list", async () => {
    const m = await vault({
      ...fromFixtures("kvV1.read.ok", "kvV1.write.ok", "kvV1.delete.ok", "kvV1.list.ok"),
      "GET /v1/kv1/sdk/test/f43633d7/missing": "kvV1.read.not-found",
      "LIST /v1/kv1/sdk/test/f43633d7/nothing": "kvV1.list.not-found",
      "LIST /v1/kv1/denied": errors(403, "1 error occurred: * permission denied"),
    });
    const kv = m.client().kvV1("/kv1/");
    expect(kv.version).toBe(1);
    expect(kv.mount).toBe("kv1");
    expect((await kv.read(`${P}/alpha`)).data).toEqual({ a: "1", n: 2 });
    expect((await kv.read(`${P}/alpha`)).metadata).toBeUndefined();
    expect(await kv.write(`${P}/alpha`, { a: "1", n: 2 })).toBeNull();
    expect(m.body()).toEqual({ a: "1", n: 2 });
    await kv.delete(`${P}/alpha`);
    expect(await kv.list(P)).toEqual(
      (fixture("kvV1.list.ok").response.body as { data: { keys: string[] } }).data.keys,
    );
    expect(await kv.list(`${P}/nothing`)).toEqual([]);
    expect((await rejection(kv.list("denied"))).code).toBe("PERMISSION_DENIED");
    expect((await rejection(kv.read(`${P}/missing`))).code).toBe("NOT_FOUND");
  });

  it("version-only operations are UNSUPPORTED without a request", async () => {
    const m = await vault();
    const kv = m.client().kvV1("kv1");
    const calls: Promise<unknown>[] = [
      kv.read("a", { version: 1 }),
      kv.write("a", {}, { cas: 0 }),
      kv.patch(),
      kv.deleteVersions(),
      kv.undelete(),
      kv.destroy(),
      kv.readMetadata(),
      kv.writeMetadata(),
      kv.deleteMetadata(),
    ];
    for (const call of calls) expect(await rejection(call)).toBeInstanceOf(UnsupportedError);
    expect(m.requests).toHaveLength(0);
  });
});

describe("KvMount (auto-detection)", () => {
  it("detects v2 once per mount using the first path, then delegates", async () => {
    const m = await vault({
      "GET /v1/sys/internal/ui/mounts/secret/sdk/allowed/hello": "mountDetect.kv2",
      "GET /v1/secret/data/sdk/allowed/hello": "kvV2.read.allowed-token",
    });
    const c = m.client();
    const kv = c.kv();
    expect(kv).toBeInstanceOf(KvMount);
    expect(c.kv("secret")).toBe(kv);
    expect((await kv.read("sdk/allowed/hello")).data).toEqual({ value: "world" });
    expect(await kv.version()).toBe(2);
    expect(await kv.engine()).toBeInstanceOf(KvV2);
    expect(m.keys().filter((k) => k.includes("internal"))).toHaveLength(1);
  });

  it("detects v1 and delegates every operation", async () => {
    const m = await vault({
      "GET /v1/sys/internal/ui/mounts/kv1/sdk/allowed/hello": "mountDetect.kv1",
      "GET /v1/kv1/sdk/allowed/hello": "kvV1.read.approle",
      "POST /v1/kv1/a": NO_CONTENT,
      "DELETE /v1/kv1/a": NO_CONTENT,
      "LIST /v1/kv1": data({ keys: ["a"] }),
    });
    const kv = m.client().kv("kv1");
    expect((await kv.read("sdk/allowed/hello")).data).toBeTypeOf("object");
    expect(await kv.engine()).toBeInstanceOf(KvV1);
    expect(await kv.write("a", { v: 1 })).toBeNull();
    await kv.delete("a");
    expect(await kv.list()).toEqual(["a"]);
    for (const call of [
      kv.patch("a", {}),
      kv.deleteVersions("a", [1]),
      kv.undelete("a", [1]),
      kv.destroy("a", [1]),
      kv.readMetadata("a"),
      kv.writeMetadata("a", {}),
      kv.deleteMetadata("a"),
    ]) {
      expect((await rejection(call)).code).toBe("UNSUPPORTED");
    }
  });

  it("config.kvVersion skips detection; v2 delegation covers every method", async () => {
    const m = await vault({
      ...fromFixtures(
        "kvV2.write.cas0",
        "kvV2.patch.ok",
        "kvV2.deleteVersions.ok",
        "kvV2.undelete.ok",
        "kvV2.destroy.ok",
        "kvV2.readMetadata.ok",
        "kvV2.writeMetadata.ok",
        "kvV2.deleteMetadata.ok",
        "kvV2.delete.ok",
      ),
    });
    const kv = m.client({ kvVersion: 2 }).kv();
    expect(await kv.version()).toBe(2);
    const p = `${P}/alpha`;
    await kv.write(p, { a: "1" }, { cas: 0 });
    await kv.patch(p, { b: "3" });
    await kv.deleteVersions(p, [1]);
    await kv.undelete(p, [3]);
    await kv.destroy(p, [1]);
    await kv.readMetadata(p);
    await kv.writeMetadata(p, { maxVersions: 5 });
    await kv.deleteMetadata(p);
    await kv.delete(p);
    expect(m.keys().some((k) => k.includes("internal"))).toBe(false);
  });

  it("detection errors propagate and are retried on the next call", async () => {
    const m = await vault({
      "GET /v1/sys/internal/ui/mounts/secret/sdk/allowed/hello": [
        "mountDetect.no-access",
        "mountDetect.kv2",
      ],
      "GET /v1/sys/internal/ui/mounts/nope/x": "mountDetect.no-mount",
      "GET /v1/sys/internal/ui/mounts/sys": data({ type: "system" }),
      "GET /v1/sys/internal/ui/mounts/weird": data({ type: "kv", options: { version: "9" } }),
      "GET /v1/sys/internal/ui/mounts/plain": data({ type: "kv", options: null }),
      "GET /v1/secret/data/sdk/allowed/hello": "kvV2.read.ok",
    });
    const c = m.client();
    const denied = await rejection(c.kv().read("sdk/allowed/hello"));
    expect(denied.code).toBe("PERMISSION_DENIED");
    expect(denied.message).toContain("preflight capability check");
    expect(await c.kv().version({ path: "sdk/allowed/hello" })).toBe(2);
    expect((await rejection(c.kv("nope").read("x"))).code).toBe("PERMISSION_DENIED");
    expect((await rejection(c.kv("sys").version())).message).toContain("not a KV mount");
    expect((await rejection(c.kv("weird").version())).message).toContain("unknown KV version");
    expect(await c.kv("plain").version()).toBe(1);
  });
});
