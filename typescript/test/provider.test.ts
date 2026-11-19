import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import { OpenBaoClient, OpenBaoSecretsProvider, REDACTED } from "../src/index.js";
import { formatReport, runConformance } from "../src/testing-entry.js";
import { type MockServer, startServer } from "./helpers/server.js";
import { FakeKv } from "./support/fake-kv.js";
import { errors, rejection, vault } from "./support/vault.js";

const scenariosDir = fileURLToPath(new URL("../../conformance/scenarios/", import.meta.url));

const servers: MockServer[] = [];
const clients: OpenBaoClient[] = [];
afterEach(async () => {
  await Promise.all(clients.splice(0).map((c) => c.close()));
  await Promise.all(servers.splice(0).map((s) => s.close()));
});

async function fake(mounts?: Record<string, 1 | 2>) {
  const kv = new FakeKv(mounts);
  const server = await startServer(kv.handle);
  servers.push(server);
  const client = new OpenBaoClient({ url: server.url, token: "t-root", retry: { maxRetries: 0 } });
  clients.push(client);
  return { kv, server, client };
}

describe("OpenBaoSecretsProvider on KV v2", () => {
  it("stores {value}, versions, typed getters, bytes as base64 and objects as JSON", async () => {
    const { kv, client } = await fake();
    const p = client.secrets({ path: "/apps/" });
    expect(p).toBeInstanceOf(OpenBaoSecretsProvider);
    expect(p.path).toBe("apps");
    expect(p.fullPath("db")).toBe("apps/db");
    expect(p.fullPath("db", "other")).toBe("other/db");
    expect(p.fullPath("", "other")).toBe("other");
    expect(client.secrets().fullPath("x")).toBe("x");
    expect(await p.set("db", "s3cret")).toBe("1");
    expect(kv.v2.get("secret/apps/db")?.versions[0]?.data).toEqual({ value: "s3cret" });
    expect(await p.set("db", "s3cret-2")).toBe("2");
    const v = await p.get("db");
    expect(v?.reveal()).toBe("s3cret-2");
    expect(v?.version).toBe("2");
    expect(String(v)).toBe(`SecretValue(${REDACTED})`);
    expect((await p.get("db", { version: "1" }))?.reveal()).toBe("s3cret");
    await expect(p.get("db", { version: "x" })).rejects.toMatchObject({ code: "VALIDATION" });
    await p.set("bin", new Uint8Array([0, 255, 1]));
    expect(kv.v2.get("secret/apps/bin")?.versions[0]?.data).toEqual({
      value: "AP8B",
      encoding: "base64",
    });
    expect([...((await p.get("bin"))?.revealBytes() ?? [])]).toEqual([0, 255, 1]);
    await p.set("obj", { a: 1 });
    expect(await p.getJson("obj")).toEqual({ a: 1 });
    expect(kv.v2.get("secret/apps/obj")?.versions[0]?.data).toEqual({ value: '{"a":1}' });
    expect(await p.get("missing")).toBeNull();
  });

  it("reads multi-field secrets as JSON and non-string values JSON-encoded", async () => {
    const { kv, client } = await fake();
    const now = new Date().toISOString();
    const entry = (data: Record<string, unknown>) => ({
      versions: [{ data, created: now, deleted: "", destroyed: false }],
      custom: {},
      created: now,
      updated: now,
    });
    kv.v2.set("secret/multi", entry({ user: "u", password: "p" }));
    kv.v2.set("secret/num", entry({ value: 42 }));
    const p = client.secrets();
    expect(await p.getJson("multi")).toEqual({ user: "u", password: "p" });
    expect(await p.getNumber("num")).toBe(42);
  });

  it("set with cas/tags/description, metadata, list (folders and deleted skipped), delete modes", async () => {
    const { kv, client } = await fake();
    const p = client.secrets({ path: "team" });
    await p.set("a", "1", { tags: { owner: "sdk" }, description: "first" });
    expect(kv.v2.get("secret/team/a")?.custom).toEqual({ owner: "sdk", description: "first" });
    await p.set("b", "2");
    await p.set("dir/c", "3");
    await expect(p.set("a", "x", { cas: 0 })).rejects.toMatchObject({ code: "CONFLICT" });
    expect(await p.set("a", "1b", { cas: 1 })).toBe("2");
    const meta = await p.metadata("a");
    expect(meta).toMatchObject({
      name: "a",
      version: "2",
      versions: 2,
      tags: { owner: "sdk", description: "first" },
    });
    expect(meta?.createdAt).toBeInstanceOf(Date);
    expect(meta?.updatedAt).toBeInstanceOf(Date);
    expect(meta?.extra).toMatchObject({
      maxVersions: "0",
      casRequired: "false",
      deleteVersionAfter: "0s",
      oldestVersion: "0",
    });
    expect((await p.metadata("dir/c"))?.path).toBe("dir");
    expect(await p.metadata("nope")).toBeNull();
    expect((await p.list()).map((m) => m.name)).toEqual(["a", "b"]);
    expect((await p.list("dir/")).map((m) => [m.name, m.path])).toEqual([["dir/c", "dir"]]);
    expect(await p.list("empty")).toEqual([]);
    const all = await p.getAll();
    expect([...all.keys()]).toEqual(["a", "b"]);
    // soft delete: get/metadata/list treat the secret as gone, delete again is NOT_FOUND
    await p.delete("b");
    expect(await p.get("b")).toBeNull();
    expect(await p.metadata("b")).toBeNull();
    expect((await p.list()).map((m) => m.name)).toEqual(["a"]);
    expect((await rejection(p.delete("b"))).code).toBe("NOT_FOUND");
    // versions
    await p.delete("a", { versions: ["1"] });
    expect(kv.v2.get("secret/team/a")?.versions[0]?.deleted).not.toBe("");
    await expect(p.delete("a", { versions: ["zero"] })).rejects.toMatchObject({
      code: "VALIDATION",
    });
    await expect(p.delete("ghost", { versions: ["1"] })).rejects.toMatchObject({
      code: "NOT_FOUND",
    });
    // permanent
    await p.delete("a", { permanent: true });
    expect(kv.v2.has("secret/team/a")).toBe(false);
    await expect(p.delete("a", { permanent: true })).rejects.toMatchObject({ code: "NOT_FOUND" });
    // other path via options
    await p.set("x", "y", { path: "elsewhere" });
    expect((await p.get("x", { path: "elsewhere" }))?.reveal()).toBe("y");
  });

  it("putSecret (base-class byte path) keeps UTF-8 as text and other bytes as base64", async () => {
    const { kv, client } = await fake();
    const p = client.secrets() as unknown as {
      putSecret(n: string, v: Uint8Array, o: object): Promise<string>;
    };
    await p.putSecret("t", new TextEncoder().encode("héllo"), {});
    await p.putSecret("b", new Uint8Array([0xff]), {});
    expect(kv.v2.get("secret/t")?.versions[0]?.data).toEqual({ value: "héllo" });
    expect(kv.v2.get("secret/b")?.versions[0]?.data).toEqual({ value: "/w==", encoding: "base64" });
  });

  it("loadEnv and watch on top of the primitives; close() stops watchers", async () => {
    const { client } = await fake();
    const p = client.secrets({ path: "env" });
    await p.set("db-url", "postgres://x");
    const env: Record<string, string | undefined> = {};
    expect(await p.loadEnv("", { env, prefix: "APP_" })).toEqual({ APP_DB_URL: "db-url" });
    expect(env.APP_DB_URL).toBe("postgres://x");
    const seen: (string | null)[] = [];
    const handle = p.watch("db-url", 10, (n) => {
      seen.push(n?.reveal() ?? null);
    });
    await handle.ready;
    await p.set("db-url", "postgres://y");
    await new Promise((r) => setTimeout(r, 60));
    expect(seen).toContain("postgres://y");
    expect(p.activeWatchers).toBe(1);
    await client.close();
    expect(handle.stopped).toBe(true);
    await p.close();
  });

  it("runs the shared secrets conformance scenarios", async () => {
    const { client } = await fake();
    const report = await runConformance({
      scenariosDir,
      categories: ["secrets"],
      factories: { secrets: () => client.secrets() },
      capabilities: { secrets: [...OpenBaoSecretsProvider.capabilities] },
    });
    expect(report.failed, formatReport(report)).toBe(0);
    expect(report.skipped).toBe(0);
  });
});

describe("OpenBaoSecretsProvider on KV v1", () => {
  it("unversioned: set returns '', version/cas/tags/versions unsupported, list names only", async () => {
    const { kv, client } = await fake({ kv1: 1 });
    const p = client.secrets({ mount: "kv1", path: "app" });
    expect(await p.set("a", "1")).toBe("");
    expect(kv.v1.get("kv1/app/a")).toEqual({ value: "1" });
    expect((await p.get("a"))?.version).toBeUndefined();
    expect((await p.get("a"))?.reveal()).toBe("1");
    await expect(p.get("a", { version: "1" })).rejects.toMatchObject({ code: "VALIDATION" });
    await expect(p.set("a", "2", { cas: 1 })).rejects.toMatchObject({ code: "UNSUPPORTED" });
    await expect(p.set("a", "2", { tags: { x: "y" } })).rejects.toMatchObject({
      code: "UNSUPPORTED",
    });
    await expect(p.delete("a", { versions: ["1"] })).rejects.toMatchObject({ code: "UNSUPPORTED" });
    await p.set("sub/b", "2");
    expect(await p.list()).toEqual([{ name: "a", tags: {}, extra: {} }]);
    expect(await p.metadata("sub/b")).toEqual({ name: "sub/b", path: "sub", tags: {}, extra: {} });
    expect(await p.metadata("zzz")).toBeNull();
    await p.delete("a");
    expect(kv.v1.has("kv1/app/a")).toBe(false);
    await expect(p.delete("a")).rejects.toMatchObject({ code: "NOT_FOUND" });
  });

  it("runs the conformance scenarios without the versions capability", async () => {
    const { client } = await fake({ kv1: 1 });
    const report = await runConformance({
      scenariosDir,
      categories: ["secrets"],
      factories: { secrets: () => client.secrets({ mount: "kv1" }) },
      capabilities: { secrets: ["write", "delete"] },
    });
    expect(report.failed, formatReport(report)).toBe(0);
  });
});

describe("provider error paths", () => {
  it("permission errors propagate (no silent null)", async () => {
    const m = await vault({
      "GET /v1/secret/data/x": errors(403, "1 error occurred: * permission denied"),
      "LIST /v1/secret/metadata": errors(403, "1 error occurred: * permission denied"),
      "GET /v1/secret/metadata/x": errors(403, "1 error occurred: * permission denied"),
      "POST /v1/secret/data/x": errors(403, "1 error occurred: * permission denied"),
    });
    const p = m.client({ kvVersion: 2 }).secrets();
    expect((await rejection(p.get("x"))).code).toBe("PERMISSION_DENIED");
    expect((await rejection(p.list())).code).toBe("PERMISSION_DENIED");
    expect((await rejection(p.metadata("x"))).code).toBe("PERMISSION_DENIED");
    expect((await rejection(p.delete("x"))).code).toBe("PERMISSION_DENIED");
    expect((await rejection(p.set("x", "v"))).code).toBe("PERMISSION_DENIED");
  });

  it("honours AbortSignal", async () => {
    const m = await vault();
    const p = m.client({ kvVersion: 2 }).secrets();
    await expect(p.set("x", "v", { signal: AbortSignal.abort() })).rejects.toMatchObject({
      code: "CANCELLED",
    });
    await expect(p.get("x", { signal: AbortSignal.abort() })).rejects.toMatchObject({
      code: "CANCELLED",
    });
  });
});
