// A small in-memory OpenBao KV server (v1 and v2 mounts) for provider and conformance tests.
// It mirrors the behaviour recorded in the fixtures: 404 `{"errors":[]}` for missing keys,
// 204 for deletes of missing paths, soft deletes, CAS and folder listings.

import type { MockResponse, RecordedRequest } from "../helpers/server.js";

interface Version {
  data: Record<string, unknown>;
  created: string;
  deleted: string;
  destroyed: boolean;
}

interface Entry {
  versions: Version[];
  custom: Record<string, string>;
  created: string;
  updated: string;
}

const notFound: MockResponse = { status: 404, body: { errors: [] } };
const noContent: MockResponse = { status: 204 };
const ok = (data: unknown): MockResponse => ({ status: 200, body: { request_id: "r", data } });

/** Fake KV server; `mounts` maps a mount name to its KV version. */
export class FakeKv {
  readonly v1 = new Map<string, Record<string, unknown>>();
  readonly v2 = new Map<string, Entry>();
  #clock = Date.parse("2026-01-01T00:00:00Z");

  constructor(readonly mounts: Record<string, 1 | 2> = { secret: 2, kv1: 1 }) {}

  #now(): string {
    this.#clock += 1000;
    return new Date(this.#clock).toISOString();
  }

  handle = (req: RecordedRequest): MockResponse => {
    const url = new URL(req.url, "http://x");
    const parts = url.pathname
      .replace(/^\/v1\//, "")
      .split("/")
      .filter((p) => p !== "")
      .map(decodeURIComponent);
    const list = url.searchParams.get("list") === "true";
    const body = req.body === "" ? {} : (JSON.parse(req.body) as Record<string, unknown>);
    if (parts[0] === "sys" && parts[1] === "internal") {
      const version = this.mounts[parts[4] ?? ""];
      if (version === undefined)
        return { status: 403, body: { errors: ["preflight capability check returned 403"] } };
      return ok({ type: "kv", path: `${parts[4]}/`, options: { version: String(version) } });
    }
    const mount = parts[0] ?? "";
    const version = this.mounts[mount];
    if (version === undefined) return { status: 404, body: { errors: ["no handler for route"] } };
    if (version === 1) return this.#v1(req.method, mount, parts.slice(1).join("/"), body, list);
    const kind = parts[1] ?? "";
    const path = parts.slice(2).join("/");
    return this.#v2(
      req.method,
      kind,
      `${mount}/${path}`,
      body,
      list,
      url.searchParams.get("version"),
    );
  };

  #v1(
    method: string,
    mount: string,
    path: string,
    body: Record<string, unknown>,
    list: boolean,
  ): MockResponse {
    const key = `${mount}/${path}`;
    if (list) {
      const keys = folder([...this.v1.keys()], key);
      return keys.length === 0 ? notFound : ok({ keys });
    }
    if (method === "GET") {
      const d = this.v1.get(key);
      return d === undefined
        ? notFound
        : { status: 200, body: { data: d, lease_duration: 2764800 } };
    }
    if (method === "POST" || method === "PUT") {
      this.v1.set(key, body);
      return noContent;
    }
    if (method === "DELETE") {
      this.v1.delete(key);
      return noContent;
    }
    return { status: 405, body: { errors: ["1 error occurred:\n\t* unsupported operation\n\n"] } };
  }

  #meta(e: Entry, version: number): Record<string, unknown> {
    const v = e.versions[version - 1] as Version;
    return {
      version,
      created_time: v.created,
      deletion_time: v.deleted,
      destroyed: v.destroyed,
      custom_metadata: Object.keys(e.custom).length === 0 ? null : e.custom,
    };
  }

  #v2(
    method: string,
    kind: string,
    key: string,
    body: Record<string, unknown>,
    list: boolean,
    versionParam: string | null,
  ): MockResponse {
    const e = this.v2.get(key);
    if (kind === "metadata") {
      if (list) {
        const keys = folder([...this.v2.keys()], key);
        return keys.length === 0 ? notFound : ok({ keys });
      }
      if (method === "GET") {
        if (e === undefined) return notFound;
        const versions: Record<string, unknown> = {};
        e.versions.forEach((v, i) => {
          versions[String(i + 1)] = {
            created_time: v.created,
            deletion_time: v.deleted,
            destroyed: v.destroyed,
          };
        });
        return ok({
          cas_required: false,
          created_time: e.created,
          updated_time: e.updated,
          current_version: e.versions.length,
          oldest_version: 0,
          max_versions: 0,
          delete_version_after: "0s",
          custom_metadata: Object.keys(e.custom).length === 0 ? null : e.custom,
          versions,
        });
      }
      if (method === "POST") {
        if (e !== undefined)
          e.custom = (body.custom_metadata as Record<string, string>) ?? e.custom;
        return noContent;
      }
      if (method === "DELETE") {
        this.v2.delete(key);
        return noContent;
      }
    }
    if (kind === "data") {
      if (method === "GET") {
        if (e === undefined) return notFound;
        const n = versionParam === null ? e.versions.length : Number(versionParam);
        const v = e.versions[n - 1];
        if (v === undefined) return notFound;
        if (v.deleted !== "" || v.destroyed)
          return { status: 404, body: { data: { data: null, metadata: this.#meta(e, n) } } };
        return ok({ data: v.data, metadata: this.#meta(e, n) });
      }
      if (method === "POST" || method === "PUT") {
        const cas = (body.options as { cas?: number } | undefined)?.cas;
        const current = e?.versions.length ?? 0;
        if (cas !== undefined && cas !== current) {
          return {
            status: 400,
            body: { errors: ["check-and-set parameter did not match the current version"] },
          };
        }
        const now = this.#now();
        const entry = e ?? { versions: [], custom: {}, created: now, updated: now };
        entry.versions.push({
          data: body.data as Record<string, unknown>,
          created: now,
          deleted: "",
          destroyed: false,
        });
        entry.updated = now;
        this.v2.set(key, entry);
        return ok(this.#meta(entry, entry.versions.length));
      }
      if (method === "DELETE") {
        const latest = e?.versions.at(-1);
        if (latest !== undefined) latest.deleted = this.#now();
        return noContent;
      }
    }
    if (kind === "delete" && method === "POST") {
      for (const n of (body.versions as number[] | undefined) ?? []) {
        const v = e?.versions[n - 1];
        if (v !== undefined) v.deleted = this.#now();
      }
      return noContent;
    }
    return { status: 405, body: { errors: ["1 error occurred:\n\t* unsupported operation\n\n"] } };
  }
}

/** Keys directly under `folder` (sub-folders end in `/`), sorted. */
function folder(all: string[], dir: string): string[] {
  const prefix = dir.endsWith("/") ? dir : `${dir}/`;
  const out = new Set<string>();
  for (const k of all) {
    if (!k.startsWith(prefix)) continue;
    const rest = k.slice(prefix.length);
    const slash = rest.indexOf("/");
    out.add(slash === -1 ? rest : rest.slice(0, slash + 1));
  }
  return [...out].sort();
}
