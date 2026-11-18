/* eslint-disable @typescript-eslint/no-explicit-any, @typescript-eslint/no-unsafe-return -- test helper over dynamic JSON */
// Test support: an OpenBao mock server that answers with the recorded fixtures
// (test/fixtures/<function>.<case>.json, recorded against openbao/openbao:2.7.2).

import { readFileSync } from "node:fs";
import { afterEach } from "vitest";
import { OpenBaoClient, type OpenBaoConfigOptions } from "../../src/index.js";
import {
  type MockResponse,
  type MockServer,
  type RecordedRequest,
  startServer,
} from "../helpers/server.js";

interface Fixture {
  request: { method: string; path: string; headers: string[]; body: unknown };
  response: { status: number; headers: string[]; body: unknown };
}

const cache = new Map<string, Fixture>();

/** Loads a fixture by name (`kvV2.read.ok`). */
export function fixture(name: string): Fixture {
  let f = cache.get(name);
  if (f === undefined) {
    f = JSON.parse(
      readFileSync(new URL(`../fixtures/${name}.json`, import.meta.url), "utf8"),
    ) as Fixture;
    cache.set(name, f);
  }
  return f;
}

/** The recorded response of a fixture as a mock response (optionally with body changes). */
export function fx(name: string, patch?: (body: any) => unknown): MockResponse {
  const f = fixture(name);
  const headers: Record<string, string> = {};
  for (const h of f.response.headers) {
    const i = h.indexOf(":");
    headers[h.slice(0, i).toLowerCase()] = h.slice(i + 1).trim();
  }
  let body = f.response.body === null ? undefined : structuredClone(f.response.body);
  if (patch !== undefined) body = patch(body) as typeof body;
  return {
    status: f.response.status,
    headers,
    ...(body === undefined ? {} : { body: typeof body === "string" ? body : JSON.stringify(body) }),
  };
}

/** A route answer: a fixture name, a canned response or a function. */
export type Route = string | MockResponse | ((req: RecordedRequest, url: URL) => Route);

/** Routes keyed by `"METHOD /v1/path"`; `GET ...?list=true` is keyed as `LIST`. */
export type Routes = Record<string, Route | Route[]>;

export interface VaultMock extends MockServer {
  /** Requests as `"METHOD /path"` keys (LIST for list=true). */
  keys(): string[];
  /** Parsed JSON body of request `i` (negative = from the end). */
  body(i?: number): any;
  /** Request `i` (negative = from the end). */
  req(i?: number): RecordedRequest;
  /** A client for this server (no retries, token `root-token-test`). */
  client(options?: OpenBaoConfigOptions): OpenBaoClient;
}

const servers: MockServer[] = [];
const clients: OpenBaoClient[] = [];
afterEach(async () => {
  await Promise.all(clients.splice(0).map((c) => c.close()));
  await Promise.all(servers.splice(0).map((s) => s.close()));
});

/** Request key: `LIST /v1/x` for list=true, else `METHOD /v1/x` (path without query). */
export function keyOf(req: RecordedRequest): string {
  const url = new URL(req.url, "http://x");
  const method = url.searchParams.get("list") === "true" ? "LIST" : req.method;
  return `${method} ${url.pathname.replace(/\/$/, "")}`;
}

function resolve(route: Route, req: RecordedRequest, url: URL): MockResponse {
  if (typeof route === "string") return fx(route);
  if (typeof route === "function") return resolve(route(req, url), req, url);
  return route;
}

/** Starts a mock OpenBao server. A route given as an array answers in sequence (last repeats). */
export async function vault(routes: Routes = {}): Promise<VaultMock> {
  const counts = new Map<string, number>();
  const s = await startServer((req) => {
    const key = keyOf(req);
    const url = new URL(req.url, "http://x");
    const route = routes[key];
    if (route === undefined) {
      return { status: 418, body: { errors: [`no mock route for ${key}`] } };
    }
    if (Array.isArray(route)) {
      const n = counts.get(key) ?? 0;
      counts.set(key, n + 1);
      return resolve(route[Math.min(n, route.length - 1)] as Route, req, url);
    }
    return resolve(route, req, url);
  });
  servers.push(s);
  const at = (i: number): RecordedRequest => {
    const r = s.requests[i < 0 ? s.requests.length + i : i];
    if (r === undefined) throw new Error(`no request ${i}`);
    return r;
  };
  return Object.assign(s, {
    keys: () => s.requests.map(keyOf),
    req: (i = -1) => at(i),
    body: (i = -1) => {
      const b = at(i).body;
      return b === "" ? undefined : JSON.parse(b);
    },
    client: (options: OpenBaoConfigOptions = {}) => {
      const c = new OpenBaoClient({
        url: s.url,
        token: "root-token-test",
        retry: { maxRetries: 0 },
        ...options,
      });
      clients.push(c);
      return c;
    },
  });
}

/** Captures a rejection (fails when the promise resolves). */
export async function rejection(p: Promise<unknown>): Promise<any> {
  try {
    await p;
  } catch (err) {
    return err;
  }
  throw new Error("expected a rejection");
}

/** A 204 response. */
export const NO_CONTENT: MockResponse = { status: 204 };

/** An OpenBao error response. */
export function errors(status: number, ...messages: string[]): MockResponse {
  return { status, body: { errors: messages } };
}

/** An envelope response with `data`. */
export function data(d: unknown, extra: Record<string, unknown> = {}): MockResponse {
  return {
    status: 200,
    body: {
      request_id: "r",
      lease_id: "",
      renewable: false,
      lease_duration: 0,
      data: d,
      wrap_info: null,
      warnings: null,
      auth: null,
      ...extra,
    },
  };
}

/** Routes for fixtures, keyed by their recorded request (`fromFixtures("kvV2.read.ok")`). */
export function fromFixtures(...names: string[]): Routes {
  const routes: Routes = {};
  for (const name of names) {
    const r = fixture(name).request;
    routes[`${r.method} ${r.path.split("?")[0]?.replace(/\/$/, "") ?? ""}`] = name;
  }
  return routes;
}
