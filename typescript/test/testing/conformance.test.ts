import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { OpenBaoClient } from "../../src/client.js";
import {
  type ConformanceOptions,
  conformanceCases,
  formatReport,
  runConformance,
} from "../../src/testing/index.js";
import { type MockServer, startServer } from "../helpers/server.js";

const scenariosDir = fileURLToPath(new URL("../../../conformance/scenarios/", import.meta.url));
let server: MockServer;

beforeAll(async () => {
  // Minimal OpenBao: sys/health (active node) and token lookup-self.
  server = await startServer((req) => {
    if (req.url.startsWith("/v1/sys/health"))
      return { status: 200, body: { initialized: true, sealed: false, standby: false, version: "0.0.1" } };
    if (req.url === "/v1/auth/token/lookup-self") return { status: 200, body: { data: {} } };
    return { status: 404, body: { errors: [] } };
  });
});

afterAll(async () => {
  await server.close();
});

function options(): ConformanceOptions {
  return {
    scenariosDir,
    categories: ["core"],
    factories: {
      core: () => new OpenBaoClient({ url: server.url, token: "conformance-token" }),
    },
    capabilities: { core: ["version"] },
  };
}

describe("conformance (core) against a local OpenBao mock", () => {
  it("every core scenario passes", async () => {
    const report = await runConformance(options());
    expect(report.failed, formatReport(report)).toBe(0);
    expect(report.skipped).toBe(0);
    expect(report.results.map((r) => r.id)).toContain("core.health");
  });

  for (const c of conformanceCases(options())) {
    it.skipIf(c.skip !== undefined)(`case ${c.id}`, async () => {
      expect((await c.run()).status).toBe("passed");
    });
  }
});
