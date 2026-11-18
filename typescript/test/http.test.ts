import { describe, expect, it } from "vitest";
import {
  durationString,
  encodePath,
  encodeSegment,
  isUtf8,
  parseTime,
  parseVaultDuration,
  secondsToMs,
  stringMap,
  strings,
} from "../src/http.js";
import { data, rejection, vault } from "./support/vault.js";

describe("http helpers", () => {
  it("encodes path segments but keeps separators and readable characters", () => {
    expect(encodePath("kv1", "/sdk/with space/", "", "a:b@c")).toBe("kv1/sdk/with%20space/a:b@c");
    expect(encodeSegment("a/b?c#d%")).toBe("a%2Fb%3Fc%23d%25");
  });

  it("durations and times", () => {
    expect(durationString(1500)).toBe("2s");
    expect(durationString(0)).toBe("0s");
    expect(() => durationString(-1)).toThrow(/invalid duration/);
    expect(() => durationString(Number.NaN)).toThrow(/invalid duration/);
    expect(parseVaultDuration(30)).toBe(30_000);
    expect(parseVaultDuration("45")).toBe(45_000);
    expect(parseVaultDuration("720h0m0s")).toBe(2_592_000_000);
    expect(parseVaultDuration("1m30s")).toBe(90_000);
    expect(parseVaultDuration("250ms")).toBe(250);
    expect(parseVaultDuration("")).toBeUndefined();
    expect(parseVaultDuration("soon")).toBeUndefined();
    expect(parseVaultDuration(null)).toBeUndefined();
    expect(secondsToMs("3")).toBe(0);
    expect(parseTime(0)).toBeNull();
    expect(parseTime("not a date")).toBeNull();
    expect(parseTime(null)).toBeNull();
    expect(parseTime(1)?.getTime()).toBe(1000);
  });

  it("value helpers", () => {
    expect(isUtf8(new Uint8Array([0xc3, 0xa9]))).toBe(true);
    expect(isUtf8(new Uint8Array([0xff]))).toBe(false);
    expect(strings(["a", 1, null, "b"])).toEqual(["a", "b"]);
    expect(strings("x")).toEqual([]);
    expect(stringMap({ a: "1", b: 2, c: null, d: { e: 1 } })).toEqual({
      a: "1",
      b: "2",
      d: '{"e":1}',
    });
    expect(stringMap([1])).toEqual({});
    expect(stringMap(null)).toEqual({});
  });

  it("empty bodies and missing data are unexpected responses", async () => {
    const m = await vault({
      "GET /v1/sys/policies/acl/a": { status: 204 },
      "GET /v1/sys/policies/acl/b": data(null),
    });
    const sys = m.client().sys;
    expect((await rejection(sys.readPolicy("a"))).message).toBe(
      "sys.readPolicy a: unexpected response (empty response body)",
    );
    expect((await rejection(sys.readPolicy("b"))).message).toContain("response has no data");
  });
});
