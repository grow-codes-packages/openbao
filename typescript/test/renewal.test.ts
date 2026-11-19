import { describe, expect, it, vi } from "vitest";
import { UnavailableError, ValidationError, systemScheduler } from "../src/index.js";
import { RenewalLoop } from "../src/renewal.js";
import { ManualScheduler } from "./support/clock.js";

const HOUR = 3_600_000;

describe("RenewalLoop", () => {
  it("renews at 2/3 of the TTL while renewals grant the full TTL", async () => {
    const clock = new ManualScheduler();
    const renew = vi.fn().mockResolvedValue({ ttlMs: HOUR, renewable: true });
    const onRenew = vi.fn();
    const loop = new RenewalLoop({ renew, onRenew, scheduler: clock });
    loop.start({ ttlMs: HOUR, renewable: true });
    expect(loop.running).toBe(true);
    expect(loop.expiresAt).toBe(clock.now() + HOUR);
    expect(clock.nextDelay()).toBe((HOUR * 2) / 3);
    await clock.advance((HOUR * 2) / 3);
    expect(renew).toHaveBeenCalledTimes(1);
    expect(renew).toHaveBeenCalledWith(undefined);
    expect(onRenew).toHaveBeenCalledTimes(1);
    await clock.advance((HOUR * 2) / 3);
    expect(renew).toHaveBeenCalledTimes(2);
    loop.stop();
    loop.stop();
    expect(loop.running).toBe(false);
    expect(clock.timers.size).toBe(0);
  });

  it("onExpire fires exactly once after the max TTL caps a renewal", async () => {
    const clock = new ManualScheduler();
    const renew = vi
      .fn()
      .mockResolvedValueOnce({ ttlMs: 30_000, renewable: true })
      .mockResolvedValue({ ttlMs: 30_000, renewable: true });
    const onExpire = vi.fn();
    const loop = new RenewalLoop({ renew, onExpire, incrementMs: HOUR, scheduler: clock });
    loop.start({ ttlMs: 60_000, renewable: true });
    await clock.advance(40_000);
    expect(renew).toHaveBeenCalledWith(HOUR);
    // capped: 30 s granted < 1 h requested -> no more renewals, expire at the end
    expect(clock.nextDelay()).toBe(30_000);
    await clock.advance(30_000);
    expect(onExpire).toHaveBeenCalledTimes(1);
    expect(loop.expired).toBe(true);
    expect(loop.running).toBe(false);
    await clock.advance(HOUR);
    expect(renew).toHaveBeenCalledTimes(1);
    expect(onExpire).toHaveBeenCalledTimes(1);
  });

  it("non-renewable leases expire without renewing; ttl 0 never schedules", async () => {
    const clock = new ManualScheduler();
    const renew = vi.fn();
    const onExpire = vi.fn();
    new RenewalLoop({ renew, onExpire, scheduler: clock }).start({ ttlMs: 5000, renewable: false });
    await clock.advance(5000);
    expect(renew).not.toHaveBeenCalled();
    expect(onExpire).toHaveBeenCalledTimes(1);
    const idle = new RenewalLoop({ renew, scheduler: clock });
    idle.start({ ttlMs: 0, renewable: true });
    expect(idle.expiresAt).toBe(0);
    expect(clock.timers.size).toBe(0);
  });

  it("retries retryable failures halfway to expiry, then gives up", async () => {
    const clock = new ManualScheduler();
    const renew = vi
      .fn()
      .mockRejectedValueOnce(new UnavailableError("down"))
      .mockResolvedValueOnce({ ttlMs: 60_000, renewable: true })
      .mockRejectedValue(new ValidationError("lease is not renewable"));
    const onError = vi.fn();
    const onExpire = vi.fn();
    const throwing = () => {
      throw new Error("callback errors are ignored");
    };
    const loop = new RenewalLoop({
      renew,
      onError: (e) => {
        onError(e);
        throwing();
      },
      onExpire,
      onRenew: throwing,
      scheduler: clock,
    });
    loop.start({ ttlMs: 60_000, renewable: true });
    await clock.advance(40_000); // fails (retryable), 20 s left -> retry in 10 s
    expect(onError).toHaveBeenCalledTimes(1);
    expect(clock.nextDelay()).toBe(10_000);
    await clock.advance(10_000); // succeeds: ttl 60 s
    expect(renew).toHaveBeenCalledTimes(2);
    await clock.advance(40_000); // non-retryable -> expire at the end
    expect(onError).toHaveBeenCalledTimes(2);
    await clock.advance(20_000);
    expect(onExpire).toHaveBeenCalledTimes(1);
  });

  it("reacquires instead of expiring when configured, retrying failures", async () => {
    const clock = new ManualScheduler();
    const renew = vi.fn().mockResolvedValue({ ttlMs: 10_000, renewable: false });
    const reacquire = vi
      .fn()
      .mockRejectedValueOnce(new UnavailableError("down"))
      .mockResolvedValue({ ttlMs: 60_000, renewable: true });
    const onRenew = vi.fn();
    const loop = new RenewalLoop({ renew, reacquire, onRenew, scheduler: clock, minDelayMs: 100 });
    loop.start({ ttlMs: 60_000, renewable: true });
    await clock.advance(40_000); // renew -> not renewable, 10 s
    expect(renew).toHaveBeenCalledTimes(1);
    await clock.advance(10_000 * (2 / 3) + 1); // reacquire fails -> retry halfway
    expect(reacquire).toHaveBeenCalledTimes(1);
    await clock.advance(5000);
    expect(reacquire).toHaveBeenCalledTimes(2);
    expect(onRenew).toHaveBeenCalledTimes(2);
    expect(loop.running).toBe(true);
    loop.stop();
  });

  it("reacquire failures close to expiry end in onExpire", async () => {
    const clock = new ManualScheduler();
    const onExpire = vi.fn();
    const loop = new RenewalLoop({
      renew: vi.fn(),
      reacquire: vi.fn().mockRejectedValue(new Error("nope")),
      onExpire,
      scheduler: clock,
      minDelayMs: 1000,
      renewFraction: 5, // invalid -> default 2/3
    });
    loop.start({ ttlMs: 2400, renewable: false });
    await clock.advance(1600); // 800 ms left < 2 * minDelay -> expire at the end
    await clock.advance(800);
    expect(onExpire).toHaveBeenCalledTimes(1);
  });

  it("stop() during an in-flight renewal ignores its result", async () => {
    const clock = new ManualScheduler();
    let resolve!: (v: { ttlMs: number; renewable: boolean }) => void;
    let reject!: (e: unknown) => void;
    const renew = vi
      .fn()
      .mockImplementationOnce(() => new Promise((r) => (resolve = r)))
      .mockImplementationOnce(() => new Promise((_r, j) => (reject = j)));
    const onRenew = vi.fn();
    const onError = vi.fn();
    const a = new RenewalLoop({ renew, onRenew, scheduler: clock });
    a.start({ ttlMs: 3000, renewable: true });
    await clock.advance(2000);
    a.stop();
    resolve({ ttlMs: 3000, renewable: true });
    const b = new RenewalLoop({ renew, onError, scheduler: clock });
    b.start({ ttlMs: 3000, renewable: true });
    await clock.advance(2000);
    b.stop();
    reject(new Error("late"));
    await clock.advance(10);
    expect(onRenew).not.toHaveBeenCalled();
    expect(onError).not.toHaveBeenCalled();
    const reacquire = vi.fn(() => new Promise<never>((_r, j) => (reject = j)));
    const c = new RenewalLoop({ renew, reacquire, onError, scheduler: clock });
    c.start({ ttlMs: 3000, renewable: false });
    await clock.advance(2000);
    c.stop();
    reject(new Error("late"));
    await clock.advance(10);
    expect(onError).not.toHaveBeenCalled();
  });

  it("systemScheduler uses real unref'd timers", async () => {
    const fired = vi.fn();
    const h = systemScheduler.setTimeout(fired, 1);
    const h2 = systemScheduler.setTimeout(fired, 50);
    systemScheduler.clearTimeout(h2);
    expect(systemScheduler.now()).toBeGreaterThan(0);
    await new Promise((r) => setTimeout(r, 20));
    expect(fired).toHaveBeenCalledTimes(1);
    systemScheduler.clearTimeout(h);
  });
});
