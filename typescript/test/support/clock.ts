import type { Scheduler } from "../../src/index.js";

/** A manual clock: timers fire only on `advance()`. */
export class ManualScheduler implements Scheduler {
  #now = 1_000_000;
  #seq = 0;
  readonly timers = new Map<number, { at: number; fn: () => void }>();

  now(): number {
    return this.#now;
  }

  setTimeout(fn: () => void, ms: number): unknown {
    const id = ++this.#seq;
    this.timers.set(id, { at: this.#now + ms, fn });
    return id;
  }

  clearTimeout(handle: unknown): void {
    this.timers.delete(handle as number);
  }

  /** Delay of the next timer from now, or `undefined`. */
  nextDelay(): number | undefined {
    let min: number | undefined;
    for (const t of this.timers.values()) min = min === undefined ? t.at : Math.min(min, t.at);
    return min === undefined ? undefined : min - this.#now;
  }

  /** Moves time forward, firing due timers in order, then lets promises settle. */
  async advance(ms: number): Promise<void> {
    const target = this.#now + ms;
    for (;;) {
      let next: [number, { at: number; fn: () => void }] | undefined;
      for (const e of this.timers)
        if (e[1].at <= target && (next === undefined || e[1].at < next[1].at)) next = e;
      if (next === undefined) break;
      this.timers.delete(next[0]);
      this.#now = next[1].at;
      next[1].fn();
      await settle();
    }
    this.#now = target;
    await settle();
  }
}

/** Lets pending promise callbacks (and quick local I/O) run. */
export async function settle(rounds = 20): Promise<void> {
  for (let i = 0; i < rounds; i++) await new Promise<void>((r) => setImmediate(r));
}
