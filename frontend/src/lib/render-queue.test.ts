import { describe, expect, it } from "vitest";
import { RenderQueue } from "@/lib/render-queue";

/** A job that finishes when told to, and records when it started. */
function job(started: string[], name: string) {
  let finish: () => void = () => {};
  const run = () =>
    new Promise<void>((resolve) => {
      started.push(name);
      finish = resolve;
    });
  return { run, finish: () => finish() };
}

const tick = () => new Promise((resolve) => setTimeout(resolve, 0));

describe("RenderQueue", () => {
  it("runs at most `concurrency` jobs at once, nearest page first", async () => {
    const queue = new RenderQueue(2);
    const started: string[] = [];
    const current = { page: 1 };
    const jobs = [1, 2, 3, 4, 5].map((page) => {
      const j = job(started, `p${page}`);
      queue.schedule(`p${page}`, () => Math.abs(page - current.page), j.run);
      return j;
    });
    expect(started).toEqual(["p1", "p2"]);
    expect(queue.pending).toBe(3);

    // The reader has flung to the end: page 5 is what matters when a slot frees up.
    current.page = 5;
    jobs[0]?.finish();
    await tick();
    expect(started).toEqual(["p1", "p2", "p5"]);
    jobs[1]?.finish();
    await tick();
    expect(started).toEqual(["p1", "p2", "p5", "p4"]);
  });

  it("a cancelled job never starts; a running one is left alone", async () => {
    const queue = new RenderQueue(1);
    const started: string[] = [];
    const first = job(started, "a");
    const second = job(started, "b");
    queue.schedule("a", () => 0, first.run);
    const handle = queue.schedule("b", () => 1, second.run);
    handle.cancel();
    expect(queue.pending).toBe(0);
    first.finish();
    await tick();
    expect(started).toEqual(["a"]);
    expect(queue.active).toBe(0);
  });

  it("re-scheduling a key replaces the waiting job rather than queueing it twice", () => {
    const queue = new RenderQueue(1);
    const started: string[] = [];
    queue.schedule("busy", () => 0, job(started, "busy").run);
    queue.schedule("p2", () => 2, job(started, "p2-old").run);
    queue.schedule("p2", () => 2, job(started, "p2-new").run);
    expect(queue.pending).toBe(1);
  });

  it("keeps going after a job fails", async () => {
    const queue = new RenderQueue(1);
    const started: string[] = [];
    queue.schedule(
      "bad",
      () => 0,
      () => Promise.reject(new Error("render failed")),
    );
    const next = job(started, "next");
    queue.schedule("next", () => 1, next.run);
    await tick();
    expect(started).toEqual(["next"]);
  });
});
