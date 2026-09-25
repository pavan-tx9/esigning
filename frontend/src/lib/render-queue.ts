/**
 * Page renders, a few at a time and nearest first.
 *
 * pdf.js will happily start twenty renders at once, and a fling through a long document did:
 * the page the reader stopped on then waited behind nineteen they had already left. This runs
 * at most `concurrency` renders and always picks the one that matters most now -- the priority
 * is asked for at pick time, so a page the reader has since scrolled to jumps the queue.
 */

export interface Scheduled {
  /** Take the job out of the queue. A job already running is left to finish. */
  cancel: () => void;
}

interface Job {
  key: string;
  priority: () => number;
  run: () => Promise<void>;
}

export class RenderQueue {
  private readonly waiting: Job[] = [];
  private running = 0;
  private readonly concurrency: number;

  constructor(concurrency = 2) {
    this.concurrency = Math.max(1, concurrency);
  }

  /** Lower priority values run first. A job with the same key replaces the one waiting. */
  schedule(key: string, priority: () => number, run: () => Promise<void>): Scheduled {
    const job: Job = { key, priority, run };
    const at = this.waiting.findIndex((other) => other.key === key);
    if (at >= 0) {
      this.waiting.splice(at, 1);
    }
    this.waiting.push(job);
    this.pump();
    return {
      cancel: () => {
        const index = this.waiting.indexOf(job);
        if (index >= 0) {
          this.waiting.splice(index, 1);
        }
      },
    };
  }

  get pending(): number {
    return this.waiting.length;
  }

  get active(): number {
    return this.running;
  }

  private pump(): void {
    while (this.running < this.concurrency && this.waiting.length > 0) {
      let best = 0;
      let bestPriority = Number.POSITIVE_INFINITY;
      this.waiting.forEach((job, index) => {
        const value = job.priority();
        if (value < bestPriority) {
          bestPriority = value;
          best = index;
        }
      });
      const [job] = this.waiting.splice(best, 1);
      if (job === undefined) {
        return;
      }
      this.running += 1;
      job.run().then(
        () => this.finished(),
        () => this.finished(),
      );
    }
  }

  private finished(): void {
    this.running -= 1;
    this.pump();
  }
}
