/**
 * The cross-tab lock every Chat engine operation runs under.
 *
 * Each tab has its own engine over the same browser store, and they take
 * turns under one Web Lock. A tab the browser froze while holding it would
 * stall every other tab for as long as it stays frozen, so the holder says it
 * is alive on a BroadcastChannel while it holds the lock, and a waiting tab
 * takes the lock over once the holder has been silent for a while. Taking
 * over moves the store's writer generation on (`claimWriter(true)`): the
 * frozen tab, if it ever resumes, has its writes refused instead of writing
 * over the new holder's. A tab that is merely busy keeps saying it is alive
 * and keeps the lock.
 */

/** How often the holder says it is alive. */
export const ALIVE_EVERY_MS = 5_000
/** How long a holder may stay silent before a waiting tab takes over. */
export const SILENT_FOR_MS = 30_000
/** How often a waiting tab checks whether the holder went silent. */
const WATCH_EVERY_MS = 1_000

export class EngineLock {
  private queue: Promise<unknown> = Promise.resolve()
  private lastAlive = 0
  private readonly channel: BroadcastChannel

  constructor(
    private readonly name: string,
    /** Claim the writer generation at the start of each turn. */
    private readonly claimWriter: (takeOver: boolean) => Promise<unknown>,
    private readonly now: () => number = Date.now,
  ) {
    this.channel = new BroadcastChannel(`${name}:alive`)
    this.channel.onmessage = () => {
      this.lastAlive = this.now()
    }
  }

  /**
   * Run `operation` under the lock. Operations of one tab run one after
   * another before they reach the cross-tab lock, so a tab never takes the
   * lock over from itself.
   */
  run<T>(operation: (tookOver: boolean) => Promise<T>): Promise<T> {
    // The queue waits for the operation itself, not only for the lock: if the
    // lock is taken from this tab, its request fails at once while the
    // operation may still be running, and the next one must not start beside
    // it on the same engine.
    let running: Promise<unknown> = Promise.resolve()
    const tracked = (tookOver: boolean) => {
      const started = operation(tookOver)
      running = started.catch(() => undefined)
      return started
    }
    const result = this.queue.then(() => this.acquire(tracked))
    this.queue = result.catch(() => undefined).then(() => running)
    return result
  }

  close(): void {
    this.channel.close()
  }

  private async acquire<T>(operation: (tookOver: boolean) => Promise<T>): Promise<T> {
    const waiting = new AbortController()
    const startedWaiting = this.now()
    let granted = false
    const watch = setInterval(() => {
      const heardFrom = Math.max(this.lastAlive, startedWaiting)
      if (this.now() - heardFrom >= SILENT_FOR_MS) waiting.abort()
    }, WATCH_EVERY_MS)
    try {
      return await navigator.locks.request(
        this.name,
        { mode: 'exclusive', signal: waiting.signal },
        () => {
          // Watching stops once the lock is ours: a holder hears nothing of
          // its own, and must not take the lock back if it is taken from it.
          granted = true
          clearInterval(watch)
          return this.hold(operation, false)
        },
      )
    } catch (error) {
      if (granted || !waiting.signal.aborted) throw error
      // The holder stopped answering: take the lock over.
      return await navigator.locks.request(
        this.name,
        { mode: 'exclusive', steal: true },
        () => this.hold(operation, true),
      )
    } finally {
      clearInterval(watch)
    }
  }

  private async hold<T>(operation: (tookOver: boolean) => Promise<T>, takeOver: boolean): Promise<T> {
    this.channel.postMessage('alive')
    const alive = setInterval(() => this.channel.postMessage('alive'), ALIVE_EVERY_MS)
    try {
      await this.claimWriter(takeOver)
      return await operation(takeOver)
    } finally {
      clearInterval(alive)
    }
  }
}
