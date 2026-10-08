import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { ALIVE_EVERY_MS, EngineLock, SILENT_FOR_MS } from './engineLock'

/** One exclusive lock with the parts of the Web Locks API the lock uses. */
class FakeLocks {
  private held: { release: () => void; fail: (error: Error) => void } | null = null
  private waiters: Array<() => void> = []

  async request<T>(
    _name: string,
    options: { signal?: AbortSignal; steal?: boolean },
    callback: () => Promise<T>,
  ): Promise<T> {
    if (options.steal && this.held) {
      // The browser releases the old holder's lock and rejects its request;
      // its callback keeps running.
      this.held.fail(new DOMException('stolen', 'AbortError'))
      this.held = null
    }
    if (this.held) {
      await new Promise<void>((resolve, reject) => {
        const grant = () => resolve()
        this.waiters.push(grant)
        options.signal?.addEventListener('abort', () => {
          this.waiters = this.waiters.filter(waiter => waiter !== grant)
          reject(new DOMException('aborted', 'AbortError'))
        })
      })
    }
    return await new Promise<T>((resolve, reject) => {
      const slot = {
        release: () => {
          if (this.held === slot) this.held = null
          this.waiters.shift()?.()
        },
        fail: reject,
      }
      this.held = slot
      callback().then(
        value => { slot.release(); resolve(value) },
        error => { slot.release(); reject(error) },
      )
    })
  }
}

describe('EngineLock', () => {
  let locks: FakeLocks

  beforeEach(() => {
    vi.useFakeTimers()
    locks = new FakeLocks()
    vi.stubGlobal('navigator', { ...navigator, locks })
  })

  afterEach(() => {
    vi.useRealTimers()
    vi.unstubAllGlobals()
  })

  it('runs one tab\'s operations one after another and claims the writer each turn', async () => {
    const claims: boolean[] = []
    const lock = new EngineLock('engine', async (takeOver) => { claims.push(takeOver) })
    const order: string[] = []
    const first = lock.run(async () => {
      order.push('first:start')
      await new Promise(resolve => setTimeout(resolve, 100))
      order.push('first:end')
    })
    const second = lock.run(async () => { order.push('second') })
    await vi.advanceTimersByTimeAsync(200)
    await Promise.all([first, second])
    expect(order).toEqual(['first:start', 'first:end', 'second'])
    expect(claims).toEqual([false, false])
    lock.close()
  })

  it('waits for a busy tab that keeps saying it is alive', async () => {
    const busy = new EngineLock('engine', async () => {})
    const waiting = new EngineLock('engine', async () => {})
    let done = false
    const slow = busy.run(() => new Promise<void>(resolve => setTimeout(() => { done = true; resolve() }, SILENT_FOR_MS * 3)))
    const claims: boolean[] = []
    const other = new EngineLock('engine', async (takeOver) => { claims.push(takeOver) })
    const next = other.run(async () => done)
    await vi.advanceTimersByTimeAsync(SILENT_FOR_MS * 3 + ALIVE_EVERY_MS)
    await expect(next).resolves.toBe(true)
    await slow
    expect(claims).toEqual([false])
    for (const lock of [busy, waiting, other]) lock.close()
  })

  it('takes over from a tab that went silent, and the frozen tab loses its turn', async () => {
    const frozen = new EngineLock('engine', async () => {})
    // A frozen tab: it holds the lock and its timers (its "alive") stop.
    const stuck = frozen.run(() => new Promise<void>(() => {}))
    frozen.close()
    vi.spyOn(BroadcastChannel.prototype, 'postMessage').mockImplementation(() => {})
    const claims: boolean[] = []
    const other = new EngineLock('engine', async (takeOver) => { claims.push(takeOver) })
    const next = other.run(async () => 'ran')
    await vi.advanceTimersByTimeAsync(SILENT_FOR_MS + 2_000)
    await expect(next).resolves.toBe('ran')
    expect(claims).toEqual([true])
    await expect(stuck).rejects.toThrow('stolen')
    other.close()
  })

  it('does not start a tab\'s next operation while one that lost the lock still runs', async () => {
    const tab = new EngineLock('engine', async () => {})
    let release!: () => void
    const order: string[] = []
    const first = tab.run(() => new Promise<void>(resolve => {
      release = () => { order.push('first:end'); resolve() }
    }))
    // Another tab takes the lock over from it.
    vi.spyOn(BroadcastChannel.prototype, 'postMessage').mockImplementation(() => {})
    const other = new EngineLock('engine', async () => {})
    const taken = other.run(async () => { order.push('other') })
    await vi.advanceTimersByTimeAsync(SILENT_FOR_MS + 2_000)
    await taken
    await expect(first).rejects.toThrow('stolen')
    const second = tab.run(async () => { order.push('second') })
    await vi.advanceTimersByTimeAsync(10)
    expect(order).toEqual(['other'])
    release()
    await second
    expect(order).toEqual(['other', 'first:end', 'second'])
    tab.close()
    other.close()
  })
})
