import { describe, expect, it } from 'vitest'
import { memoryRevisionStore, OlderThanSeenError, plainGuardKeysForTesting, RevisionGuard } from './revisionGuard'

const T = 1_791_633_600_000

function device(clock: { now: number }, store = memoryRevisionStore(), account = 'user-1') {
  return new RevisionGuard(store, () => Promise.resolve(plainGuardKeysForTesting(account)), () => clock.now)
}

describe('RevisionGuard', () => {
  it('refuses an older revision than seen, and accepts the same or newer', async () => {
    const guard = device({ now: T })
    await guard.accept('contact', 'a', T + 5)
    await expect(guard.accept('contact', 'a', T + 4)).rejects.toBeInstanceOf(OlderThanSeenError)
    await guard.accept('contact', 'a', T + 5)
    await guard.accept('contact', 'a', T + 9)
    expect(await guard.seen('contact', 'a')).toBe(T + 9)
    // Another value, scope or account has its own history.
    await guard.accept('contact', 'b', 1)
    await guard.accept('mail-name', 'a', 1)
    expect(await device({ now: T }, memoryRevisionStore(), 'user-2').seen('contact', 'a')).toBe(0)
  })

  it('makes a value deleted and made again newer than anything seen', async () => {
    const clock = { now: T }
    const guard = device(clock)
    await guard.accept('contact', 'uid-1', await guard.next('contact', 'uid-1'))
    // Deleted, then imported again with the same UID a minute later.
    clock.now = T + 60_000
    const again = await guard.next('contact', 'uid-1')
    expect(again).toBe(T + 60_000)
    await guard.accept('contact', 'uid-1', again)
  })

  it('keeps writes rising when the clock goes back', async () => {
    const clock = { now: T }
    const guard = device(clock)
    await guard.accept('mail-name', 'f', await guard.next('mail-name', 'f'))
    clock.now = T - 3_600_000
    const next = await guard.next('mail-name', 'f')
    expect(next).toBe(T + 1)
    // And above the revision the write started from.
    expect(await guard.next('mail-name', 'f', T + 50)).toBe(T + 51)
  })

  it('continues above a revision a device with a fast clock wrote', async () => {
    const ahead = device({ now: T + 86_400_000 })
    const written = await ahead.next('identity-pins', 'list')
    const reader = device({ now: T })
    await reader.accept('identity-pins', 'list', written)
    expect(await reader.next('identity-pins', 'list', written)).toBe(written + 1)
    // A device that never read it writes with its own clock; the server's
    // compare-and-swap refuses that write (it started from an older base),
    // and the device reads again before it writes.
    const fresh = device({ now: T })
    expect(await fresh.next('identity-pins', 'list')).toBe(T)
  })

  it('trusts the first revision again after its store is reset', async () => {
    const guard = device({ now: T })
    await guard.accept('contact', 'a', T + 5)
    const reset = device({ now: T })
    await reset.accept('contact', 'a', T + 1)
    await expect(reset.accept('contact', 'a', T)).rejects.toBeInstanceOf(OlderThanSeenError)
  })

  it('refuses revisions that are not positive safe integers', async () => {
    const guard = device({ now: T })
    for (const bad of [0, -1, 1.5, Number.MAX_SAFE_INTEGER + 2]) {
      await expect(guard.accept('contact', 'a', bad)).rejects.toThrow('invalid revision')
    }
  })

  it('takes an entry that was altered or moved on disk as none', async () => {
    const store = memoryRevisionStore()
    const guard = device({ now: T }, store)
    await guard.accept('contact', 'a', T + 5)
    const keys = plainGuardKeysForTesting('user-1')
    // Moved from another value's entry: does not open for this one.
    await store.put(keys.entryId('contact', 'a'), `${keys.entryId('contact', 'b')}=${T + 9}`)
    expect(await guard.seen('contact', 'a')).toBe(0)
  })

  it('keeps the higher of two revisions accepted at once', async () => {
    const guard = device({ now: T })
    await Promise.all([guard.accept('contact', 'a', T + 9), guard.accept('contact', 'a', T + 5).catch(() => undefined)])
    expect(await guard.seen('contact', 'a')).toBe(T + 9)
  })
})
