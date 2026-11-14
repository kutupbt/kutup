import { describe, expect, it } from 'vitest'
import { LocalChainPins, plainChainPinKeysForTesting, type ChainPinKeys } from './localChainPins'
import { memoryRevisionStore } from './revisionGuard'

const A = 'aa'.repeat(32)
const B = 'bb'.repeat(32)

function device(store = memoryRevisionStore(), account = 'binding-1', keys: ChainPinKeys = plainChainPinKeysForTesting(account)) {
  return new LocalChainPins(store, () => Promise.resolve(keys))
}

describe('LocalChainPins', () => {
  it('keeps the newest state seen of each chain, and never moves back', async () => {
    const pins = device()
    expect(await pins.loadPin('photos-library', 'inc')).toBeNull()
    expect(await pins.storePin('photos-library', 'inc', 2n, A)).toBe(true)
    expect(await pins.loadPin('photos-library', 'inc')).toEqual({ revision: 2n, digest: A })
    // Older, or the same revision again (with another digest too): not written.
    expect(await pins.storePin('photos-library', 'inc', 1, B)).toBe(false)
    expect(await pins.storePin('photos-library', 'inc', 2n, B)).toBe(false)
    expect(await pins.loadPin('photos-library', 'inc')).toEqual({ revision: 2n, digest: A })
    expect(await pins.storePin('photos-library', 'inc', 3n, B)).toBe(true)
    expect(await pins.loadPin('photos-library', 'inc')).toEqual({ revision: 3n, digest: B })
    // Another chain, scope or account has its own.
    expect(await pins.loadPin('photos-library', 'other')).toBeNull()
    expect(await pins.loadPin('chat-attachment-ledger', 'inc')).toBeNull()
  })

  it('keeps revisions past a safe integer, and a cursor of 0', async () => {
    const pins = device()
    await pins.storePin('chat-attachment-ledger', 'inc', 0n, '00'.repeat(32))
    expect(await pins.loadPin('chat-attachment-ledger', 'inc')).toEqual({ revision: 0n, digest: '00'.repeat(32) })
    await pins.storePin('chat-attachment-ledger', 'inc', 0xffff_ffff_ffff_fffen, A)
    expect((await pins.loadPin('chat-attachment-ledger', 'inc'))?.revision).toBe(0xffff_ffff_ffff_fffen)
  })

  it('treats a pin that does not open as unseen, and pins again over it', async () => {
    const store = memoryRevisionStore()
    const pins = device(store)
    await pins.storePin('photos-library', 'inc', 5n, A)
    // Another account's keys over the same store: its names differ, and a pin
    // moved under its name does not open.
    const other = device(store, 'binding-2')
    expect(await other.loadPin('photos-library', 'inc')).toBeNull()
    await store.put('binding-2:photos-library:inc', (await store.get('binding-1:photos-library:inc'))!)
    expect(await other.loadPin('photos-library', 'inc')).toBeNull()
    // Altered: unseen, and a lower revision is then pinned over it.
    await store.put('binding-1:photos-library:inc', 'garbage')
    expect(await pins.loadPin('photos-library', 'inc')).toBeNull()
    expect(await pins.storePin('photos-library', 'inc', 1n, B)).toBe(true)
    expect(await pins.loadPin('photos-library', 'inc')).toEqual({ revision: 1n, digest: B })
  })

  it('refuses a malformed revision or digest', async () => {
    const pins = device()
    await expect(pins.storePin('photos-library', 'inc', -1n, A)).rejects.toThrow(/revision/)
    await expect(pins.storePin('photos-library', 'inc', 1n << 64n, A)).rejects.toThrow(/revision/)
    await expect(pins.storePin('photos-library', 'inc', 1n, 'AA'.repeat(32))).rejects.toThrow(/digest/)
    await expect(pins.storePin('photos-library', 'inc', 1n, 'aa')).rejects.toThrow(/digest/)
  })

  it('leaves the higher of two stores at once pinned', async () => {
    const pins = device()
    await Promise.all([
      pins.storePin('photos-library', 'inc', 9n, B),
      pins.storePin('photos-library', 'inc', 4n, A),
    ])
    expect(await pins.loadPin('photos-library', 'inc')).toEqual({ revision: 9n, digest: B })
  })
})
