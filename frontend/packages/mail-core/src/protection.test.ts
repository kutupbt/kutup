import { beforeEach, describe, expect, it, vi } from 'vitest'

// Keys named "old…" have expired; the rest check. The lookup finds "found".
vi.mock('@kutup/crypto', () => ({
  fromBase64: (value: string) => new TextEncoder().encode(value),
  inspectExternalMailKey: (bytes: Uint8Array) => {
    const name = new TextDecoder().decode(bytes)
    return name.startsWith('old') ? Promise.reject(new Error('public key has expired')) : Promise.resolve({ publicKey: name, fingerprint: `fp-${name}`, createdAt: 1 })
  },
}))
const lookup = vi.fn<(address: string) => Promise<unknown>>()
const kutupKeys = vi.fn<(address: string) => Promise<unknown>>()
vi.mock('./keys', () => ({ outsideKey: (address: string) => lookup(address), addressKeys: (address: string) => kutupKeys(address) }))

const { protectionFor } = await import('./protection')

const key = (name: string) => ({ address: 'dave@example.org', publicKey: name, fingerprint: `fp-${name}` })

beforeEach(() => {
  lookup.mockReset()
  lookup.mockResolvedValue({ address: 'dave@example.org', source: 'wkd', publicKey: 'found', fingerprint: 'fp-found', keys: [] })
})

describe('protection with several trusted keys', () => {
  it('encrypts to the first trusted key that can encrypt, skipping expired ones', async () => {
    const protection = await protectionFor('dave@example.org', 'kutup.dev', { keys: [key('old1'), key('new'), key('other')], pgp: {} })
    expect(protection).toEqual({ kind: 'pinned', publicKey: 'new', fingerprint: 'fp-new' })
    expect(lookup).not.toHaveBeenCalled()
  })

  it('waits when every trusted key is unusable, rather than falling back to a found one', async () => {
    const protection = await protectionFor('dave@example.org', 'kutup.dev', { keys: [key('old1'), key('old2')], pgp: {} })
    expect(protection).toEqual({ kind: 'pinnedUnusable', fingerprint: 'fp-old1' })
  })

  it('uses a found key without trusted ones, unless the address says not to encrypt', async () => {
    expect(await protectionFor('dave@example.org', 'kutup.dev', undefined)).toMatchObject({ kind: 'found', fingerprint: 'fp-found' })
    expect(await protectionFor('dave@example.org', 'kutup.dev', { keys: [], pgp: { encrypt: false } })).toEqual({ kind: 'none' })
    expect(await protectionFor('dave@example.org', 'kutup.dev', { keys: [key('new')], pgp: { encrypt: false } })).toEqual({ kind: 'none' })
  })

  it('leaves Kutup addresses to their key lists', async () => {
    kutupKeys.mockResolvedValue({ encryptionDisabled: false })
    expect(await protectionFor('ayse@kutup.dev', 'kutup.dev', undefined)).toEqual({ kind: 'kutup' })
    kutupKeys.mockRejectedValue(new Error('no such address'))
    expect(await protectionFor('ayse@kutup.dev', 'kutup.dev', undefined)).toEqual({ kind: 'kutup' })
  })

  it('says when a Kutup address forwards outside, as its key list does', async () => {
    kutupKeys.mockResolvedValue({ encryptionDisabled: true })
    expect(await protectionFor('ayse@kutup.dev', 'kutup.dev', undefined)).toEqual({ kind: 'kutup', encryptionDisabled: true })
  })
})
