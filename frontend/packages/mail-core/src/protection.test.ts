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
const keyErrors = vi.hoisted(() => {
  class NoKutupAddress extends Error {}
  class GroupAddress extends Error {}
  class AddressDisabled extends Error {}
  return { NoKutupAddress, GroupAddress, AddressDisabled }
})
vi.mock('./keys', () => ({ outsideKey: (address: string) => lookup(address), addressKeys: (address: string) => kutupKeys(address), ...keyErrors }))

const { isKutupElsewhere, protectionFor } = await import('./protection')

const key = (name: string) => ({ address: 'dave@example.org', publicKey: name, fingerprint: `fp-${name}` })

beforeEach(() => {
  // Outside addresses: no Kutup key on this server.
  kutupKeys.mockReset()
  kutupKeys.mockRejectedValue(new keyErrors.NoKutupAddress())
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

  it('takes an address on a custom domain this server holds as a Kutup address, and never sends to a disabled one', async () => {
    kutupKeys.mockResolvedValue({ encryptionDisabled: false })
    expect(await protectionFor('info@customer.test', 'kutup.dev', undefined)).toEqual({ kind: 'kutup' })
    expect(lookup).not.toHaveBeenCalled()
    kutupKeys.mockRejectedValue(new keyErrors.AddressDisabled())
    expect(await protectionFor('info@customer.test', 'kutup.dev', undefined)).toEqual({ kind: 'disabled' })
    expect(await protectionFor('ayse@kutup.dev', 'kutup.dev', undefined)).toEqual({ kind: 'disabled' })
    expect(lookup).not.toHaveBeenCalled()
  })

  it('never takes this server’s word for an address on another domain over keys Contacts trust', async () => {
    kutupKeys.mockResolvedValue({ encryptionDisabled: false })
    expect(await protectionFor('bob@gmail.test', 'kutup.dev', { keys: [key('new')], pgp: {} })).toEqual({ kind: 'pinnedConflict', fingerprint: 'fp-new' })
    // Its own domain is the server's to say.
    expect(await protectionFor('ayse@kutup.dev', 'kutup.dev', { keys: [key('new')], pgp: {} })).toEqual({ kind: 'kutup' })
    expect(lookup).not.toHaveBeenCalled()
  })

  it('knows a Kutup user on a custom domain from an outside address, for the composer', async () => {
    kutupKeys.mockResolvedValue({ encryptionDisabled: false })
    expect(await isKutupElsewhere('Info@Customer.test')).toBe(true)
    // The server's bare answers aren't verified: outside here.
    kutupKeys.mockRejectedValue(new keyErrors.AddressDisabled())
    expect(await isKutupElsewhere('info@customer.test')).toBe(false)
    kutupKeys.mockRejectedValue(new keyErrors.GroupAddress())
    expect(await isKutupElsewhere('team@customer.test')).toBe(false)
    kutupKeys.mockRejectedValue(new keyErrors.NoKutupAddress())
    expect(await isKutupElsewhere('dave@example.org')).toBe(false)
    kutupKeys.mockRejectedValue(new Error('network'))
    expect(await isKutupElsewhere('dave@example.org')).toBe(false)
  })

  it('says when a Kutup address forwards outside, as its key list does', async () => {
    kutupKeys.mockResolvedValue({ encryptionDisabled: true })
    expect(await protectionFor('ayse@kutup.dev', 'kutup.dev', undefined)).toEqual({ kind: 'kutup', encryptionDisabled: true })
  })
})
