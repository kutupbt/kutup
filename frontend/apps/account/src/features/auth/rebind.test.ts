import { beforeEach, describe, expect, it, vi } from 'vitest'

// The re-seal (docs/plans/account-identity.md): a retry after a failed
// attempt seals with the password's key again, never with a wiped one.

const post = vi.hoisted(() => vi.fn())
const get = vi.hoisted(() => vi.fn())
const hex = (bytes: Uint8Array) => Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('')
vi.mock('@kutup/session/client', () => ({ default: { post, get } }))
vi.mock('@kutup/session/persist', () => ({ persistKeys: vi.fn() }))
vi.mock('@kutup/session/profile', () => ({ activateSession: vi.fn() }))
vi.mock('@kutup/session/apps', () => ({ loadServerSettings: vi.fn() }))
vi.mock('@kutup/crypto/identityPins', () => ({ signDriveKeyBinding: vi.fn() }))
vi.mock('@kutup/crypto/accountProtectionWorker', () => ({}))
vi.mock('@kutup/session/passRebind', () => ({ rebindPassVaultSecrets: vi.fn(() => Promise.resolve([])) }))
vi.mock('@kutup/crypto/mnemonic', () => ({ decodeMnemonic: () => new Uint8Array(32).fill(7) }))
vi.mock('@kutup/session/store', () => ({
  getSession: () => ({ masterKey: new Uint8Array(32).fill(1), privateKey: new Uint8Array(32).fill(2) }),
  updateSession: vi.fn(),
}))
// Sealing names its key, so the test sees which key sealed what.
vi.mock('@kutup/crypto', () => ({
  ACCOUNT_ENVELOPE_PURPOSE: { passwordMasterKey: 1, recoveryMasterKey: 2, driveHpkePrivateKey: 3, chatBackupRoot: 4, mailAddressPrivateKey: 5 },
  toBase64: () => 'b64',
  deriveRecoveryAuthProof: () => Promise.resolve('proof'),
  sealAccountEnvelope: (plain: Uint8Array, key: Uint8Array) => Promise.resolve(`${hex(key)}|${hex(plain)}`),
  openAccountEnvelope: (envelope: string, key: Uint8Array) => {
    const [sealedWith, plain] = envelope.split('|')
    if (sealedWith !== hex(key)) return Promise.reject(new Error('auth failed'))
    return Promise.resolve(Uint8Array.from((plain ?? '').match(/../g) ?? [], (h) => parseInt(h, 16)))
  },
  resealAccountEnvelope: vi.fn(),
}))

import { rebindAccount, type PendingRebind } from './flows'

describe('rebindAccount', () => {
  beforeEach(() => {
    post.mockReset()
    get.mockReset()
    get.mockImplementation((path: string) => Promise.resolve({ data: path === '/mail/addresses' ? [] : {} }))
  })

  it('seals with the password key again on a retry, not with a wiped one', async () => {
    const kek = new Uint8Array(32).fill(9)
    const pending: PendingRebind = { name: 'ayse', oldBinding: 'ayse@example.org', keyEncryptionKey: kek, loginKey: 'login' }
    post.mockRejectedValueOnce(new Error('keys changed meanwhile')).mockResolvedValue({ data: {} })
    await expect(rebindAccount(pending, { kind: 'new', mnemonic: 'words' })).rejects.toThrow()
    await rebindAccount(pending, { kind: 'new', mnemonic: 'words' })
    const body = post.mock.calls[1][1] as { masterKeyEnvelope: string }
    expect(body.masterKeyEnvelope.split('|')[0]).toBe(hex(new Uint8Array(32).fill(9)))
  })

  it('refuses to seal under a wiped key', async () => {
    const pending: PendingRebind = { name: 'ayse', oldBinding: 'ayse@example.org', keyEncryptionKey: new Uint8Array(32), loginKey: 'login' }
    await expect(rebindAccount(pending, { kind: 'new', mnemonic: 'words' })).rejects.toThrow(/wiped key/)
    expect(post).not.toHaveBeenCalled()
  })
})
