import { beforeEach, describe, expect, it, vi } from 'vitest'

const get = vi.fn()
vi.mock('@kutup/session/client', () => ({ default: { get: (...args: unknown[]) => get(...args), put: vi.fn() } }))
vi.mock('@kutup/crypto/identity', () => ({
  deriveAccountIdentityKeys: () => Promise.resolve({ incarnationId: 'aa'.repeat(32) }),
}))
vi.mock('@kutup/crypto/chatMedia', () => ({}))
vi.mock('@kutup/crypto/hash', () => ({ hash: vi.fn() }))

const { ChatAttachmentLedger } = await import('./attachment-ledger')
const { localChainPins, resetLocalChainPinsForTesting } = await import('@kutup/crypto/localChainPins')

const masterKey = new Uint8Array(32).fill(7)
const BINDING = 'binding-1'
const INCARNATION = 'aa'.repeat(32)
const OLD_KEY = 'kutup.chat.attachment-ledger.pin.v1.' + INCARNATION
const empty = () => ({ data: { entities: [], nextCursor: '0', more: false } })
const pins = () => localChainPins({ masterKey, envelopeBinding: BINDING })

describe('the attachment ledger rollback pin', () => {
  beforeEach(() => {
    localStorage.clear()
    resetLocalChainPinsForTesting()
    get.mockReset()
  })

  // First: the old pins go once per page, on the first pin stored.
  it('is sealed, not in localStorage, and the old plain pins are dropped unread', async () => {
    // An old pin far ahead of the server: not migrated, so not enforced.
    localStorage.setItem(OLD_KEY, JSON.stringify({ version: 1, cursor: '9', chainDigest: 'ab'.repeat(32) }))
    localStorage.setItem('kutup.other', 'kept')
    get.mockResolvedValueOnce(empty())
    await ChatAttachmentLedger.open(masterKey, BINDING)
    expect(localStorage.getItem(OLD_KEY)).toBeNull()
    expect(localStorage.getItem('kutup.other')).toBe('kept')
    expect(await pins().loadPin('chat-attachment-ledger', INCARNATION)).toEqual({ revision: 0n, digest: '00'.repeat(32) })
  })

  it('refuses a ledger that stops before the pinned cursor', async () => {
    await pins().storePin('chat-attachment-ledger', INCARNATION, 5n, 'ab'.repeat(32))
    get.mockResolvedValueOnce(empty())
    await expect(ChatAttachmentLedger.open(masterKey, BINDING)).rejects.toThrow(/stopped before the local rollback pin/)
    // The pin did not move back.
    expect((await pins().loadPin('chat-attachment-ledger', INCARNATION))?.revision).toBe(5n)
  })

  it('takes another account\'s pin as unseen', async () => {
    await localChainPins({ masterKey, envelopeBinding: 'binding-2' })
      .storePin('chat-attachment-ledger', INCARNATION, 5n, 'ab'.repeat(32))
    get.mockResolvedValueOnce(empty())
    await ChatAttachmentLedger.open(masterKey, BINDING)
    expect((await pins().loadPin('chat-attachment-ledger', INCARNATION))?.revision).toBe(0n)
  })
})
