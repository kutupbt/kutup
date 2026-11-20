import { beforeEach, describe, expect, it, vi } from 'vitest'

// The ledger as the account-records `chatAttachments` scope: read through the
// verified account head, each record opened as its id and listed revision,
// and written as the next revision with the next head.

interface Stored { revision: number; envelope: string }
const scope = { records: new Map<string, Stored>() }
const writes: { puts: unknown[]; deletes: string[] }[] = []
const head = {
  records: vi.fn(() => Promise.resolve(scope)),
  recordsWrite: vi.fn(async (_name: string, edit: (copy: typeof scope, attempt: number) => Promise<{ puts: Stored[]; deletes: string[]; done: unknown } | null>) => {
    const change = await edit(scope, 1)
    if (!change) return undefined
    writes.push({ puts: change.puts, deletes: change.deletes })
    return change.done
  }),
}
vi.mock('@kutup/session/accountHead', () => ({ accountHead: vi.fn(() => Promise.resolve(head)) }))
vi.mock('@kutup/session/accountRecords', () => ({ randomRecordId: () => 'NEW' }))

const sealed = new Map<string, { entry: Record<string, unknown>; revision: number }>()
const crypto = {
  openChatAttachmentLedger: vi.fn((envelope: string) => {
    const opened = sealed.get(envelope)!
    return Promise.resolve({ plaintext: new TextEncoder().encode(envelope), revision: opened.revision })
  }),
  sealChatAttachmentLedger: vi.fn((_plain: Uint8Array, _owner: unknown, id: string, revision: number) =>
    Promise.resolve(`sealed:${id}:${revision}`)),
  encodeChatAttachmentLedgerEntry: vi.fn(() => Promise.resolve(new Uint8Array([1]))),
  decodeChatAttachmentLedgerEntry: vi.fn((plaintext: Uint8Array) =>
    Promise.resolve(sealed.get(new TextDecoder().decode(plaintext))!.entry)),
}
vi.mock('@kutup/crypto/chatMedia', () => crypto)

const { ChatAttachmentLedger } = await import('./attachment-ledger')

const account = { accountId: 'u', masterKeys: 'keys', roots: {}, envelopeBinding: 'b' } as never
const entry = (attachmentId: string, state = 'active') => ({
  version: 1,
  conversationKind: 'direct',
  conversationReference: 'aci:peer@a.test',
  messageId: 'm',
  attachmentId,
  storageReferenceId: 's',
  ciphertextBytes: 10,
  state,
  mediaClass: 'photo',
  displayName: 'cat.jpg',
  updatedAtMs: 1,
})

describe('the attachment ledger on account records', () => {
  beforeEach(() => {
    scope.records.clear()
    sealed.clear()
    writes.length = 0
    vi.clearAllMocks()
  })

  it('opens each record as its id at the revision the verified index lists', async () => {
    scope.records.set('E1', { revision: 3, envelope: 'e1' })
    sealed.set('e1', { entry: entry('a1'), revision: 3 })
    const ledger = await ChatAttachmentLedger.open(account)
    expect(ledger.entries()).toMatchObject([{ entityId: 'E1', revision: 3, entry: { attachmentId: 'a1' } }])
    expect(crypto.openChatAttachmentLedger).toHaveBeenCalledWith('e1', { masterKeys: 'keys', binding: 'b' }, 'E1')
    expect(ledger.totalsByConversation().get('aci:peer@a.test')).toBe(10)
    // Unchanged records are not opened again.
    await ledger.sync()
    expect(crypto.openChatAttachmentLedger).toHaveBeenCalledOnce()
  })

  it('refuses a record sealed at another revision than the one listed', async () => {
    scope.records.set('E1', { revision: 4, envelope: 'e1' })
    sealed.set('e1', { entry: entry('a1'), revision: 3 })
    await expect(ChatAttachmentLedger.open(account)).rejects.toThrow(/differs/)
  })

  it('creates an entity under a new random id and moves it to its next revision', async () => {
    const ledger = await ChatAttachmentLedger.open(account)
    const id = await ledger.create(entry('a1') as never)
    expect(id).toBe('NEW')
    expect(writes).toEqual([{ puts: [{ id: 'NEW', revision: 1, envelope: 'sealed:NEW:1' }], deletes: [] }])
    expect(ledger.hasAttachment('m', 'a1')).toBe(true)

    scope.records.set('NEW', { revision: 1, envelope: 'sealed:NEW:1' })
    sealed.set('sealed:NEW:1', { entry: entry('a1'), revision: 1 })
    await ledger.markExpired('NEW', 2)
    expect(writes[1]).toEqual({ puts: [{ id: 'NEW', revision: 2, envelope: 'sealed:NEW:2' }], deletes: [] })
    expect(ledger.activeEntries()).toEqual([])
  })

  it('refuses to update an entity the scope does not hold', async () => {
    const ledger = await ChatAttachmentLedger.open(account)
    await expect(ledger.update('E9', entry('a9') as never)).rejects.toThrow(/unknown/)
    expect(writes).toEqual([])
  })
})
