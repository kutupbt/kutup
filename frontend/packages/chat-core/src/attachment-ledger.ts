// Account-private, linked-device attachment accounting: the account-records
// store's `chatAttachments` scope (docs/plans/account-records.md), one record
// per entity at its newest revision, its id random. The server sees only
// opaque record ids, revisions and padded ciphertext; conversation names and
// attachment relationships are decoded solely in the browser. The account
// head covers the scope: every read is checked against the verified head, so
// a server can't roll an entity back, drop it or bring an old one back.

import type { AccountRoots } from '@kutup/crypto/accountRoots'
import type { MasterKeys } from '@kutup/crypto/masterKeys'
import {
  decodeChatAttachmentLedgerEntry,
  encodeChatAttachmentLedgerEntry,
  openChatAttachmentLedger,
  sealChatAttachmentLedger,
  type ChatAttachmentLedgerOwner,
} from '@kutup/crypto/chatMedia'
import { accountHead } from '@kutup/session/accountHead'
import { randomRecordId, type ScopeRecords } from '@kutup/session/accountRecords'
import type { ChatAttachmentLedgerEntryV1 } from './types'

const SCOPE = 'chatAttachments'

export interface CurrentLedgerEntity {
  entityId: string
  revision: number
  /** The sealed record as stored: an unchanged one is not opened again. */
  envelope: string
  entry: ChatAttachmentLedgerEntryV1
}

/** Whose ledger: the signed-in account (`session`). */
export interface LedgerAccount {
  userId: string
  masterKeys: MasterKeys
  roots: AccountRoots
  /** What the account's sealed records are bound to (`session.envelopeBinding`). */
  envelopeBinding: string
}

export class ChatAttachmentLedger {
  private current = new Map<string, CurrentLedgerEntity>()

  private constructor(private readonly account: LedgerAccount) {}

  static async open(account: LedgerAccount): Promise<ChatAttachmentLedger> {
    const ledger = new ChatAttachmentLedger(account)
    await ledger.sync()
    return ledger
  }

  /** Reads the scope as the verified account head vouches for it. */
  async sync(): Promise<void> {
    await this.adopt(await (await this.head()).records(SCOPE))
  }

  async create(entry: ChatAttachmentLedgerEntryV1): Promise<string> {
    const entityId = randomRecordId()
    await this.put(entityId, entry, true)
    return entityId
  }

  async update(entityId: string, entry: ChatAttachmentLedgerEntryV1): Promise<void> {
    if (!this.current.has(entityId)) throw new Error('unknown Chat attachment ledger entity')
    await this.put(entityId, entry, false)
  }

  entries(): ReadonlyArray<CurrentLedgerEntity> {
    return Array.from(this.current.values())
  }

  activeEntries(conversationReference?: string): ReadonlyArray<CurrentLedgerEntity> {
    return Array.from(this.current.values()).filter(({ entry }) =>
      entry.state === 'active' &&
      (conversationReference === undefined || entry.conversationReference === conversationReference))
  }

  async markCleared(entityId: string, updatedAtMs: number): Promise<void> {
    const current = this.current.get(entityId)
    if (!current) throw new Error('unknown Chat attachment ledger entity')
    if (current.entry.state === 'cleared') return
    await this.update(entityId, {
      ...current.entry,
      state: 'cleared',
      updatedAtMs,
      driveFileId: undefined,
    })
  }

  async markExpired(entityId: string, updatedAtMs: number): Promise<void> {
    const current = this.current.get(entityId)
    if (!current) throw new Error('unknown Chat attachment ledger entity')
    if (current.entry.state === 'expired') return
    await this.update(entityId, {
      ...current.entry,
      state: 'expired',
      updatedAtMs,
      driveFileId: undefined,
    })
  }

  totalsByConversation(): Map<string, number> {
    const totals = new Map<string, number>()
    for (const { entry } of this.current.values()) {
      if (entry.state !== 'active') continue
      totals.set(
        entry.conversationReference,
        (totals.get(entry.conversationReference) ?? 0) + entry.ciphertextBytes,
      )
    }
    return totals
  }

  hasAttachment(messageId: string, attachmentId: string): boolean {
    return Array.from(this.current.values()).some(({ entry }) =>
      entry.messageId === messageId && entry.attachmentId === attachmentId)
  }

  dispose(): void {
    this.current.clear()
  }

  private head() {
    return accountHead(this.account)
  }

  private owner(): ChatAttachmentLedgerOwner {
    return { masterKeys: this.account.masterKeys, binding: this.account.envelopeBinding }
  }

  /**
   * Takes a verified copy of the scope: each record opened as exactly its id
   * and the revision the index lists (one already open at that revision is
   * kept as it is).
   */
  private async adopt(copy: ScopeRecords): Promise<void> {
    const next = new Map<string, CurrentLedgerEntity>()
    for (const [entityId, stored] of copy.records) {
      const known = this.current.get(entityId)
      if (known && known.revision === stored.revision && known.envelope === stored.envelope) {
        next.set(entityId, known)
        continue
      }
      const { plaintext, revision } = await openChatAttachmentLedger(stored.envelope, this.owner(), entityId)
      if (revision !== stored.revision) {
        throw new Error('Chat attachment ledger record differs from its listed revision')
      }
      const entry = await decodeChatAttachmentLedgerEntry<ChatAttachmentLedgerEntryV1>(plaintext)
      if (entry.version !== 1) throw new Error('unsupported Chat attachment ledger entry')
      next.set(entityId, { entityId, revision, envelope: stored.envelope, entry })
    }
    this.current = next
  }

  /**
   * Stores `entry` as the entity's next revision with the next account head;
   * when another device wrote first, read again and stored on top.
   */
  private async put(entityId: string, entry: ChatAttachmentLedgerEntryV1, isNew: boolean): Promise<void> {
    const plaintext = await encodeChatAttachmentLedgerEntry(entry)
    const stored = await (await this.head()).recordsWrite(SCOPE, async (copy) => {
      await this.adopt(copy)
      const previous = copy.records.get(entityId)
      if (!isNew && !previous) throw new Error('unknown Chat attachment ledger entity')
      const revision = (previous?.revision ?? 0) + 1
      const envelope = await sealChatAttachmentLedger(plaintext, this.owner(), entityId, revision)
      return { puts: [{ id: entityId, revision, envelope }], deletes: [], done: { revision, envelope } }
    })
    if (!stored) throw new Error('Chat attachment ledger write was not stored')
    this.current.set(entityId, { entityId, revision: stored.revision, envelope: stored.envelope, entry })
  }
}
