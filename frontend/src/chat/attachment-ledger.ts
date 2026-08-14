// Account-private, linked-device attachment accounting. The server sees only
// opaque entity IDs, revision chains and ciphertext sizes; conversation names
// and attachment relationships are decoded solely in the browser.

import api from '@/api/client'
import { toBase64 } from '@/crypto/base64'
import { deriveAccountIdentityKeys } from '@/crypto/identity'
import {
  chatAttachmentLedgerEnvelopeDigest,
  decodeChatAttachmentLedgerEntry,
  deriveChatAttachmentLedgerKey,
  encodeChatAttachmentLedgerEntry,
  inspectChatAttachmentLedgerEnvelope,
  openChatAttachmentLedger,
  sealChatAttachmentLedger,
} from '@/crypto/chatMedia'
import type { ChatAttachmentLedgerEntryV1 } from './types'

interface LedgerWireEntity {
  entityId: string
  revision: string
  envelopeDigest: string
  envelope: string
  cursor: string
}

interface LedgerDiffPage {
  entities: LedgerWireEntity[]
  nextCursor: string
  more: boolean
}

interface LedgerPutResponse {
  entityId: string
  revision: string
  envelopeDigest: string
  cursor: string
  idempotent: boolean
}

interface LedgerLocalPinV1 {
  version: 1
  cursor: string
  chainDigest: string
}

export interface CurrentLedgerEntity {
  entityId: string
  revision: bigint
  envelopeDigest: string
  cursor: bigint
  entry: ChatAttachmentLedgerEntryV1
}

const ZERO_DIGEST = '0'.repeat(64)
const MAX_LEDGER_PAGES = 4096
const LOCAL_PIN_PREFIX = 'kutup.chat.attachment-ledger.pin.v1.'
const LOCAL_PIN_DOMAIN = new TextEncoder().encode('kutup/chat-attachment-ledger/local-pin/v1\0')

export class ChatAttachmentLedger {
  private readonly current = new Map<string, CurrentLedgerEntity>()
  private cursor = 0n
  private chainDigest: Uint8Array = new Uint8Array(32)
  private pinVerified: boolean

  private constructor(
    private readonly ledgerKey: Uint8Array,
    private readonly accountIncarnationId: string,
    private readonly localPin: LedgerLocalPinV1 | null,
  ) {
    this.pinVerified = localPin === null || localPin.cursor === '0'
  }

  static async open(masterKey: Uint8Array): Promise<ChatAttachmentLedger> {
    const [ledgerKey, identity] = await Promise.all([
      deriveChatAttachmentLedgerKey(masterKey),
      deriveAccountIdentityKeys(toBase64(masterKey)),
    ])
    const ledger = new ChatAttachmentLedger(
      ledgerKey,
      identity.incarnationId,
      loadLocalPin(identity.incarnationId),
    )
    await ledger.sync()
    return ledger
  }

  /** Replay every unseen revision in cursor order and verify no chain gap. */
  async sync(): Promise<void> {
    for (let pageNumber = 0; pageNumber < MAX_LEDGER_PAGES; pageNumber++) {
      const response = await api.get<LedgerDiffPage>('/chat/media/ledger', {
        params: { after: this.cursor.toString(), limit: 256 },
      })
      const page = response.data
      let pageCursor = this.cursor
      for (const wire of page.entities) {
        const cursor = parseCanonicalU64(wire.cursor, 'ledger cursor')
        const revision = parseCanonicalU64(wire.revision, 'ledger revision')
        if (cursor <= pageCursor) throw new Error('Chat attachment ledger cursor regressed')
        const header = await inspectChatAttachmentLedgerEnvelope(wire.envelope)
        const digest = await chatAttachmentLedgerEnvelopeDigest(wire.envelope)
        if (header.suite !== 1 || header.accountIncarnationId !== this.accountIncarnationId ||
            header.entityId !== wire.entityId ||
            parseCanonicalU64(header.revision, 'envelope ledger revision') !== revision ||
            digest !== wire.envelopeDigest) {
          throw new Error('Chat attachment ledger response differs from its envelope')
        }
        const previous = this.current.get(wire.entityId)
        if (revision === 1n) {
          if (previous || header.previousEnvelopeDigest !== ZERO_DIGEST) {
            throw new Error('Chat attachment ledger replayed an invalid first revision')
          }
        } else if (!previous || revision !== previous.revision + 1n ||
                   header.previousEnvelopeDigest !== previous.envelopeDigest) {
          throw new Error('Chat attachment ledger has a missing or reordered revision')
        }
        const plaintext = await openChatAttachmentLedger(
          wire.envelope,
          this.ledgerKey,
          {
            accountIncarnationId: this.accountIncarnationId,
            entityId: wire.entityId,
            revision,
            ...(revision > 1n
              ? { previousEnvelopeDigest: header.previousEnvelopeDigest }
              : {}),
          },
        )
        const entry = await decodeChatAttachmentLedgerEntry<ChatAttachmentLedgerEntryV1>(plaintext)
        if (entry.version !== 1) throw new Error('unsupported Chat attachment ledger entry')
        this.chainDigest = await advanceLocalPin(
          this.chainDigest,
          cursor,
          wire.entityId,
          revision,
          digest,
        )
        this.current.set(wire.entityId, {
          entityId: wire.entityId,
          revision,
          envelopeDigest: digest,
          cursor,
          entry,
        })
        if (!this.pinVerified && this.localPin) {
          const pinnedCursor = parseCanonicalU64(this.localPin.cursor, 'local ledger pin cursor')
          if (cursor > pinnedCursor) {
            throw new Error('Chat attachment ledger omitted the locally pinned cursor')
          }
          if (cursor === pinnedCursor) {
            if (bytesToHex(this.chainDigest) !== this.localPin.chainDigest) {
              throw new Error('Chat attachment ledger conflicts with the local rollback pin')
            }
            this.pinVerified = true
          }
        }
        pageCursor = cursor
      }
      const advertisedCursor = parseCanonicalU64(page.nextCursor, 'ledger next cursor')
      if (advertisedCursor !== pageCursor) {
        throw new Error('Chat attachment ledger page cursor is inconsistent')
      }
      this.cursor = pageCursor
      if (!page.more) {
        if (!this.pinVerified) {
          throw new Error('Chat attachment ledger stopped before the local rollback pin')
        }
        storeLocalPin(this.accountIncarnationId, this.cursor, this.chainDigest)
        return
      }
      if (page.entities.length !== 256) {
        throw new Error('Chat attachment ledger continuation is not a full page')
      }
    }
    throw new Error('Chat attachment ledger exceeded its bounded page count')
  }

  async create(entry: ChatAttachmentLedgerEntryV1): Promise<string> {
    const entityId = crypto.randomUUID()
    await this.put(entityId, entry)
    return entityId
  }

  async update(entityId: string, entry: ChatAttachmentLedgerEntryV1): Promise<void> {
    if (!this.current.has(entityId)) throw new Error('unknown Chat attachment ledger entity')
    await this.put(entityId, entry)
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
    this.ledgerKey.fill(0)
    this.chainDigest.fill(0)
    this.current.clear()
    this.cursor = 0n
  }

  private async put(entityId: string, entry: ChatAttachmentLedgerEntryV1): Promise<void> {
    const previous = this.current.get(entityId)
    const revision = (previous?.revision ?? 0n) + 1n
    const plaintext = await encodeChatAttachmentLedgerEntry(entry)
    const envelope = await sealChatAttachmentLedger(plaintext, this.ledgerKey, {
      accountIncarnationId: this.accountIncarnationId,
      entityId,
      revision,
      ...(previous ? { previousEnvelopeDigest: previous.envelopeDigest } : {}),
    })
    const digest = await chatAttachmentLedgerEnvelopeDigest(envelope)
    const operationId = await ledgerOperationId(entityId, revision, digest)
    const response = await api.put<LedgerPutResponse>(
      `/chat/media/ledger/${encodeURIComponent(entityId)}`,
      { operationId, envelope },
    )
    const result = response.data
    const cursor = parseCanonicalU64(result.cursor, 'ledger cursor')
    if (result.entityId !== entityId ||
        parseCanonicalU64(result.revision, 'ledger revision') !== revision ||
        result.envelopeDigest !== digest || cursor <= this.cursor) {
      throw new Error('Chat attachment ledger acknowledgement is inconsistent')
    }
    // Cursor values are account-global. A linked device may have committed
    // one or more revisions between our last diff and this acknowledgement.
    // Replay through the acknowledged cursor instead of jumping over them.
    await this.sync()
    const stored = this.current.get(entityId)
    if (!stored || stored.revision !== revision || stored.envelopeDigest !== digest ||
        stored.cursor !== cursor || stored.entry.attachmentId !== entry.attachmentId) {
      throw new Error('Chat attachment ledger write was not recovered from its ordered diff')
    }
  }
}

function localPinKey(accountIncarnationId: string): string {
  return `${LOCAL_PIN_PREFIX}${accountIncarnationId}`
}

function loadLocalPin(accountIncarnationId: string): LedgerLocalPinV1 | null {
  let encoded: string | null
  try {
    encoded = globalThis.localStorage?.getItem(localPinKey(accountIncarnationId)) ?? null
  } catch {
    return null
  }
  if (encoded === null) return null
  let value: unknown
  try {
    value = JSON.parse(encoded)
  } catch {
    throw new Error('local Chat attachment ledger pin is malformed')
  }
  if (typeof value !== 'object' || value === null) {
    throw new Error('local Chat attachment ledger pin is malformed')
  }
  const pin = value as Partial<LedgerLocalPinV1>
  if (pin.version !== 1 || typeof pin.cursor !== 'string' ||
      typeof pin.chainDigest !== 'string' || !/^[0-9a-f]{64}$/.test(pin.chainDigest)) {
    throw new Error('local Chat attachment ledger pin is malformed')
  }
  parseCanonicalU64(pin.cursor, 'local ledger pin cursor')
  return pin as LedgerLocalPinV1
}

function storeLocalPin(
  accountIncarnationId: string,
  cursor: bigint,
  chainDigest: Uint8Array,
): void {
  const pin: LedgerLocalPinV1 = {
    version: 1,
    cursor: cursor.toString(),
    chainDigest: bytesToHex(chainDigest),
  }
  try {
    globalThis.localStorage?.setItem(localPinKey(accountIncarnationId), JSON.stringify(pin))
  } catch {
    // Browsers may disable persistent storage. The authenticated remote chain
    // still verifies; only cross-restart rollback pinning is unavailable.
  }
}

async function advanceLocalPin(
  previous: Uint8Array,
  cursor: bigint,
  entityId: string,
  revision: bigint,
  envelopeDigest: string,
): Promise<Uint8Array> {
  const input = new Uint8Array(LOCAL_PIN_DOMAIN.length + 32 + 8 + 16 + 8 + 32)
  let offset = 0
  input.set(LOCAL_PIN_DOMAIN, offset)
  offset += LOCAL_PIN_DOMAIN.length
  input.set(previous, offset)
  offset += 32
  new DataView(input.buffer).setBigUint64(offset, cursor, false)
  offset += 8
  input.set(uuidBytes(entityId), offset)
  offset += 16
  new DataView(input.buffer).setBigUint64(offset, revision, false)
  offset += 8
  input.set(hexBytes(envelopeDigest), offset)
  return new Uint8Array(await crypto.subtle.digest('SHA-256', input))
}

function uuidBytes(value: string): Uint8Array {
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(value)) {
    throw new Error('ledger entity id is not a canonical UUID')
  }
  return hexBytes(value.replaceAll('-', ''))
}

function hexBytes(value: string): Uint8Array {
  if (!/^(?:[0-9a-f]{2})+$/.test(value)) throw new Error('ledger digest is not canonical hex')
  return Uint8Array.from(value.match(/../g) ?? [], byte => Number.parseInt(byte, 16))
}

function bytesToHex(value: Uint8Array): string {
  return Array.from(value, byte => byte.toString(16).padStart(2, '0')).join('')
}

function parseCanonicalU64(value: string, field: string): bigint {
  if (!/^(0|[1-9][0-9]*)$/.test(value)) throw new Error(`${field} is not canonical`)
  const parsed = BigInt(value)
  if (parsed < 0n || parsed > 0xffff_ffff_ffff_ffffn) {
    throw new Error(`${field} is outside u64`)
  }
  return parsed
}

async function ledgerOperationId(
  entityId: string,
  revision: bigint,
  digest: string,
): Promise<string> {
  const bytes = new TextEncoder().encode(
    `kutup/chat-attachment-ledger/operation/v1\0${entityId}\0${revision}\0${digest}`,
  )
  const hash = new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)).slice(0, 16)
  hash[6] = (hash[6] & 0x0f) | 0x80
  hash[8] = (hash[8] & 0x3f) | 0x80
  const hex = Array.from(hash, byte => byte.toString(16).padStart(2, '0')).join('')
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`
}
