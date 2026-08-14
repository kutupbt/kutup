import api from '@/api/client'
import { ACCOUNT_ENVELOPE_PURPOSE, openAccountEnvelope, sealAccountEnvelope } from '@/crypto/accountEnvelope'
import { fromBase64, toBase64 } from '@/crypto/base64'
import { deriveAccountIdentityKeys } from '@/crypto/identity'
import { getCryptoWasm } from '@/crypto/rustWasm'
import { getSodium } from '@/crypto/sodium'
import { newStreamDecryptor } from '@/crypto/streamDecryptor'
import { ABYTES, HEADER_BYTES, PLAIN_CHUNK, newStreamEncryptor } from '@/crypto/streamEncryptor'
import { resolveApiBase } from '@/lib/apiBase'
import {
  acknowledgeBackupEntry as acknowledge,
  commitBackupQueue as commitQueue,
  countStore,
  getAll,
  loadBackupState as loadState,
  openBackupStore as openBackupDb,
  putValue,
  replaceBackupMedia,
  replaceRestoredRecords,
} from './backup-store'
import type {
  BackupLocalState as LocalState,
  BackupOutboxEntry as OutboxEntry,
  StoredBackupMedia,
  StoredBackupRecord,
} from './backup-store'
import type { ChatAttachmentDescriptorV1, ChatHistoryEntry } from './types'

const ZERO_DIGEST = '0'.repeat(64)
const SEGMENT_PURPOSE = 2
const BASE_PURPOSE = 1
const SEGMENT_TARGET_BYTES = 64 * 1024
const COMPACT_EVENT_THRESHOLD = 10_000
const COMPACT_BYTE_THRESHOLD = 64 * 1024 * 1024
const COMPACT_DAILY_MS = 24 * 60 * 60 * 1000
const BACKUP_MEDIA_HEADER_BYTES = 107
const encoder = new TextEncoder()

export interface BackupAuthorization {
  version: number
  backupIncarnationId: string
  accountIncarnationId: string
  suite: number
  protectionDomain: number
  manifestSigningPublicKey: string
  accountAuthorityKeyId: string
  createdAtUnix: number
  accountAuthoritySignature: string
}

export interface BackupManifest {
  version: number
  backupIncarnationId: string
  suite: number
  protectionDomain: number
  generation: number
  previousManifestDigest: string
  baseObjectId: string
  baseCiphertextBytes: number
  baseCiphertextSha256: string
  coveredCursor: number
  mediaReferenceSetDigest: string
  signerAuthorizationDigest: string
  createdAtUnix: number
  signature: string
}

export interface BackupStatusResponse {
  provisioned: boolean
  rootEnvelope?: string
  signerAuthorization?: BackupAuthorization
  manifest?: BackupManifest
  currentCursor: number
  latestProtectedAtUnix?: number
  storage: BackupStorageUsage
}

export interface BackupStorageUsage {
  quotaBytes: number
  usedBytes: number
  messageBytes: number
  deliveryMediaBytes: number
  historyMediaBytes: number
}

export type ChatBackupState =
  | 'protected'
  | 'backingUp'
  | 'offline'
  | 'mediaPending'
  | 'needsAttention'

export interface ChatBackupView {
  state: ChatBackupState
  storageFull: boolean
  currentCursor: number
  latestProtectedAt?: number
  pendingEvents: number
  pendingBytes: number
  pendingMedia: number
  pendingMediaBytes: number
  storage: BackupStorageUsage
}

export interface BackupMediaSource {
  attachmentId: string
  referenceId: string
  ciphertextBytes: number
}

interface BackupDisplayRecord {
  version: 1
  recordId: string
  mutationSequence: number
  conversation: ChatHistoryEntry['conversation']
  sender: string
  senderDeviceId: number
  outgoing: boolean
  content?: ChatHistoryEntry['content']
  timestampMs: number
  delivered: boolean
  absoluteExpiryMs?: number
  tombstone: boolean
}

type StoredRecord = StoredBackupRecord<BackupDisplayRecord>

export interface SegmentPage {
  segments: Array<{
    operationId: string
    cursor: number
    sourceDeviceId: number
    deviceSequence: number
    previousSegmentDigest: string
    ciphertextBytes: number
    ciphertextSha256: string
    ciphertext: string
    acknowledgedAtUnix: number
  }>
  currentCursor: number
  more: boolean
}

export interface ChatBackupOptions {
  databaseName: string
  email: string
  username: string
  serverName: string
  masterKey: Uint8Array
  deviceId: number
  history: () => Promise<ChatHistoryEntry[]>
  manifestSequence: () => Promise<number>
  mediaSources: () => readonly BackupMediaSource[]
  localMediaCiphertext: (
    descriptor: ChatAttachmentDescriptorV1,
    signal?: AbortSignal,
  ) => AsyncIterable<Uint8Array>
}

export interface BackupConnectivity {
  isOnline(): boolean
}

export interface BackupClock {
  now(): number
}

export type BackupScheduledTask = unknown

export interface BackupScheduler {
  schedule(delayMs: number, callback: () => void): BackupScheduledTask
  cancel(task: BackupScheduledTask): void
}

export interface BackupIdSource {
  randomUuid(): string
  randomBytes(length: number): Uint8Array
}

export type ChatBackupCompactionCheckpoint =
  | 'current-base-and-tail-verified'
  | 'replacement-base-encrypted'
  | 'base-upload-acknowledged'
  | 'media-reconciliation-acknowledged'
  | 'manifest-cas-acknowledged'
  | 'local-generation-cursor-pin-persisted'

export interface ChatBackupTransport {
  status(): Promise<BackupStatusResponse>
  provision(request: {
    operationId: string
    rootEnvelope: string
    signerAuthorization: BackupAuthorization
  }): Promise<BackupStatusResponse>
  appendSegment(request: {
    operationId: string
    backupIncarnationId: string
    sourceDeviceId: number
    deviceSequence: number
    previousSegmentDigest: string
    accountManifestSequence: number
    ciphertextBytes: number
    ciphertextSha256: string
    ciphertext: string
  }): Promise<{ cursor: number; acknowledgedAtUnix: number }>
  listSegments(after: number, limit: number): Promise<SegmentPage>
  stageBase(metadata: {
    backupIncarnationId: string
    objectId: string
    generation: number
    coveredCursor: number
    ciphertextBytes: number
    ciphertextSha256: string
  }, ciphertext: Uint8Array): Promise<void>
  downloadBase(objectId: string): Promise<Uint8Array>
  copyMedia(request: {
    operationId: string
    backupIncarnationId: string
    sourceAttachmentId: string
    mediaId: string
    referenceId: string
    outerEncryptionKey: string
  }): Promise<void>
  uploadMedia(metadata: {
    backupIncarnationId: string
    mediaId: string
    referenceId: string
    sourceCiphertextBytes: number
    ciphertextBytes: number
    ciphertextSha256: string
  }, ciphertext: Blob): Promise<void>
  downloadMedia(mediaId: string, accessToken: string, signal?: AbortSignal): Promise<{
    body: ReadableStream<Uint8Array>
    ciphertextSha256: string
  }>
  reconcileMedia(request: {
    operationId: string
    targetGeneration: number
    referenceSetDigest: string
    pageIndex: number
    finalPage: boolean
    references: Array<{ referenceId: string; mediaId: string }>
  }): Promise<void>
  compareAndSwapManifest(request: {
    expectedGeneration: number
    expectedCursor: number
    expectedManifestDigest: string
    manifest: BackupManifest
  }): Promise<void>
}

export interface ChatBackupRuntime {
  transport: ChatBackupTransport
  connectivity: BackupConnectivity
  clock: BackupClock
  scheduler: BackupScheduler
  ids: BackupIdSource
  checkpoint?: (checkpoint: ChatBackupCompactionCheckpoint) => void | Promise<void>
}

const browserTransport: ChatBackupTransport = {
  async status() {
    return (await api.get<BackupStatusResponse>('/chat/backup')).data
  },
  async provision(request) {
    return (await api.post<BackupStatusResponse>('/chat/backup', request)).data
  },
  async appendSegment(request) {
    return (await api.post<{ cursor: number; acknowledgedAtUnix: number }>(
      '/chat/backup/segments', request,
    )).data
  },
  async listSegments(after, limit) {
    return (await api.get<SegmentPage>('/chat/backup/segments', {
      params: { after, limit },
    })).data
  },
  async stageBase(metadata, ciphertext) {
    const form = new FormData()
    form.append('metadata', new Blob([JSON.stringify(metadata)], { type: 'application/json' }))
    form.append('ciphertext', new Blob([ciphertext.slice().buffer as ArrayBuffer]), 'base.bin')
    await api.post('/chat/backup/bases', form)
  },
  async downloadBase(objectId) {
    const response = await api.get<ArrayBuffer>(
      `/chat/backup/bases/${encodeURIComponent(objectId)}`,
      { responseType: 'arraybuffer' },
    )
    return new Uint8Array(response.data)
  },
  async copyMedia(request) {
    await api.post('/chat/backup/media/copy', request)
  },
  async uploadMedia(metadata, ciphertext) {
    const form = new FormData()
    form.append('metadata', new Blob([JSON.stringify(metadata)], { type: 'application/json' }))
    form.append('ciphertext', ciphertext, 'media.bin')
    await api.post('/chat/backup/media', form)
  },
  async downloadMedia(mediaId, accessToken, signal) {
    const response = await fetch(
      `${await resolveApiBase()}/chat/backup/media/${encodeURIComponent(mediaId)}`,
      { headers: { Authorization: `Bearer ${accessToken}` }, signal },
    )
    if (!response.ok || !response.body) throw new Error('protected Chat media is unavailable')
    const ciphertextSha256 = response.headers.get('x-kutup-ciphertext-sha256')
    if (!ciphertextSha256 || !/^[0-9a-f]{64}$/.test(ciphertextSha256)) {
      throw new Error('protected Chat media response has no canonical digest')
    }
    return { body: response.body, ciphertextSha256 }
  },
  async reconcileMedia(request) {
    await api.post('/chat/backup/media/reconciliation', request)
  },
  async compareAndSwapManifest(request) {
    await api.put('/chat/backup/manifest', request)
  },
}

export function browserChatBackupRuntime(): ChatBackupRuntime {
  return {
    transport: browserTransport,
    connectivity: { isOnline: () => navigator.onLine },
    clock: { now: () => Date.now() },
    scheduler: {
      schedule: (delayMs, callback) => setTimeout(callback, delayMs),
      cancel: task => clearTimeout(task as ReturnType<typeof setTimeout>),
    },
    ids: {
      randomUuid: () => crypto.randomUUID(),
      randomBytes: length => crypto.getRandomValues(new Uint8Array(length)),
    },
    checkpoint: () => undefined,
  }
}

interface MediaProtection {
  referenceId: string
  mediaId: string
  ciphertextBytes: number
  protected: boolean
  needsAttention: boolean
  storageFull: boolean
}

export class ChatBackupCoordinator {
  private readonly listeners = new Set<() => void>()
  private readonly media = new Map<string, MediaProtection>()
  private viewValue: ChatBackupView
  private timer: BackupScheduledTask | null = null
  private running: Promise<void> | null = null
  private disposed = false
  private compactionRequested = false
  private messageStorageFull = false

  private constructor(
    private readonly options: ChatBackupOptions,
    private readonly db: IDBDatabase,
    private readonly root: Uint8Array,
    private status: BackupStatusResponse,
    private readonly accountIncarnationId: string,
    private readonly backupIncarnationId: string,
    private signerAuthorizationDigest: string,
    private manifestDigest: string,
    private readonly runtime: ChatBackupRuntime,
  ) {
    this.viewValue = {
      state: runtime.connectivity.isOnline() ? 'protected' : 'offline',
      storageFull: false,
      currentCursor: status.currentCursor,
      latestProtectedAt: status.latestProtectedAtUnix
        ? status.latestProtectedAtUnix * 1000
        : undefined,
      pendingEvents: 0,
      pendingBytes: 0,
      pendingMedia: 0,
      pendingMediaBytes: 0,
      storage: status.storage,
    }
  }

  static async open(
    options: ChatBackupOptions,
    runtime: ChatBackupRuntime = browserChatBackupRuntime(),
  ): Promise<ChatBackupCoordinator> {
    const [db, identity, wasm] = await Promise.all([
      openBackupDb(options.databaseName),
      deriveAccountIdentityKeys(toBase64(options.masterKey)),
      getCryptoWasm(),
    ])
    let root: Uint8Array | undefined
    try {
      let status = await runtime.transport.status()
      let backupIncarnationId: string
    if (status.provisioned) {
      if (!status.rootEnvelope || !status.signerAuthorization) {
        throw new Error('Chat backup status is incomplete')
      }
      root = await openAccountEnvelope(
        status.rootEnvelope,
        options.masterKey,
        ACCOUNT_ENVELOPE_PURPOSE.chatBackupRoot,
        options.email,
      )
      backupIncarnationId = status.signerAuthorization.backupIncarnationId
    } else {
      root = runtime.ids.randomBytes(32)
      backupIncarnationId = runtime.ids.randomUuid()
      const authorization = wasm.createChatBackupSignerAuthorization(
        toBase64(options.masterKey),
        toBase64(root),
        backupIncarnationId,
        BigInt(Math.floor(runtime.clock.now() / 1000)),
      ) as BackupAuthorization
      const rootEnvelope = await sealAccountEnvelope(
        root,
        options.masterKey,
        ACCOUNT_ENVELOPE_PURPOSE.chatBackupRoot,
        options.email,
      )
      status = await runtime.transport.provision({
        operationId: runtime.ids.randomUuid(),
        rootEnvelope,
        signerAuthorization: authorization,
      })
    }
    if (!status.signerAuthorization) throw new Error('Chat backup signer is unavailable')
    const verified = wasm.verifyChatBackupMetadata(
      status.signerAuthorization,
      status.manifest ?? null,
      toBase64(options.masterKey),
      toBase64(root),
      backupIncarnationId,
    )
    const coordinator = new ChatBackupCoordinator(
      options,
      db,
      root,
      status,
      identity.incarnationId,
      backupIncarnationId,
      verified.signerAuthorizationDigest,
      verified.manifestDigest ?? ZERO_DIGEST,
      runtime,
    )
    await coordinator.loadMediaState()
    await coordinator.rejectRollbackAndPin()
    await coordinator.restore()
    await coordinator.collectAndQueue()
    await coordinator.refreshView()
    void coordinator.flushNow().catch(() => undefined)
      return coordinator
    } catch (error) {
      root?.fill(0)
      db.close()
      throw error
    }
  }

  view(): ChatBackupView {
    return this.viewValue
  }

  subscribe(listener: () => void): () => void {
    this.listeners.add(listener)
    return () => this.listeners.delete(listener)
  }

  async restoredHistoryAsync(): Promise<ChatHistoryEntry[]> {
    const stored = await getAll<StoredRecord>(this.db, 'records')
    return stored
      .map(({ record }) => record)
      .filter(record => !record.tombstone && record.content)
      .map(record => ({
        id: record.recordId,
        conversation: record.conversation,
        peer: record.sender,
        direction: record.outgoing ? 'outgoing' : 'incoming',
        senderDeviceId: record.senderDeviceId || undefined,
        timestampMs: record.timestampMs,
        delivered: record.delivered,
        deduplicated: false,
        content: record.content!,
      }))
  }

  async *fetchMediaCiphertext(
    mediaId: string,
    accessToken: string,
    signal?: AbortSignal,
  ): AsyncGenerator<Uint8Array, void, void> {
    const response = await this.runtime.transport.downloadMedia(mediaId, accessToken, signal)
    const reader = response.body.getReader()
    const buffered = new BufferedStreamReader(reader)
    const sodium = await getSodium()
    const digest = sodium.crypto_hash_sha256_init() as unknown as Parameters<
      typeof sodium.crypto_hash_sha256_update
    >[0]
    try {
      const prefix = await buffered.readExact(BACKUP_MEDIA_HEADER_BYTES + HEADER_BYTES)
      sodium.crypto_hash_sha256_update(digest, prefix)
      const typedHeader = prefix.subarray(0, BACKUP_MEDIA_HEADER_BYTES)
      const streamHeader = prefix.subarray(BACKUP_MEDIA_HEADER_BYTES)
      const opened = (await getCryptoWasm()).openChatBackupMediaHeader(
        toBase64(typedHeader),
        toBase64(this.root),
        this.accountIncarnationId,
        this.backupIncarnationId,
        mediaId,
      )
      const decryptor = await newStreamDecryptor(
        fromBase64(opened.outerEncryptionKey),
        streamHeader,
        typedHeader,
      )
      let paddedRemaining = Number(opened.paddedPlaintextBytes)
      let sourceRemaining = Number(opened.sourceCiphertextBytes)
      if (!Number.isSafeInteger(paddedRemaining) || !Number.isSafeInteger(sourceRemaining)
          || sourceRemaining <= 0 || paddedRemaining < sourceRemaining) {
        throw new Error('protected Chat media lengths are invalid')
      }
      while (paddedRemaining > 0) {
        const plainBytes = Math.min(PLAIN_CHUNK, paddedRemaining)
        const frame = await buffered.readExact(plainBytes + ABYTES)
        sodium.crypto_hash_sha256_update(digest, frame)
        const openedFrame = decryptor.pull(frame)
        if (openedFrame.plain.length !== plainBytes
            || openedFrame.isFinal !== (plainBytes === paddedRemaining)) {
          throw new Error('protected Chat media secretstream framing is invalid')
        }
        const sourceBytes = Math.min(sourceRemaining, openedFrame.plain.length)
        if (sourceBytes > 0) yield openedFrame.plain.slice(0, sourceBytes)
        for (let index = sourceBytes; index < openedFrame.plain.length; index++) {
          if (openedFrame.plain[index] !== 0) throw new Error('protected Chat media padding is invalid')
        }
        sourceRemaining -= sourceBytes
        paddedRemaining -= plainBytes
      }
      if (sourceRemaining !== 0 || await buffered.hasMore()) {
        throw new Error('protected Chat media length is inconsistent')
      }
      if (sodium.crypto_hash_sha256_final(digest, 'hex') !== response.ciphertextSha256) {
        throw new Error('protected Chat media digest is invalid')
      }
    } finally {
      await reader.cancel().catch(() => undefined)
    }
  }

  schedule(): void {
    if (this.disposed || this.timer !== null) return
    this.timer = this.runtime.scheduler.schedule(900, () => {
      this.timer = null
      void this.runCycle()
    })
  }

  pageHidden(): void {
    if (document.visibilityState === 'hidden') void this.runCycle()
  }

  online(): void {
    void this.runCycle()
  }

  /** Runs the same serialized cycle used by startup, debounce, visibility, and online events. */
  flushNow(): Promise<void> {
    if (this.timer !== null) this.runtime.scheduler.cancel(this.timer)
    this.timer = null
    return this.runCycle()
  }

  /** Resolves when the currently scheduled/running work has reached a durable boundary. */
  async settled(): Promise<void> {
    if (this.timer !== null) await this.flushNow()
    while (this.running) await this.running
  }

  dispose(): void {
    this.disposed = true
    if (this.timer !== null) this.runtime.scheduler.cancel(this.timer)
    this.timer = null
    this.root.fill(0)
    this.listeners.clear()
    this.db.close()
  }

  private runCycle(): Promise<void> {
    if (this.running) return this.running
    this.running = (async () => {
      await this.collectAndQueue()
      await this.flush()
    })().finally(() => { this.running = null })
    return this.running
  }

  private async protectMedia(history: readonly ChatHistoryEntry[]): Promise<Map<string, string>> {
    const wasm = await getCryptoWasm()
    const protectedIds = new Map<string, string>()
    const descriptors = new Map<string, ChatAttachmentDescriptorV1>()
    const deletedMessageIds = new Set(history.flatMap(entry =>
      entry.content.mutation?.operation === 'delete'
        ? [entry.content.mutation.targetMessageId]
        : []))
    for (const entry of history) {
      const descriptor = entry.content.attachment
      if (descriptor && isEligible(entry, this.runtime.clock.now())
          && (!entry.content.messageId || !deletedMessageIds.has(entry.content.messageId))) {
        descriptors.set(descriptor.attachmentId, descriptor)
      }
    }
    const sources = this.options.mediaSources()
      .filter(source => descriptors.has(source.attachmentId))
    const activeAttachmentIds = new Set(descriptors.keys())
    for (const attachmentId of this.media.keys()) {
      if (!activeAttachmentIds.has(attachmentId)) {
        this.media.delete(attachmentId)
        this.compactionRequested = true
      }
    }
    for (const [attachmentId] of descriptors) {
      const existing = this.media.get(attachmentId)
      if (existing) protectedIds.set(attachmentId, existing.mediaId)
    }
    for (const source of sources) {
      let state = this.media.get(source.attachmentId)
      if (!state) {
        const prepared = wasm.prepareChatBackupMedia(
          toBase64(this.root),
          this.accountIncarnationId,
          this.backupIncarnationId,
          source.attachmentId,
          BigInt(source.ciphertextBytes),
        )
        state = {
          referenceId: source.referenceId,
          mediaId: prepared.mediaId,
          ciphertextBytes: backupMediaObjectBytes(Number(prepared.paddedPlaintextBytes)),
          protected: false,
          needsAttention: false,
          storageFull: false,
        }
        this.media.set(source.attachmentId, state)
      }
      protectedIds.set(source.attachmentId, state.mediaId)
      if (state.protected || !this.runtime.connectivity.isOnline()) continue
      state.needsAttention = false
      state.storageFull = false
      try {
        const prepared = wasm.prepareChatBackupMedia(
          toBase64(this.root),
          this.accountIncarnationId,
          this.backupIncarnationId,
          source.attachmentId,
          BigInt(source.ciphertextBytes),
        )
        await this.runtime.transport.copyMedia({
          operationId: await deterministicUuid(`copy:${state.referenceId}:${state.mediaId}`),
          backupIncarnationId: this.backupIncarnationId,
          sourceAttachmentId: source.attachmentId,
          mediaId: state.mediaId,
          referenceId: state.referenceId,
          outerEncryptionKey: prepared.outerEncryptionKey,
        })
        state.protected = true
      } catch (error: any) {
        if (transportStatus(error) === 404) {
          const descriptor = descriptors.get(source.attachmentId)
          if (descriptor) {
            try {
              await this.uploadLocalMediaCopy(source, descriptor)
              state.protected = true
            } catch {
              // The verified local cache is an optional fallback. Keep this
              // media item explicitly pending when it is absent or evicted.
            }
          }
        } else if (transportStatus(error) !== undefined) {
          // Media protection is independent from message-history protection.
          // Preserve display mutations in the outbox while surfacing the
          // failed media copy as an actionable backup state.
          state.needsAttention = true
          state.storageFull = transportStatus(error) === 507
        }
      }
    }
    await this.persistMediaState()
    return protectedIds
  }

  private async uploadLocalMediaCopy(
    source: BackupMediaSource,
    descriptor: ChatAttachmentDescriptorV1,
  ): Promise<void> {
    if (descriptor.ciphertextBytes !== source.ciphertextBytes) {
      throw new Error('local Chat media length differs from its backup source')
    }
    const prepared = (await getCryptoWasm()).prepareChatBackupMedia(
      toBase64(this.root),
      this.accountIncarnationId,
      this.backupIncarnationId,
      source.attachmentId,
      BigInt(source.ciphertextBytes),
    )
    const typedHeader = fromBase64(prepared.objectHeader)
    const paddedBytes = Number(prepared.paddedPlaintextBytes)
    if (!Number.isSafeInteger(paddedBytes) || paddedBytes < source.ciphertextBytes) {
      throw new Error('backup media padding length is invalid')
    }
    const encryptor = await newStreamEncryptor(
      fromBase64(prepared.outerEncryptionKey), typedHeader,
    )
    const sodium = await getSodium()
    const hash = sodium.crypto_hash_sha256_init() as unknown as Parameters<
      typeof sodium.crypto_hash_sha256_update
    >[0]
    const parts: BlobPart[] = []
    let outerBytes = 0
    const appendOuter = (bytes: Uint8Array) => {
      sodium.crypto_hash_sha256_update(hash, bytes)
      parts.push(bytes.slice().buffer as ArrayBuffer)
      outerBytes += bytes.length
    }
    appendOuter(typedHeader)
    appendOuter(encryptor.header)

    let sourceBytes = 0
    let paddedEmitted = 0
    let pending: Uint8Array<ArrayBufferLike> = new Uint8Array()
    const emit = (plain: Uint8Array) => {
      paddedEmitted += plain.length
      appendOuter(encryptor.push(plain, paddedEmitted === paddedBytes))
    }
    for await (const chunk of this.options.localMediaCiphertext(descriptor)) {
      sourceBytes += chunk.length
      if (sourceBytes > descriptor.ciphertextBytes) {
        throw new Error('local Chat media exceeds its authenticated length')
      }
      pending = appendBytes(pending, chunk)
      while (paddedEmitted < paddedBytes) {
        const frameBytes = Math.min(PLAIN_CHUNK, paddedBytes - paddedEmitted)
        if (pending.length < frameBytes) break
        emit(pending.slice(0, frameBytes))
        pending = pending.slice(frameBytes)
      }
    }
    if (sourceBytes !== descriptor.ciphertextBytes) {
      throw new Error('local Chat media is truncated')
    }
    while (paddedEmitted < paddedBytes) {
      const frameBytes = Math.min(PLAIN_CHUNK, paddedBytes - paddedEmitted)
      const plain = new Uint8Array(frameBytes)
      const copied = Math.min(pending.length, frameBytes)
      plain.set(pending.subarray(0, copied))
      pending = pending.slice(copied)
      emit(plain)
    }
    if (pending.length !== 0) throw new Error('local Chat media padding overflow')

    const metadata = {
      backupIncarnationId: this.backupIncarnationId,
      mediaId: prepared.mediaId,
      referenceId: source.referenceId,
      sourceCiphertextBytes: source.ciphertextBytes,
      ciphertextBytes: outerBytes,
      ciphertextSha256: sodium.crypto_hash_sha256_final(hash, 'hex'),
    }
    await this.runtime.transport.uploadMedia(metadata, new Blob(parts))
  }

  private async collectAndQueue(): Promise<void> {
    const [history, stored, localState] = await Promise.all([
      this.options.history(),
      getAll<StoredRecord>(this.db, 'records'),
      loadState(this.db, this.runtime.clock.now()),
    ])
    const localRecordIds = new Set(await Promise.all(
      history.map(entry => canonicalRecordId(entry.id)),
    ))
    // A clean install restores display history before its new Chat engine has
    // any local rows. Keep those server-authenticated records in the media
    // protection set until a local row supersedes them. Otherwise the first
    // startup cycle reconciles an empty media set and destroys the only copy
    // capable of satisfying the restored attachment.
    const protectionHistory = history.concat(stored
      .filter(value => !value.local && !value.record.tombstone
        && value.record.content && !localRecordIds.has(value.id))
      .map(({ record }) => ({
        id: record.recordId,
        conversation: record.conversation,
        peer: record.sender,
        direction: record.outgoing ? 'outgoing' as const : 'incoming' as const,
        senderDeviceId: record.senderDeviceId || undefined,
        timestampMs: record.timestampMs,
        delivered: record.delivered,
        deduplicated: false,
        content: record.content!,
      })))
    const backupMedia = await this.protectMedia(protectionHistory)
    const prior = new Map(stored.map(value => [value.id, value]))
    const current = new Set<string>()
    const mutations: BackupDisplayRecord[] = []
    const replacements: StoredRecord[] = []
    for (const entry of history) {
      const recordId = await canonicalRecordId(entry.id)
      current.add(recordId)
      const previous = prior.get(recordId)
      const eligible = isEligible(entry, this.runtime.clock.now())
      if (!eligible) {
        if (previous && !previous.record.tombstone) {
          const tombstone = { ...previous.record, mutationSequence: previous.record.mutationSequence + 1,
            content: undefined, tombstone: true }
          mutations.push(tombstone)
          replacements.push({ id: recordId, fingerprint: await fingerprint(tombstone), record: tombstone, local: true })
        }
        continue
      }
      const content = structuredClone(entry.content)
      if (content.attachment) {
        const mediaId = backupMedia.get(content.attachment.attachmentId)
        const media = this.media.get(content.attachment.attachmentId)
        if (mediaId && media) {
          content.attachment.backupMediaId = mediaId
          content.attachment.backupMediaReferenceId = media.referenceId
        }
      }
      const record: BackupDisplayRecord = {
        version: 1,
        recordId,
        mutationSequence: previous?.record.mutationSequence ?? 1,
        conversation: entry.conversation,
        sender: entry.direction === 'outgoing'
          ? `${this.options.username}@${this.options.serverName}`
          : entry.peer,
        senderDeviceId: entry.senderDeviceId ?? this.options.deviceId,
        outgoing: entry.direction === 'outgoing',
        content,
        timestampMs: entry.timestampMs,
        delivered: entry.delivered,
        ...(entry.content.expiresAtMs ? { absoluteExpiryMs: entry.content.expiresAtMs } : {}),
        tombstone: false,
      }
      let recordFingerprint = await fingerprint(record)
      if (previous && previous.fingerprint !== recordFingerprint) {
        record.mutationSequence = previous.record.mutationSequence + 1
        recordFingerprint = await fingerprint(record)
      }
      if (!previous || previous.fingerprint !== recordFingerprint) mutations.push(record)
      replacements.push({ id: recordId, fingerprint: recordFingerprint, record, local: true })
    }
    for (const previous of stored) {
      if (!previous.local || current.has(previous.id) || previous.record.tombstone) continue
      const tombstone: BackupDisplayRecord = {
        ...previous.record,
        mutationSequence: previous.record.mutationSequence + 1,
        content: undefined,
        tombstone: true,
      }
      mutations.push(tombstone)
      replacements.push({ id: previous.id, fingerprint: await fingerprint(tombstone), record: tombstone, local: true })
    }
    if (mutations.length === 0) {
      if (replacements.some(value => !prior.get(value.id)?.local)) {
        await commitQueue(this.db, replacements, [], localState)
      }
      await this.refreshView()
      return
    }
    if (mutations.some(record => record.tombstone)) this.compactionRequested = true
    const chunks = splitRecords(mutations)
    const wasm = await getCryptoWasm()
    let sequence = localState.deviceSequence
    let previousDigest = localState.lastSegmentDigest
    const outbox: OutboxEntry[] = []
    for (const records of chunks) {
      sequence += 1
      const operationId = this.runtime.ids.randomUuid()
      const plaintext = wasm.encodeChatBackupPlaintext({ version: 1, records }, SEGMENT_PURPOSE)
      const ciphertext = wasm.sealChatBackupObject(
        plaintext,
        toBase64(this.root),
        this.accountIncarnationId,
        this.backupIncarnationId,
        SEGMENT_PURPOSE,
        operationId,
        this.options.deviceId,
        BigInt(sequence),
        previousDigest,
      )
      const ciphertextBytes = fromBase64(ciphertext).length
      const ciphertextSha256 = await sha256Hex(fromBase64(ciphertext))
      outbox.push({
        deviceSequence: sequence,
        operationId,
        previousSegmentDigest: previousDigest,
        ciphertext,
        ciphertextBytes,
        ciphertextSha256,
        recordCount: records.length,
      })
      previousDigest = ciphertextSha256
    }
    await commitQueue(this.db, replacements, outbox, {
      ...localState,
      deviceSequence: sequence,
      lastSegmentDigest: previousDigest,
    })
    await this.refreshView('backingUp')
  }

  private async flush(): Promise<void> {
    if (!this.runtime.connectivity.isOnline()) {
      await this.refreshView('offline')
      return
    }
    const outbox = (await getAll<OutboxEntry>(this.db, 'outbox'))
      .sort((left, right) => left.deviceSequence - right.deviceSequence)
    if (outbox.length === 0) {
      await this.refreshView(this.mediaViewState())
      await this.maybeCompact()
      return
    }
    await this.refreshView('backingUp')
    const accountManifestSequence = await this.options.manifestSequence()
    for (const entry of outbox) {
      try {
        const receipt = await this.runtime.transport.appendSegment({
          operationId: entry.operationId,
          backupIncarnationId: this.backupIncarnationId,
          sourceDeviceId: this.options.deviceId,
          deviceSequence: entry.deviceSequence,
          previousSegmentDigest: entry.previousSegmentDigest,
          accountManifestSequence,
          ciphertextBytes: entry.ciphertextBytes,
          ciphertextSha256: entry.ciphertextSha256,
          ciphertext: entry.ciphertext,
        })
        await acknowledge(
          this.db,
          entry,
          receipt.cursor,
          receipt.acknowledgedAtUnix * 1000,
          this.runtime.clock.now(),
        )
        this.messageStorageFull = false
      } catch (error: any) {
        if (transportStatus(error) === 507) {
          this.messageStorageFull = true
          await this.refreshServerStatus('needsAttention')
          return
        }
        if (!this.runtime.connectivity.isOnline() || !transportStatus(error)) {
          await this.refreshView('offline')
          return
        }
        await this.refreshView('needsAttention')
        throw error
      }
    }
    await this.refreshServerStatus(this.mediaViewState())
    await this.maybeCompact()
  }

  private async restore(force = false, persist = true): Promise<StoredRecord[] | undefined> {
    const state = await loadState(this.db, this.runtime.clock.now())
    if (!force && state.restoredCursor >= this.status.currentCursor
        && (await countStore(this.db, 'records')) > 0) {
      return undefined
    }
    const records = new Map<string, BackupDisplayRecord>()
    const recordSources = new Map<string, Set<number>>()
    let after = 0
    const manifest = this.status.manifest
    if (manifest) {
      const bytes = await this.runtime.transport.downloadBase(manifest.baseObjectId)
      if (bytes.length !== manifest.baseCiphertextBytes || await sha256Hex(bytes) !== manifest.baseCiphertextSha256) {
        throw new Error('Chat backup base differs from its signed manifest')
      }
      const plaintext = await this.openObject(
        toBase64(bytes), BASE_PURPOSE, manifest.baseObjectId, 0, 0, ZERO_DIGEST,
      )
      const base = (await getCryptoWasm()).decodeChatBackupPlaintext(
        toBase64(plaintext), BASE_PURPOSE,
      ) as { version: number; coveredCursor: number; records: BackupDisplayRecord[] }
      if (base.version !== 1 || base.coveredCursor !== manifest.coveredCursor) {
        throw new Error('Chat backup base cursor is invalid')
      }
      applyRecords(records, recordSources, base.records)
      after = manifest.coveredCursor
    }
    const tailDeviceHeads = new Map<number, { sequence: number; digest: string }>()
    const tailOperations = new Set<string>()
    let restoreComplete = false
    for (let pages = 0; pages < 100_000; pages++) {
      const page = await this.runtime.transport.listSegments(after, 256)
      for (const segment of page.segments) {
        if (segment.cursor !== after + 1) throw new Error('Chat backup tail has a cursor gap')
        if (tailOperations.has(segment.operationId)) {
          throw new Error('Chat backup tail repeats an operation')
        }
        const deviceHead = tailDeviceHeads.get(segment.sourceDeviceId)
        if (deviceHead && (segment.deviceSequence !== deviceHead.sequence + 1
            || segment.previousSegmentDigest !== deviceHead.digest)) {
          throw new Error('Chat backup device segment chain was reordered')
        }
        const bytes = fromBase64(segment.ciphertext)
        if (bytes.length !== segment.ciphertextBytes || await sha256Hex(bytes) !== segment.ciphertextSha256) {
          throw new Error('Chat backup segment digest is invalid')
        }
        const plaintext = await this.openObject(
          segment.ciphertext,
          SEGMENT_PURPOSE,
          segment.operationId,
          segment.sourceDeviceId,
          segment.deviceSequence,
          segment.previousSegmentDigest,
        )
        const decoded = (await getCryptoWasm()).decodeChatBackupPlaintext(
          toBase64(plaintext), SEGMENT_PURPOSE,
        ) as { version: number; records: BackupDisplayRecord[] }
        if (decoded.version !== 1) throw new Error('unsupported Chat backup segment')
        applyRecords(records, recordSources, decoded.records, segment.sourceDeviceId)
        tailOperations.add(segment.operationId)
        tailDeviceHeads.set(segment.sourceDeviceId, {
          sequence: segment.deviceSequence,
          digest: segment.ciphertextSha256,
        })
        after = segment.cursor
      }
      if (!page.more) {
        if (after !== page.currentCursor) throw new Error('Chat backup restore stopped before its cursor')
        restoreComplete = true
        break
      }
      if (page.segments.length !== 256) throw new Error('Chat backup continuation page is incomplete')
    }
    if (!restoreComplete) throw new Error('Chat backup restore exceeds the bounded page limit')
    const stored = await Promise.all(Array.from(records.values()).map(async record => ({
      id: record.recordId,
      fingerprint: await fingerprint(record),
      record,
      local: false,
    })))
    if (persist) {
      const media = restoredMedia(stored)
      this.media.clear()
      for (const value of media) {
        this.media.set(value.attachmentId, {
          referenceId: value.referenceId,
          mediaId: value.mediaId,
          ciphertextBytes: value.ciphertextBytes,
          protected: value.protected,
          needsAttention: value.needsAttention,
          storageFull: value.storageFull,
        })
      }
      await replaceRestoredRecords(
        this.db,
        stored,
        after,
        this.runtime.clock.now(),
        media,
      )
    }
    return stored
  }

  private async openObject(
    ciphertext: string,
    purpose: number,
    objectId: string,
    sourceDeviceId: number,
    sequence: number,
    previousDigest: string,
  ): Promise<Uint8Array> {
    const wasm = await getCryptoWasm()
    return fromBase64(wasm.openChatBackupObject(
      ciphertext,
      toBase64(this.root),
      this.accountIncarnationId,
      this.backupIncarnationId,
      purpose,
      objectId,
      sourceDeviceId,
      BigInt(sequence),
      previousDigest,
    ))
  }

  private async maybeCompact(): Promise<void> {
    for (let attempt = 0; attempt < 3; attempt++) {
      try {
        await this.compactIfNeededOnce()
        return
      } catch (error) {
        if (transportStatus(error) !== 409 || attempt === 2) throw error
        // A competing device won the compare-and-swap. Authenticate and pin
        // that winner, then rebuild from its exact base plus tail.
        await this.refreshServerStatus(this.mediaViewState())
      }
    }
  }

  private async compactIfNeededOnce(): Promise<void> {
    const state = await loadState(this.db, this.runtime.clock.now())
    if (this.status.currentCursor === 0 || (!this.compactionRequested && (
      state.acknowledgedEvents < COMPACT_EVENT_THRESHOLD &&
      state.acknowledgedBytes < COMPACT_BYTE_THRESHOLD &&
      this.runtime.clock.now() - state.lastCompactedAt < COMPACT_DAILY_MS
    ))) return
    // Never stage from an assumed local view. Re-read and authenticate the
    // exact server restore point first; this intentionally performs no local
    // history transaction, so any rejection imports zero records.
    const verifiedRestorePoint = await this.restore(true, false)
    if (!verifiedRestorePoint) throw new Error('Chat backup restore point verification was skipped')
    await this.runtime.checkpoint?.('current-base-and-tail-verified')
    const records = verifiedRestorePoint.map(value => value.record)
    const objectId = this.runtime.ids.randomUuid()
    const generation = (this.status.manifest?.generation ?? 0) + 1
    const wasm = await getCryptoWasm()
    const plaintext = wasm.encodeChatBackupPlaintext({
      version: 1,
      coveredCursor: this.status.currentCursor,
      records,
    }, BASE_PURPOSE)
    const ciphertext = fromBase64(wasm.sealChatBackupObject(
      plaintext, toBase64(this.root), this.accountIncarnationId,
      this.backupIncarnationId, BASE_PURPOSE, objectId, 0, 0n, ZERO_DIGEST,
    ))
    const baseDigest = await sha256Hex(ciphertext)
    await this.runtime.checkpoint?.('replacement-base-encrypted')
    const baseMetadata = {
      backupIncarnationId: this.backupIncarnationId,
      objectId,
      generation,
      coveredCursor: this.status.currentCursor,
      ciphertextBytes: ciphertext.length,
      ciphertextSha256: baseDigest,
    }
    await this.runtime.transport.stageBase(baseMetadata, ciphertext)
    await this.runtime.checkpoint?.('base-upload-acknowledged')

    const references = Array.from(this.media.values())
      .filter(value => value.protected)
      .map(value => ({ referenceId: value.referenceId, mediaId: value.mediaId }))
      .sort((left, right) => left.referenceId.localeCompare(right.referenceId))
    const referenceDigest = await mediaReferenceDigest(references)
    const reconciliationId = this.runtime.ids.randomUuid()
    const pages = Math.max(1, Math.ceil(references.length / 1000))
    for (let page = 0; page < pages; page++) {
      await this.runtime.transport.reconcileMedia({
        operationId: reconciliationId,
        targetGeneration: generation,
        referenceSetDigest: referenceDigest,
        pageIndex: page,
        finalPage: page === pages - 1,
        references: references.slice(page * 1000, (page + 1) * 1000),
      })
    }
    await this.runtime.checkpoint?.('media-reconciliation-acknowledged')
    const previousManifestDigest = this.manifestDigest
    if (!this.status.signerAuthorization) throw new Error('Chat backup signer is unavailable')
    const signerAuthorizationDigest = this.signerAuthorizationDigest
    const manifest = wasm.signChatBackupManifest({
      version: 1,
      backupIncarnationId: this.backupIncarnationId,
      suite: 1,
      protectionDomain: 1,
      generation,
      previousManifestDigest,
      baseObjectId: objectId,
      baseCiphertextBytes: ciphertext.length,
      baseCiphertextSha256: baseDigest,
      coveredCursor: this.status.currentCursor,
      mediaReferenceSetDigest: referenceDigest,
      signerAuthorizationDigest,
      createdAtUnix: Math.floor(this.runtime.clock.now() / 1000),
      signature: '',
    }, toBase64(this.root), this.accountIncarnationId, this.backupIncarnationId) as BackupManifest
    await this.runtime.transport.compareAndSwapManifest({
      expectedGeneration: generation - 1,
      expectedCursor: this.status.currentCursor,
      expectedManifestDigest: previousManifestDigest,
      manifest,
    })
    await this.runtime.checkpoint?.('manifest-cas-acknowledged')
    state.acknowledgedEvents = 0
    state.acknowledgedBytes = 0
    state.lastCompactedAt = this.runtime.clock.now()
    await putValue(this.db, 'meta', state)
    await this.refreshServerStatus(this.mediaViewState())
    await this.runtime.checkpoint?.('local-generation-cursor-pin-persisted')
    this.compactionRequested = false
  }

  private mediaViewState(): ChatBackupState {
    const pending = Array.from(this.media.values()).filter(value => !value.protected)
    if (pending.some(value => value.needsAttention)) return 'needsAttention'
    return pending.length > 0 ? 'mediaPending' : 'protected'
  }

  private async loadMediaState(): Promise<void> {
    const stored = await getAll<StoredBackupMedia>(this.db, 'media')
    for (const value of stored) {
      this.media.set(value.attachmentId, {
        referenceId: value.referenceId,
        mediaId: value.mediaId,
        ciphertextBytes: value.ciphertextBytes,
        protected: value.protected,
        needsAttention: value.needsAttention,
        storageFull: value.storageFull,
      })
    }
  }

  private persistMediaState(): Promise<void> {
    return replaceBackupMedia(this.db, Array.from(this.media, ([attachmentId, value]) => ({
      attachmentId,
      ...value,
    })))
  }

  private async refreshServerStatus(preferred: ChatBackupState): Promise<void> {
    this.status = await this.runtime.transport.status()
    if (!this.status.provisioned || !this.status.signerAuthorization) {
      throw new Error('Chat backup disappeared from the server')
    }
    const verified = (await getCryptoWasm()).verifyChatBackupMetadata(
      this.status.signerAuthorization,
      this.status.manifest ?? null,
      toBase64(this.options.masterKey),
      toBase64(this.root),
      this.backupIncarnationId,
    )
    this.signerAuthorizationDigest = verified.signerAuthorizationDigest
    this.manifestDigest = verified.manifestDigest ?? ZERO_DIGEST
    await this.rejectRollbackAndPin()
    await this.refreshView(preferred)
  }

  private async rejectRollbackAndPin(): Promise<void> {
    const state = await loadState(this.db, this.runtime.clock.now())
    const generation = this.status.manifest?.generation ?? 0
    if (this.status.currentCursor < state.highestCursor
        || generation < state.highestGeneration
        || (generation === state.highestGeneration
          && state.highestManifestDigest !== ZERO_DIGEST
          && this.manifestDigest !== state.highestManifestDigest)) {
      throw new Error('Chat backup rollback detected')
    }
    state.highestCursor = Math.max(state.highestCursor, this.status.currentCursor)
    if (generation > state.highestGeneration || state.highestManifestDigest === ZERO_DIGEST) {
      state.highestGeneration = generation
      state.highestManifestDigest = this.manifestDigest
    }
    await putValue(this.db, 'meta', state)
  }

  private async refreshView(preferred?: ChatBackupState): Promise<void> {
    const [outbox, state] = await Promise.all([
      getAll<OutboxEntry>(this.db, 'outbox'),
      loadState(this.db, this.runtime.clock.now()),
    ])
    const pendingMedia = Array.from(this.media.values()).filter(value => !value.protected)
    this.viewValue = {
      state: preferred ?? (!this.runtime.connectivity.isOnline() ? 'offline'
        : outbox.length > 0 ? 'backingUp'
          : this.mediaViewState()),
      storageFull: this.messageStorageFull || pendingMedia.some(value => value.storageFull),
      currentCursor: this.status.currentCursor,
      latestProtectedAt: state.latestProtectedAt ?? this.viewValue.latestProtectedAt,
      pendingEvents: outbox.reduce((sum, value) => sum + value.recordCount, 0),
      pendingBytes: outbox.reduce((sum, value) => sum + value.ciphertextBytes, 0),
      pendingMedia: pendingMedia.length,
      pendingMediaBytes: pendingMedia.reduce((sum, value) => sum + value.ciphertextBytes, 0),
      storage: this.status.storage,
    }
    for (const listener of this.listeners) listener()
  }
}

function isEligible(entry: ChatHistoryEntry, now: number): boolean {
  const kind = entry.content.kind.toLowerCase().replaceAll('_', '')
  if (kind === 'typing' || kind.includes('viewonce')) return false
  return !entry.content.expiresAtMs || entry.content.expiresAtMs > now + 24 * 60 * 60 * 1000
}

function transportStatus(error: unknown): number | undefined {
  if (!error || typeof error !== 'object') return undefined
  const candidate = error as { status?: unknown; response?: { status?: unknown } }
  const status = candidate.status ?? candidate.response?.status
  return typeof status === 'number' ? status : undefined
}

function applyRecords(
  target: Map<string, BackupDisplayRecord>,
  sources: Map<string, Set<number>>,
  records: BackupDisplayRecord[],
  sourceDeviceId?: number,
): void {
  for (const record of records) {
    const current = target.get(record.recordId)
    if (!current) {
      if (sourceDeviceId !== undefined && record.mutationSequence !== 1) {
        throw new Error('Chat backup record mutation sequence is invalid')
      }
      target.set(record.recordId, record)
      if (sourceDeviceId !== undefined) sources.set(record.recordId, new Set([sourceDeviceId]))
      continue
    }
    if (sourceDeviceId !== undefined
        && record.mutationSequence === current.mutationSequence
        && JSON.stringify(record) === JSON.stringify(current)) {
      // Every linked device receives the same account history and may race to
      // protect a newly observed immutable display record. Treat one exact
      // copy per independent device chain as convergence, while continuing to
      // reject same-chain duplicates and all equal-sequence conflicts.
      const currentSources = sources.get(record.recordId) ?? new Set<number>()
      if (currentSources.has(sourceDeviceId)) {
        throw new Error('Chat backup record mutation sequence is invalid')
      }
      currentSources.add(sourceDeviceId)
      sources.set(record.recordId, currentSources)
      continue
    }
    if (record.mutationSequence !== current.mutationSequence + 1) {
      throw new Error('Chat backup record mutation sequence is invalid')
    }
    target.set(record.recordId, record)
    if (sourceDeviceId === undefined) sources.delete(record.recordId)
    else sources.set(record.recordId, new Set([sourceDeviceId]))
  }
}

function restoredMedia(records: StoredRecord[]): StoredBackupMedia[] {
  const media = new Map<string, StoredBackupMedia>()
  for (const { record } of records) {
    const attachment = record.tombstone ? undefined : record.content?.attachment
    if (!attachment?.backupMediaId || !attachment.backupMediaReferenceId) continue
    if (!/^[0-9a-f]{64}$/.test(attachment.backupMediaId)
        || !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(
          attachment.backupMediaReferenceId,
        )) {
      throw new Error('Chat backup media reference is invalid')
    }
    const candidate: StoredBackupMedia = {
      attachmentId: attachment.attachmentId,
      referenceId: attachment.backupMediaReferenceId,
      mediaId: attachment.backupMediaId,
      ciphertextBytes: 0,
      protected: true,
      needsAttention: false,
      storageFull: false,
    }
    const current = media.get(candidate.attachmentId)
    if (current && (current.referenceId !== candidate.referenceId
        || current.mediaId !== candidate.mediaId)) {
      throw new Error('Chat backup media reference conflicts across records')
    }
    media.set(candidate.attachmentId, candidate)
  }
  return Array.from(media.values())
}

function splitRecords(records: BackupDisplayRecord[]): BackupDisplayRecord[][] {
  const chunks: BackupDisplayRecord[][] = []
  let current: BackupDisplayRecord[] = []
  let bytes = 0
  for (const record of records) {
    const size = encoder.encode(JSON.stringify(record)).length
    if (current.length > 0 && bytes + size > SEGMENT_TARGET_BYTES) {
      chunks.push(current)
      current = []
      bytes = 0
    }
    current.push(record)
    bytes += size
  }
  if (current.length > 0) chunks.push(current)
  return chunks
}

function appendBytes(left: Uint8Array, right: Uint8Array): Uint8Array {
  const joined = new Uint8Array(left.length + right.length)
  joined.set(left)
  joined.set(right, left.length)
  return joined
}

function backupMediaObjectBytes(paddedPlaintextBytes: number): number {
  if (!Number.isSafeInteger(paddedPlaintextBytes) || paddedPlaintextBytes <= 0) {
    throw new Error('backup media padded length is invalid')
  }
  return BACKUP_MEDIA_HEADER_BYTES + HEADER_BYTES + paddedPlaintextBytes
    + Math.ceil(paddedPlaintextBytes / PLAIN_CHUNK) * ABYTES
}

async function fingerprint(value: unknown): Promise<string> {
  return sha256Hex(encoder.encode(JSON.stringify(value)))
}

async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest(
    'SHA-256', bytes.slice().buffer as ArrayBuffer,
  ))
  return Array.from(digest, byte => byte.toString(16).padStart(2, '0')).join('')
}

async function deterministicUuid(value: string): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', encoder.encode(value)))
  digest[6] = (digest[6] & 0x0f) | 0x50
  digest[8] = (digest[8] & 0x3f) | 0x80
  const hex = Array.from(digest.subarray(0, 16), byte => byte.toString(16).padStart(2, '0')).join('')
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`
}

async function canonicalRecordId(id: string): Promise<string> {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(id)
    ? id
    : deterministicUuid(`record:${id}`)
}

async function mediaReferenceDigest(references: Array<{ referenceId: string; mediaId: string }>): Promise<string> {
  const count = new Uint8Array(8)
  new DataView(count.buffer).setBigUint64(0, BigInt(references.length), false)
  const chunks: Uint8Array[] = [encoder.encode('kutup/chat-backup/media-reference-set/v1\0'), count]
  for (const reference of references) {
    chunks.push(uuidBytes(reference.referenceId), hexBytes(reference.mediaId))
  }
  const all = new Uint8Array(chunks.reduce((sum, chunk) => sum + chunk.length, 0))
  let offset = 0
  for (const chunk of chunks) { all.set(chunk, offset); offset += chunk.length }
  return sha256Hex(all)
}

function uuidBytes(value: string): Uint8Array {
  return hexBytes(value.replaceAll('-', ''))
}

function hexBytes(value: string): Uint8Array {
  if (value.length % 2 !== 0 || !/^[0-9a-f]+$/.test(value)) throw new Error('invalid canonical hex')
  return Uint8Array.from(value.match(/../g)!, pair => Number.parseInt(pair, 16))
}

class BufferedStreamReader {
  private buffered = new Uint8Array()
  private ended = false

  constructor(private readonly reader: ReadableStreamDefaultReader<Uint8Array>) {}

  async readExact(bytes: number): Promise<Uint8Array> {
    while (this.buffered.length < bytes && !this.ended) {
      const next = await this.reader.read()
      if (next.done) {
        this.ended = true
        break
      }
      const joined = new Uint8Array(this.buffered.length + next.value.length)
      joined.set(this.buffered)
      joined.set(next.value, this.buffered.length)
      this.buffered = joined
    }
    if (this.buffered.length < bytes) throw new Error('protected Chat media is truncated')
    const output = this.buffered.slice(0, bytes)
    this.buffered = this.buffered.slice(bytes)
    return output
  }

  async hasMore(): Promise<boolean> {
    if (this.buffered.length > 0) return true
    if (this.ended) return false
    const next = await this.reader.read()
    this.ended = !!next.done
    if (!next.done) this.buffered = new Uint8Array(next.value)
    return !next.done
  }
}
