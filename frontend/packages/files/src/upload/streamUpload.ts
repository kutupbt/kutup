// streamUpload — E2EE streaming upload via the tus.io resumable protocol.
// Memory stays bounded at about two 5 MB chunks whatever the file's size:
// the plaintext is read from File.slice() a chunk at a time, encrypted, and
// handed to tus-js-client as the exact ranges it sends (encryptedSource.ts).
//
// An upload survives a long loss of the connection: it waits, and goes on
// from where the server stopped once the browser is back online. Started
// with `resumable`, it also survives a reload or a crash: what it needs to go
// on is kept in this browser (pendingUploads.ts, nothing readable without
// the folder key), and `resumeUpload` continues it once the same file is
// chosen again, re-encrypting what the server already holds rather than
// sending it (docs/roadmap.md, "Drive · large uploads from the browser").
//
// Wire format (crates/kutup-server/src/handlers/tus.rs + the CLI):
//   POST  /api/uploads          — creates session, returns {fileId}
//   HEAD  /api/uploads/<id>     — where an upload stands, to go on from there
//   PATCH /api/uploads/<id>     — appends one S3 multipart part each
//   final PATCH triggers the server's finaliser (Complete + INSERT files)

import * as tus from 'tus-js-client'
import { fromBase64, toBase64 } from '@kutup/crypto/base64'
import { createFileRecordV1, openFileRecordV1, type FileMetadataV1, type MediaMetadataV1 } from '@kutup/crypto'
import {
  DRIVE_FILE_BLOB_CIPHER_CHUNK,
  DRIVE_FILE_BLOB_PREFIX_BYTES,
  newFileBlobStreamEncryptorV1,
  resumeFileBlobStreamEncryptorV1,
} from '@kutup/crypto/fileBlob'
import { ABYTES } from '@kutup/crypto/streamEncryptor'
import { newContentHasher } from '@kutup/crypto/contentHash'
import { resolveApiBase } from '@kutup/session/apiBase'
import { EncryptedFileSource, fileSource, type PlaintextSource } from './encryptedSource'
import { holdUpload, pendingUploads, type PendingUpload } from './pendingUploads'

export interface StreamUploadOptions {
  file: File
  collection: { id: string; keyEpoch: number; collectionKey: Uint8Array }
  /**
   * The bearer token, or a function returning a current one. Uploads can
   * outlive a 15-minute access token, so apps pass a function
   * (`freshAccessToken`) and every request asks it anew.
   */
  accessToken: string | (() => Promise<string>)
  /** Plaintext bytes uploaded so far, plaintext total. */
  onProgress?: (plainSent: number, plainTotal: number) => void
  /** True while the connection is gone and the upload waits to go on. */
  onWaiting?: (waiting: boolean) => void
  /** Cancel an in-flight upload. Calls tus DELETE under the hood. */
  signal?: AbortSignal
  /** A photo's or video's details (`@kutup/files/media`), sealed with its name. */
  media?: MediaMetadataV1
  /** Keep what is needed to go on after a reload, for this account. */
  resumable?: { owner: string }
  /** The name's hash in the folder (docs/plans/drive-unique-names.md): the server keeps it unique. */
  nameHash?: string
}

/** What an upload made: enough to seal things beside it (a thumbnail). */
export interface UploadedFile {
  fileId: string
  fileKey: Uint8Array
  /** A new file's key is generation 1. */
  keyGeneration: 1
  collectionId: string
  /**
   * SHA-256 of the plaintext (base64), read while it was encrypted; null
   * if not every byte was read in order here.
   */
  contentSha256: string | null
}

/**
 * The name is taken in the folder (`409 name_taken`), with what holds it
 * when the server said (docs/plans/drive-unique-names.md).
 */
export class UploadNameTaken extends Error {
  constructor(readonly holder: { kind: 'file' | 'folder'; id: string; contentHash: string | null } | null) {
    super('an item with this name is already here')
  }
}

/** The file chosen to resume an upload is not the one it started with. */
export class NotTheSameFile extends Error {
  constructor() {
    super('this is not the file the upload started with')
  }
}

/** The server no longer has the upload (it was finished, cancelled or reaped). */
export class UploadNoLongerOnServer extends Error {
  constructor() {
    super('the upload is no longer on the server')
  }
}

/** The folder's key changed since the upload started; it cannot go on. */
export class FolderKeyChanged extends Error {
  constructor() {
    super("the folder's key changed since the upload started")
  }
}

/**
 * Encrypt and upload a File. Resolves with the new file's id and key (the
 * id is client-generated and confirmed by the server).
 */
export async function streamUpload(opts: StreamUploadOptions): Promise<UploadedFile> {
  const meta: FileMetadataV1 = {
    name: opts.file.name,
    mimeType: opts.file.type || 'application/octet-stream',
    size: opts.file.size,
  }
  if (opts.media) meta.media = opts.media
  const record = await createFileRecordV1(
    opts.collection.id,
    opts.collection.keyEpoch,
    opts.collection.collectionKey,
    meta,
  )
  const context = { fileId: record.fileId, generation: record.keyGeneration }
  const first = await newFileBlobStreamEncryptorV1(record.fileKey, context)
  let started = false
  const pending: Omit<PendingUpload, 'uploadUrl' | 'startedAt' | 'updatedAt'> | null = opts.resumable
    ? {
        fileId: record.fileId,
        owner: opts.resumable.owner,
        size: opts.file.size,
        lastModified: opts.file.lastModified,
        collectionId: opts.collection.id,
        keyEpoch: opts.collection.keyEpoch,
        fileKeyEnvelope: record.fileKeyEnvelope,
        metadataEnvelope: record.metadataEnvelope,
        prefix: toBase64(first.prefix),
      }
    : null
  const hashed = await hashingSource(fileSource(opts.file))
  await send({
    ...opts,
    plaintext: hashed.source,
    fileId: record.fileId,
    prefix: first.prefix,
    // The first pass uses the encryptor that made the prefix; a pass that
    // has to start over rebuilds it from the prefix.
    openStream: async () => {
      if (!started) {
        started = true
        return first
      }
      return resumeFileBlobStreamEncryptorV1(record.fileKey, context, first.prefix)
    },
    create: {
      metadata: {
        fileId: record.fileId,
        collectionId: opts.collection.id,
        metadataEnvelope: record.metadataEnvelope,
        fileKeyEnvelope: record.fileKeyEnvelope,
        ...(opts.nameHash ? { nameHash: opts.nameHash } : {}),
      },
      remember: pending
        ? async (uploadUrl) => {
            const now = Date.now()
            const record = { ...pending, uploadUrl, startedAt: now, updatedAt: now }
            await pendingUploads.put(record)
            return record
          }
        : undefined,
    },
    pending,
  })
  return {
    fileId: record.fileId,
    fileKey: record.fileKey,
    keyGeneration: record.keyGeneration,
    collectionId: opts.collection.id,
    contentSha256: hashed.digest(),
  }
}

/**
 * The plaintext, hashed as it is read. Encryption always reads it from the
 * start and in order (a pass that starts over reads it again from the
 * start), so each byte is hashed the first time it is read in sequence.
 */
export async function hashingSource(source: PlaintextSource): Promise<{ source: PlaintextSource; digest: () => string | null }> {
  const hasher = await newContentHasher()
  let hashedTo = 0
  let result: string | null | undefined
  return {
    source: {
      size: source.size,
      read: async (start, end) => {
        const bytes = await source.read(start, end)
        if (start === hashedTo && result === undefined) {
          hasher.update(bytes)
          hashedTo = start + bytes.length
        }
        return bytes
      },
    },
    digest: () => {
      if (result === undefined) result = hashedTo === source.size ? hasher.finish() : null
      return result
    },
  }
}

export interface ResumeUploadOptions {
  upload: PendingUpload
  /** The same file, chosen again (a page cannot open it by itself). */
  file: File
  /** The folder's key at the upload's `keyEpoch`. */
  collection: { id: string; keyEpoch: number; collectionKey: Uint8Array }
  accessToken: string | (() => Promise<string>)
  onProgress?: (plainSent: number, plainTotal: number) => void
  onWaiting?: (waiting: boolean) => void
  signal?: AbortSignal
}

/** The name an interrupted upload was for, read with its folder's key. */
export async function pendingUploadName(
  upload: PendingUpload,
  collectionKey: Uint8Array,
): Promise<FileMetadataV1> {
  const { metadata } = await openPendingRecord(upload, collectionKey)
  return metadata
}

function openPendingRecord(upload: PendingUpload, collectionKey: Uint8Array) {
  return openFileRecordV1(
    {
      id: upload.fileId,
      collectionId: upload.collectionId,
      keyEpoch: upload.keyEpoch,
      keyGeneration: 1,
      metadataRevision: 1,
      fileKeyEnvelope: upload.fileKeyEnvelope,
      metadataEnvelope: upload.metadataEnvelope,
    } as Parameters<typeof openFileRecordV1>[0],
    collectionKey,
  )
}

/**
 * Go on with an upload a reload or crash interrupted, from where the
 * server stopped. Rejects `NotTheSameFile` for another file,
 * `FolderKeyChanged` when the folder moved to a new key since, and
 * `UploadNoLongerOnServer` when the server no longer has it.
 */
export async function resumeUpload(opts: ResumeUploadOptions): Promise<UploadedFile> {
  const { upload } = opts
  if (opts.collection.id !== upload.collectionId) throw new Error('not the folder the upload started in')
  if (opts.collection.keyEpoch !== upload.keyEpoch) throw new FolderKeyChanged()
  const { fileKey, metadata } = await openPendingRecord(upload, opts.collection.collectionKey)
  if (!sameName(opts.file.name, metadata.name) || opts.file.size !== upload.size || opts.file.lastModified !== upload.lastModified) {
    throw new NotTheSameFile()
  }
  const context = { fileId: upload.fileId, generation: 1 }
  const prefix = fromBase64(upload.prefix)
  // The stored prefix must be this file's, under this key: Rust checks it.
  await resumeFileBlobStreamEncryptorV1(fileKey, context, prefix)
  // Going on re-encrypts what the server already holds from the start, so
  // the whole file is read (and hashed) here too.
  const hashed = await hashingSource(fileSource(opts.file))
  await send({
    ...opts,
    plaintext: hashed.source,
    fileId: upload.fileId,
    prefix,
    openStream: () => resumeFileBlobStreamEncryptorV1(fileKey, context, prefix),
    uploadUrl: upload.uploadUrl,
    pending: upload,
  })
  return { fileId: upload.fileId, fileKey, keyGeneration: 1, collectionId: upload.collectionId, contentSha256: hashed.digest() }
}

/**
 * The file chosen again is the one uploaded under `stored`: the same name,
 * or the name with the ` (2)` its folder's clash gave it ("Keep both").
 */
function sameName(chosen: string, stored: string): boolean {
  if (chosen === stored) return true
  const dot = stored.lastIndexOf('.')
  const [stem, extension] = dot > 0 ? [stored.slice(0, dot), stored.slice(dot)] : [stored, '']
  return `${stem.replace(/ \(\d+\)$/, '')}${extension}` === chosen
}

/** How long to wait before trying a lost connection again: growing, at most a minute. */
function backoff(attempt: number): number {
  return Math.min(60_000, 2_000 * 2 ** Math.min(attempt, 5))
}

function statusOf(error: unknown): number {
  const response = (error as { originalResponse?: { getStatus(): number } | null }).originalResponse
  return response ? response.getStatus() : 0
}

/** The refusal of a taken name (at create, or when the upload ends); null for anything else. */
function nameTakenOf(error: unknown): UploadNameTaken | null {
  const response = (error as { originalResponse?: { getStatus(): number; getBody(): string } | null }).originalResponse
  if (!response || response.getStatus() !== 409) return null
  try {
    const body = JSON.parse(response.getBody()) as { code?: string; holder?: UploadNameTaken['holder'] }
    if (body.code !== 'name_taken') return null
    const holder = body.holder
    return new UploadNameTaken(
      holder && (holder.kind === 'file' || holder.kind === 'folder') && typeof holder.id === 'string'
        ? { kind: holder.kind, id: holder.id, contentHash: holder.contentHash ?? null }
        : null,
    )
  } catch {
    return null
  }
}

/** A failure that waiting does not cure: the server refused, or the upload is gone. */
function isFinal(status: number): boolean {
  return status >= 400 && status < 500 && status !== 408 && status !== 409 && status !== 423 && status !== 429
}

interface SendOptions {
  file: File
  /** The file's bytes as encryption reads them. */
  plaintext: PlaintextSource
  fileId: string
  prefix: Uint8Array
  openStream: () => ReturnType<typeof resumeFileBlobStreamEncryptorV1>
  accessToken: string | (() => Promise<string>)
  onProgress?: (plainSent: number, plainTotal: number) => void
  onWaiting?: (waiting: boolean) => void
  signal?: AbortSignal
  /** A new upload: what the server records, and where to remember it. */
  create?: { metadata: Record<string, string>; remember?: (uploadUrl: string) => Promise<PendingUpload> }
  /** An upload that exists on the server already. */
  uploadUrl?: string
  /** The remembered upload, kept current and forgotten at the end. */
  pending: Pick<PendingUpload, 'fileId'> | null
}

async function send(opts: SendOptions): Promise<void> {
  const source = new EncryptedFileSource(opts.plaintext, opts.openStream, opts.prefix)
  const uploadsEndpoint = `${await resolveApiBase()}/uploads/`
  const plainTotal = opts.file.size
  let lastPlainSent = 0
  let lastRemembered = 0

  const report = (cipherAccepted: number) => {
    // Each message past the prefix is 17 bytes over its plaintext.
    if (cipherAccepted <= DRIVE_FILE_BLOB_PREFIX_BYTES) return
    const afterPrefix = cipherAccepted - DRIVE_FILE_BLOB_PREFIX_BYTES
    const plain = Math.min(plainTotal, afterPrefix - ABYTES * Math.ceil(afterPrefix / DRIVE_FILE_BLOB_CIPHER_CHUNK))
    if (plain > lastPlainSent) {
      lastPlainSent = plain
      opts.onProgress?.(plain, plainTotal)
    }
  }

  // The upload as remembered in this browser, kept current while it runs.
  let remembered: PendingUpload | null = opts.pending && 'uploadUrl' in opts.pending ? (opts.pending as PendingUpload) : null
  const forget = () => (opts.pending ? pendingUploads.remove(opts.pending.fileId).catch(() => undefined) : undefined)
  const touch = () => {
    // Written now and then, so a long upload is not taken for an abandoned one.
    if (!remembered || Date.now() - lastRemembered < 60_000) return
    lastRemembered = Date.now()
    remembered = { ...remembered, updatedAt: lastRemembered }
    void pendingUploads.put(remembered).catch(() => undefined)
  }

  const running = new Promise<void>((resolve, reject) => {
    let attempt = 0
    let finished = false
    let waitingTimer: ReturnType<typeof setTimeout> | null = null
    let waiting = false

    const setWaiting = (value: boolean) => {
      if (waiting === value) return
      waiting = value
      opts.onWaiting?.(value)
    }
    const finish = (error?: unknown) => {
      if (finished) return
      finished = true
      if (waitingTimer) clearTimeout(waitingTimer)
      window.removeEventListener('online', goOn)
      setWaiting(false)
      source.close()
      if (error) reject(error)
      else resolve()
    }

    // The file is only its name for tus: the bytes come from `source`.
    const upload = new tus.Upload(opts.file, {
      endpoint: opts.uploadUrl ? null : uploadsEndpoint,
      uploadUrl: opts.uploadUrl ?? null,
      uploadSize: source.size,
      // One message's length per PATCH: S3's 5-MiB minimum for every part
      // but the last; the prefix shifts the messages across requests.
      chunkSize: DRIVE_FILE_BLOB_CIPHER_CHUNK,
      fileReader: { openFile: async () => source },
      retryDelays: [0, 1000, 3000, 5000, 10000],
      // Resuming is ours (pendingUploads); tus's own needs a fingerprint of
      // the input, which a re-encrypted stream does not have.
      storeFingerprintForResuming: false,
      removeFingerprintOnSuccess: true,
      async onBeforeRequest(req) {
        const token = typeof opts.accessToken === 'function' ? await opts.accessToken() : opts.accessToken
        req.setHeader('Authorization', `Bearer ${token}`)
      },
      // An expired token is recoverable: the next attempt's onBeforeRequest
      // fetches a fresh one. Other client errors are not retried here.
      onShouldRetry(err, _attempt, options) {
        const status = statusOf(err)
        if (status === 401) return true
        if (isFinal(status) || nameTakenOf(err)) return false
        return (options.retryDelays?.length ?? 0) > 0
      },
      metadata: opts.create?.metadata ?? {},
      onUploadUrlAvailable() {
        const remember = opts.create?.remember
        if (!remember || !upload.url) return
        void remember(upload.url).then((record) => {
          remembered = record
          lastRemembered = record.updatedAt
        }).catch(() => undefined)
      },
      onProgress(bytesSent) {
        report(bytesSent)
      },
      // The Create response (201) echoes the file's id: it must be the one
      // this client made and sealed everything under.
      onAfterResponse(req, res) {
        if (req.getMethod() !== 'POST' || res.getStatus() !== 201) return
        let echoed: string | undefined
        try {
          echoed = (JSON.parse(res.getBody()) as { fileId?: string }).fileId
        } catch {
          echoed = undefined
        }
        if (echoed !== opts.fileId) {
          void upload.abort(true).catch(() => {})
          void forget()
          finish(new Error('the server answered for another file'))
        }
      },
      onChunkComplete(_chunkSize, bytesAccepted) {
        attempt = 0
        setWaiting(false)
        report(bytesAccepted)
        touch()
      },
      onError(err) {
        if (finished || opts.signal?.aborted) return
        const status = statusOf(err)
        // Someone else took the name meanwhile: the server discarded the upload.
        const taken = nameTakenOf(err)
        if (taken) {
          void forget()
          finish(taken)
          return
        }
        if (status === 404 || status === 410) {
          void forget()
          finish(opts.uploadUrl ? new UploadNoLongerOnServer() : err)
          return
        }
        if (isFinal(status)) {
          void forget()
          finish(err)
          return
        }
        // The connection is gone (or the server is): wait, then go on from
        // where the server stopped. tus asks it with HEAD.
        if (!waiting) console.warn('upload: waiting to go on', status, err instanceof Error ? err.message : err)
        setWaiting(true)
        const delay = backoff(attempt++)
        waitingTimer = setTimeout(goOn, navigator.onLine === false ? 60_000 : delay)
      },
      onSuccess() {
        // Report 100 % one final time: the final PATCH may be smaller than
        // the step between progress reports.
        opts.onProgress?.(plainTotal, plainTotal)
        void forget()
        finish()
      },
    })

    function goOn() {
      if (finished || !waiting) return
      if (waitingTimer) clearTimeout(waitingTimer)
      waitingTimer = null
      upload.start()
    }
    window.addEventListener('online', goOn)

    if (opts.signal) {
      const cancel = () => {
        // shouldTerminate=true → tus DELETE on the server, freeing the
        // reserved quota at once.
        void upload.abort(true).catch(() => {})
        void forget()
        finish(new DOMException('Upload aborted', 'AbortError'))
      }
      if (opts.signal.aborted) {
        cancel()
        return
      }
      opts.signal.addEventListener('abort', cancel, { once: true })
    }

    upload.start()
  })
  if (opts.pending) holdUpload(opts.pending.fileId, running)
  await running
}
