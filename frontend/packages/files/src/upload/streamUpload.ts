// streamUpload — E2EE streaming upload via the tus.io resumable protocol.
// Memory stays bounded at a few 4 MiB blocks whatever the file's size: the
// plaintext is read from File.slice() a block at a time, sealed in the block
// format (docs/plans/drive-block-format.md §2), and handed to tus-js-client
// as the exact ranges it sends (encryptedSource.ts).
//
// Every upload is a new content revision with an id this client picks. It
// lands on the server as an uploaded revision; once its last byte is there,
// the client commits it with the file's next metadata, which commits to the
// revision and its manifest's digest (known only after the last block):
// `POST /api/v1/drive/files/{id}/revisions/{revisionId}/commit` (commit.ts).
//
// An upload survives a long loss of the connection: it waits, and goes on
// from where the server stopped once the browser is back online. Started
// with `resumable`, it also survives a reload or a crash: what it needs to go
// on is kept in this browser (pendingUploads.ts, nothing readable without
// the folder key), and `resumeUpload` continues it once the same file is
// chosen again, sealing again what the server already holds rather than
// sending it, and commits it if that had not happened yet.
//
// Wire format (crates/kutup-server/src/handlers/tus.rs + the CLI):
//   POST  /api/v1/drive/uploads          — creates the upload (and a new file's key row)
//   HEAD  /api/v1/drive/uploads/<id>     — where an upload stands, to go on from there
//   PATCH /api/v1/drive/uploads/<id>     — appends bytes; the last leaves an uploaded revision
//   POST  /api/v1/drive/files/<id>/revisions/<revisionId>/commit — makes it current

import * as tus from 'tus-js-client'
import {
  createFileRecordV1,
  newDriveBlockEncryptor,
  newRevisionId,
  openFileKeyV1,
  openFileMetadataDraftV1,
  openFileMetadataV1,
  renameFileRecordV1,
  sealFileMetadataDraftV1,
  sealRevisionContent,
  type ContentCommitment,
  type FileMetadataDraftV1,
  type FileMetadataV2,
  type MediaMetadataV1,
} from '@kutup/crypto'
import { hashBlob } from '@kutup/crypto/contentHash'
import { resolveApiBase } from '@kutup/session/apiBase'
import { clientFetch, clientHeaders, latchClientTooOld } from '@kutup/session/clientVersion'
import { DRIVE_BLOCK_SIZE } from '@kutup/crypto/driveBlocks'
import { commitRevision, conflictCode, manifestSigner } from './commit'
import { EncryptedFileSource, fileSource, loadTail, NotTheSameFile, storeTail, type PlaintextSource, type SealedBlockLog, type SealedTail } from './encryptedSource'

export { NotTheSameFile }
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
  nameHash: string
  /**
   * SHA-256 of the plaintext (base64), when the caller has it already;
   * otherwise the file is read once to work it out before it is sealed
   * into the metadata.
   */
  sha256?: string
  /** What to do when the name is taken by the time the upload commits. */
  freeName?: FreeName
}

/**
 * The name to commit a new file under when its own was taken while it
 * uploaded (`409 name_taken` at the commit): the next free one in its
 * folder and its hash, as a "Keep both" picks it. The bytes stay as they
 * are; only the metadata and the name hash change.
 */
export type FreeName = (taken: string) => Promise<{ name: string; nameHash: string }>

/** What an upload made: enough to seal things beside it (a thumbnail). */
export interface UploadedFile {
  fileId: string
  fileKey: Uint8Array
  /** A new file's key is generation 1; a new version is sealed at the file's current one. */
  keyGeneration: number
  /** The content revision the upload made current: what its thumbnails are bound to. */
  revisionId: string
  /** A new version of an existing file (its metadata landed with its commit). */
  version?: boolean
  /** That version's id: its revision's. */
  versionId?: string
  collectionId: string
  /** SHA-256 of the plaintext (base64), as sealed in its metadata; null if it has none. */
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

/**
 * A new version was refused because the file changed since it was chosen
 * (docs/api.md, "POST /api/v1/drive/uploads with versionOf"): another version
 * (`version`), its metadata (`revision`), or its key (`key`). The server
 * discarded the upload; sending it again as it was would only fail again.
 */
export class VersionConflict extends Error {
  constructor(readonly kind: 'version' | 'revision' | 'key') {
    super('the file changed since this upload started')
  }
}

/**
 * Another upload of a new version of this file is open: this account's
 * (`uploadId`, to go on with or cancel), or someone else's (null), with
 * the seconds since its last part arrived (null when not said).
 */
export class VersionUploading extends Error {
  constructor(
    readonly uploadId: string | null,
    readonly idleSeconds: number | null = null,
    /** True: this account uploads it (it may go on); false with an id: the folder's owner, who may cancel it. */
    readonly yours = false,
  ) {
    super('a new version of this file is being uploaded')
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

/** What an upload's draft says, from a file and its details. */
function draftOf(file: File, sha256: string, media?: MediaMetadataV1): FileMetadataDraftV1 {
  const draft: FileMetadataDraftV1 = {
    name: file.name,
    mimeType: file.type || 'application/octet-stream',
    size: file.size,
    sha256,
  }
  if (media) draft.media = media
  return draft
}

/** What the browser keeps of an upload, before the server names it. */
type PendingDraft = Omit<PendingUpload, 'uploadUrl' | 'startedAt' | 'updatedAt'>

/**
 * Encrypt and upload a File as a new file, and commit it. Resolves with the
 * new file's id and key (the id is client-generated and confirmed by the
 * server).
 */
export async function streamUpload(opts: StreamUploadOptions): Promise<UploadedFile> {
  // The content's SHA-256 goes into the sealed metadata (never to the
  // server as such): a move works the folder's content hash out from it.
  const sha256 = opts.sha256 ?? (await hashBlob(opts.file, opts.signal))
  const draft = draftOf(opts.file, sha256, opts.media)
  const record = await createFileRecordV1(opts.collection.id, opts.collection.keyEpoch, opts.collection.collectionKey)
  const revisionId = newRevisionId()
  const pending: PendingDraft | null = opts.resumable
    ? {
        fileId: record.fileId,
        owner: opts.resumable.owner,
        size: opts.file.size,
        lastModified: opts.file.lastModified,
        collectionId: opts.collection.id,
        keyEpoch: opts.collection.keyEpoch,
        fileKeyEnvelope: record.fileKeyEnvelope,
        revisionId,
        draftEnvelope: await sealFileMetadataDraftV1(record.fileId, record.keyGeneration, revisionId, record.fileKey, draft),
      }
    : null
  const sent = await send({
    ...opts,
    plaintext: fileSource(opts.file),
    fileId: record.fileId,
    fileKey: record.fileKey,
    revisionId,
    generation: record.keyGeneration,
    sha256,
    create: {
      metadata: {
        fileId: record.fileId,
        collectionId: opts.collection.id,
        fileKeyEnvelope: record.fileKeyEnvelope,
        nameHash: opts.nameHash,
        revisionId,
      },
      pending,
    },
    pending,
  })
  await commitUpload({
    fileId: record.fileId,
    fileKey: record.fileKey,
    keyGeneration: record.keyGeneration,
    revisionId,
    content: sent.content,
    draft,
    base: null,
    uploadUrl: sent.uploadUrl,
    accessToken: opts.accessToken,
    pending,
    freeName: opts.freeName,
  })
  return {
    fileId: record.fileId,
    fileKey: record.fileKey,
    keyGeneration: record.keyGeneration,
    revisionId,
    collectionId: opts.collection.id,
    contentSha256: sha256,
  }
}

/** The file a new version is for, as it is now (re-keyed to its folder's epoch first). */
export interface VersionTarget {
  fileId: string
  collectionId: string
  /** The folder epoch its key is wrapped at, and that wrap. */
  keyEpoch: number
  fileKeyEnvelope: string
  /** Its current key and that key's generation: the new content is sealed under it. */
  fileKey: Uint8Array
  keyGeneration: number
  /** Its metadata revision now: the commit seals the next. */
  metadataRevision: number
}

export interface StreamVersionOptions {
  file: File
  target: VersionTarget
  /** What the file's new metadata says (its name as it is, the new size and `sha256`); the commit adds the content. */
  metadata: FileMetadataDraftV1
  /** The new content's hash in its folder, recorded as the version lands. */
  contentHash?: string
  /** Stored only while the file still holds this version (an id, or `original`). */
  basedOn?: string
  accessToken: string | (() => Promise<string>)
  onProgress?: (plainSent: number, plainTotal: number) => void
  onWaiting?: (waiting: boolean) => void
  signal?: AbortSignal
  resumable?: { owner: string }
}

/** The tus `Upload-Metadata` of a new version (exported for tests). */
export function versionUploadMetadata(
  target: Pick<VersionTarget, 'fileId'>,
  revisionId: string,
  opts: Pick<StreamVersionOptions, 'contentHash' | 'basedOn'>,
): Record<string, string> {
  const metadata: Record<string, string> = { versionOf: target.fileId, revisionId }
  if (opts.contentHash) metadata.contentHash = opts.contentHash
  if (opts.basedOn) metadata.basedOn = opts.basedOn
  return metadata
}

/**
 * Upload `file` as the newest version of an existing file, over tus like a
 * new file — resumable after a reload, at any size — sealed for the file at
 * its current key generation, then committed with its next metadata
 * (Proton's revisions; docs/api.md). A file changed meanwhile rejects
 * `VersionConflict`; another open upload of a version of it,
 * `VersionUploading`.
 */
export async function streamVersionUpload(opts: StreamVersionOptions): Promise<UploadedFile> {
  const { target } = opts
  const revisionId = newRevisionId()
  const pending: PendingDraft | null = opts.resumable
    ? {
        fileId: target.fileId,
        owner: opts.resumable.owner,
        size: opts.file.size,
        lastModified: opts.file.lastModified,
        collectionId: target.collectionId,
        keyEpoch: target.keyEpoch,
        fileKeyEnvelope: target.fileKeyEnvelope,
        revisionId,
        draftEnvelope: await sealFileMetadataDraftV1(target.fileId, target.keyGeneration, revisionId, target.fileKey, opts.metadata),
        version: { keyGeneration: target.keyGeneration, metadataRevision: target.metadataRevision },
      }
    : null
  const sent = await send({
    ...opts,
    plaintext: fileSource(opts.file),
    fileId: target.fileId,
    fileKey: target.fileKey,
    revisionId,
    generation: target.keyGeneration,
    sha256: opts.metadata.sha256,
    create: { metadata: versionUploadMetadata(target, revisionId, opts), pending },
    pending,
  })
  await commitUpload({
    fileId: target.fileId,
    fileKey: target.fileKey,
    keyGeneration: target.keyGeneration,
    revisionId,
    content: sent.content,
    draft: opts.metadata,
    base: { metadataRevision: target.metadataRevision, collectionId: target.collectionId },
    uploadUrl: sent.uploadUrl,
    accessToken: opts.accessToken,
    pending,
  })
  return {
    fileId: target.fileId,
    fileKey: target.fileKey,
    keyGeneration: target.keyGeneration,
    revisionId,
    collectionId: target.collectionId,
    contentSha256: opts.metadata.sha256 ?? null,
    version: true,
    versionId: revisionId,
  }
}

interface CommitUploadOptions {
  fileId: string
  fileKey: Uint8Array
  keyGeneration: number
  revisionId: string
  content: ContentCommitment
  draft: FileMetadataDraftV1
  /** A version: the metadata revision it started from and the folder to read the file again from; null for a new file. */
  base: { metadataRevision: number; collectionId: string } | null
  uploadUrl: string
  accessToken: string | (() => Promise<string>)
  pending: Pick<PendingUpload, 'fileId'> | null
  /** A new file whose name was taken meanwhile commits under the one this gives. */
  freeName?: FreeName
}

/** How many other names a new file's commit tries when its name keeps being taken. */
const MAX_COMMIT_RENAMES = 3

/**
 * Commits an uploaded revision with the file's next metadata. A version
 * whose file was renamed meanwhile keeps the new name. A new file whose
 * name was taken while it uploaded commits under the next free name
 * (`freeName`), without sending anything again. A refusal (the name was
 * taken and no other is given, the file changed) cancels the upload,
 * freeing its quota; a failure to reach the server keeps the browser's
 * record, so `resumeUpload` commits it later.
 */
async function commitUpload(opts: CommitUploadOptions): Promise<void> {
  let draft = opts.draft
  let nameHash: string | undefined
  for (let renames = 0; ; renames++) {
    try {
      await commitOnce(opts, draft, nameHash)
      return
    } catch (error) {
      const taken = error instanceof UploadNameTaken
      if (!taken || opts.base || !opts.freeName || renames >= MAX_COMMIT_RENAMES) {
        await settleCommitError(opts, error)
        throw error
      }
      const free = await opts.freeName(draft.name).catch(async (failed: unknown) => {
        await settleCommitError(opts, error)
        throw failed
      })
      draft = { ...draft, name: free.name }
      nameHash = free.nameHash
    }
  }
}

/** `draft` naming the original upload and the saved state `current` names (and nothing `current` doesn't). */
function withRevisionsOf(draft: FileMetadataDraftV1, current: FileMetadataV2): FileMetadataDraftV1 {
  const { originalRevisionId: _original, stateRevisionId: _state, ...rest } = draft
  void _original
  void _state
  return {
    ...rest,
    ...(current.originalRevisionId ? { originalRevisionId: current.originalRevisionId } : {}),
    ...(current.stateRevisionId ? { stateRevisionId: current.stateRevisionId } : {}),
  }
}

/** One commit of the revision with `draft` (and a new name's hash). */
async function commitOnce(opts: CommitUploadOptions, baseDraft: FileMetadataDraftV1, nameHash: string | undefined): Promise<void> {
  // What the revision is, sealed with it: its content record goes up with
  // the commit, so it opens against a committed digest once in the history.
  const revisionContentEnvelope = await sealRevisionContent(
    opts.fileKey,
    { fileId: opts.fileId, revisionId: opts.revisionId, generation: opts.keyGeneration },
    opts.content,
    opts.draft.size,
  )
  try {
    await commitRevision({
      fileId: opts.fileId,
      revisionId: opts.revisionId,
      revisionContentEnvelope,
      nameHash,
      metadataRevision: opts.base?.metadataRevision ?? 0,
      collectionId: opts.base?.collectionId ?? null,
      seal: async ({ metadataRevision, row }) => {
        let draft = baseDraft
        if (row) {
          // Someone wrote the file meanwhile: on top of what it is now.
          if (row.keyGeneration !== opts.keyGeneration) throw new VersionConflict('key')
          const current = await openFileMetadataV1(row, opts.fileKey)
          draft = withRevisionsOf({ ...draft, name: current.name }, current)
        }
        // A new file's first commit names its original upload; a version
        // carries the one the file has (docs/plans/drive-block-format.md §2).
        const named = opts.base ? draft : { ...draft, originalRevisionId: opts.revisionId }
        return renameFileRecordV1(
          { id: opts.fileId, keyGeneration: opts.keyGeneration, metadataRevision },
          opts.fileKey,
          { ...named, content: opts.content },
        )
      },
    })
  } catch (error) {
    if (error instanceof VersionConflict) throw error
    const status = (error as { response?: { status?: number } }).response?.status ?? 0
    throw refusalFromBody(status, (error as { response?: { data?: unknown } }).response?.data) ?? error
  }
  if (opts.pending) await pendingUploads.remove(opts.pending.fileId).catch(() => undefined)
}

/**
 * After a commit failed for good: a refusal (the name was taken, the file
 * changed) or a final status cancels the upload, freeing its quota, and
 * forgets the browser's record; anything else keeps both, to commit later.
 */
async function settleCommitError(opts: CommitUploadOptions, error: unknown): Promise<void> {
  const status = (error as { response?: { status?: number } }).response?.status ?? 0
  const refused = error instanceof UploadNameTaken || error instanceof VersionConflict || error instanceof VersionUploading
  // The object is gone from storage: the upload can never be committed.
  const lost = conflictCode(error) === 'objectMissing'
  if (refused || lost || isFinal(status)) {
    await terminate(opts.uploadUrl, opts.accessToken)
    if (opts.pending) await pendingUploads.remove(opts.pending.fileId).catch(() => undefined)
  }
}

/** Cancels an upload on the server (tus DELETE): an uploaded revision that will not be committed, and its quota. */
async function terminate(uploadUrl: string, accessToken: string | (() => Promise<string>)): Promise<void> {
  try {
    const token = typeof accessToken === 'function' ? await accessToken() : accessToken
    await clientFetch(uploadUrl, { method: 'DELETE', headers: { 'Tus-Resumable': '1.0.0', Authorization: `Bearer ${token}` } })
  } catch {
    // The sweep removes it with the abandoned uploads.
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
  /** A new file whose name was taken meanwhile commits under the one this gives. */
  freeName?: FreeName
}

/** What an interrupted upload's metadata will say (its name), read with its folder's key. */
export async function pendingUploadName(
  upload: PendingUpload,
  collectionKey: Uint8Array,
): Promise<FileMetadataDraftV1> {
  const { draft } = await openPendingRecord(upload, collectionKey)
  return draft
}

async function openPendingRecord(upload: PendingUpload, collectionKey: Uint8Array) {
  const keyGeneration = upload.version?.keyGeneration ?? 1
  const fileKey = await openFileKeyV1(
    {
      id: upload.fileId,
      collectionId: upload.collectionId,
      keyEpoch: upload.keyEpoch,
      keyGeneration,
      fileKeyEnvelope: upload.fileKeyEnvelope,
    },
    collectionKey,
  )
  const draft = await openFileMetadataDraftV1(upload.draftEnvelope, upload.fileId, keyGeneration, upload.revisionId, fileKey)
  return { fileKey, keyGeneration, draft }
}

/**
 * Go on with an upload a reload or crash interrupted, from where the
 * server stopped, and commit it. Rejects `NotTheSameFile` for another file,
 * `FolderKeyChanged` when the folder moved to a new key since, and
 * `UploadNoLongerOnServer` when the server no longer has it.
 */
export async function resumeUpload(opts: ResumeUploadOptions): Promise<UploadedFile> {
  const { upload } = opts
  if (opts.collection.id !== upload.collectionId) throw new Error('not the folder the upload started in')
  if (opts.collection.keyEpoch !== upload.keyEpoch) throw new FolderKeyChanged()
  const { fileKey, keyGeneration, draft } = await openPendingRecord(upload, opts.collection.collectionKey)
  if (!sameName(opts.file.name, draft.name) || opts.file.size !== upload.size || opts.file.lastModified !== upload.lastModified) {
    throw new NotTheSameFile()
  }
  const kept = upload.tail ? loadTail(upload.tail) : undefined
  if (kept && kept.content.revisionId !== upload.revisionId) throw new Error('the kept tail is for another revision')
  let content: ContentCommitment
  try {
    const sent = await send({
      ...opts,
      plaintext: fileSource(opts.file),
      fileId: upload.fileId,
      fileKey,
      revisionId: upload.revisionId,
      generation: keyGeneration,
      // The file chosen again is checked by its content, not only its name,
      // size and date: its SHA-256 as it is sealed again, or (a draft
      // without one) its blocks against the ones sealed before.
      sha256: draft.sha256,
      tail: kept,
      uploadUrl: upload.uploadUrl,
      pending: upload,
    })
    content = sent.content
  } catch (error) {
    // Every byte had arrived and the commit may have landed before the
    // record was forgotten: committing again settles it either way.
    if (!(error instanceof UploadNoLongerOnServer) || !kept) throw error
    content = kept.content
  }
  await commitUpload({
    fileId: upload.fileId,
    fileKey,
    keyGeneration,
    revisionId: upload.revisionId,
    content,
    draft,
    base: upload.version ? { metadataRevision: upload.version.metadataRevision, collectionId: upload.collectionId } : null,
    uploadUrl: upload.uploadUrl,
    accessToken: opts.accessToken,
    pending: upload,
    freeName: opts.freeName,
  }).catch((error: unknown) => {
    // Nothing to commit any more: the upload is gone.
    if ((error as { response?: { status?: number } }).response?.status === 404) throw new UploadNoLongerOnServer()
    throw error
  })
  return {
    fileId: upload.fileId,
    fileKey,
    keyGeneration,
    revisionId: upload.revisionId,
    collectionId: upload.collectionId,
    contentSha256: draft.sha256 ?? null,
    ...(upload.version ? { version: true, versionId: upload.revisionId } : {}),
  }
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

type RefusalBody = { code?: unknown; error?: unknown; uploadId?: unknown; idleSeconds?: unknown; yours?: unknown; holder?: unknown }

/** A 409's body, from tus (text) or the API client (parsed). */
function bodyOf(body: unknown): RefusalBody | null {
  if (typeof body === 'string') {
    try {
      const parsed: unknown = JSON.parse(body)
      return parsed && typeof parsed === 'object' ? (parsed as RefusalBody) : null
    } catch {
      return null
    }
  }
  return body && typeof body === 'object' ? (body as RefusalBody) : null
}

/**
 * What a 409 refuses, at create, when the upload ends or at the commit:
 * the name is taken, or the file changed (or another version of it is being
 * uploaded); null for anything else.
 */
function refusalFromBody(status: number, raw: unknown): UploadNameTaken | VersionConflict | VersionUploading | null {
  if (status !== 409) return null
  const body = bodyOf(raw)
  if (!body) return null
  if (body.code === 'name_taken') {
    const holder = body.holder as { kind?: unknown; id?: unknown; contentHash?: unknown } | null | undefined
    return new UploadNameTaken(
      holder && (holder.kind === 'file' || holder.kind === 'folder') && typeof holder.id === 'string'
        ? { kind: holder.kind, id: holder.id, contentHash: typeof holder.contentHash === 'string' ? holder.contentHash : null }
        : null,
    )
  }
  if (body.code === 'version_conflict') return new VersionConflict('version')
  if (body.code === 'revision_conflict') return new VersionConflict('revision')
  if (body.code === 'versionUploading') {
    return new VersionUploading(
      typeof body.uploadId === 'string' ? body.uploadId : null,
      typeof body.idleSeconds === 'number' ? body.idleSeconds : null,
      body.yours === true,
    )
  }
  if (body.error === 'file key changed' || body.error === 'file needs a re-key') return new VersionConflict('key')
  return null
}

function tusResponse(error: unknown): { status: number; body: string } | null {
  const response = (error as { originalResponse?: { getStatus(): number; getBody(): string } | null }).originalResponse
  return response ? { status: response.getStatus(), body: response.getBody() } : null
}

/** A new version's refusal (at create, or when the upload ends); null for anything else (exported for tests). */
export function versionRefusalOf(error: unknown): VersionConflict | VersionUploading | null {
  const response = tusResponse(error)
  const refused = response ? refusalFromBody(response.status, response.body) : null
  return refused instanceof UploadNameTaken ? null : refused
}

/** A refusal that settles the upload: the name is taken, or the file changed. */
function refusalOf(error: unknown): Error | null {
  const response = tusResponse(error)
  return response ? refusalFromBody(response.status, response.body) : null
}

/**
 * What a failed request means for an upload (exported for tests):
 * - `refused`: the name is taken or the file changed (the server discarded
 *   the upload); an open version upload refusing ours at create keeps the
 *   record this browser has of that one (same file id);
 * - `gone`: a remembered upload the server no longer has;
 * - `final`: a refusal waiting does not cure — among them a 403 when the
 *   writer lost access mid-upload (the server already discarded it);
 * - `wait`: the connection (or the server) is away: go on later.
 * Everything but `wait` forgets the remembered upload unless said.
 */
export function settleUploadError(
  status: number,
  refused: Error | null,
  resuming: boolean,
): { kind: 'refused' | 'gone' | 'final' | 'wait'; forget: boolean } {
  if (refused) return { kind: 'refused', forget: !(refused instanceof VersionUploading) }
  if (status === 404 || status === 410) return { kind: resuming ? 'gone' : 'final', forget: true }
  if (isFinal(status)) return { kind: 'final', forget: true }
  return { kind: 'wait', forget: false }
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
  /** The key, revision and generation the object is sealed for. */
  fileKey: Uint8Array
  revisionId: string
  generation: number
  /** The tail made before (a resumed upload's, kept by the browser). */
  tail?: SealedTail
  /**
   * The plaintext's SHA-256 the metadata will carry, when it carries one:
   * the content is hashed again as it is sealed and must be the same, or
   * the upload is discarded (`NotTheSameFile`). Without one, the sealed
   * blocks are kept in the browser's record and compared when sealed again.
   */
  sha256?: string
  accessToken: string | (() => Promise<string>)
  onProgress?: (plainSent: number, plainTotal: number) => void
  onWaiting?: (waiting: boolean) => void
  signal?: AbortSignal
  /** A new upload: what the server records, and what to remember of it once it has a URL. */
  create?: { metadata: Record<string, string>; pending: PendingDraft | null }
  /** An upload that exists on the server already. */
  uploadUrl?: string
  /** The remembered upload, kept current while it runs. */
  pending: Pick<PendingUpload, 'fileId'> | null
}

/** The upload's id, the last part of its URL. */
export function uploadIdOf(uploadUrl: string): string {
  return uploadUrl.split('/').filter(Boolean).at(-1) ?? ''
}

/** How many bytes a PATCH carries: two sealed blocks, above S3's 5-MiB minimum for every part but the last. */
const PATCH_BLOCKS = 2

/**
 * Sends the upload; resolves, once every byte is on the server, with its
 * URL and what the metadata commits to. The browser's record (if any) is
 * kept: the commit forgets it.
 */
async function send(opts: SendOptions): Promise<{ uploadUrl: string; content: ContentCommitment }> {
  const signer = await manifestSigner()
  const open = () => newDriveBlockEncryptor(opts.fileKey, { fileId: opts.fileId, revisionId: opts.revisionId, generation: opts.generation }, opts.plaintext.size)
  const first = await open()
  const header = first.header.length
  const stride = first.sealedOffset(1) - first.sealedOffset(0)

  // The upload as remembered in this browser, kept current while it runs.
  let remembered: PendingUpload | null = opts.pending && 'uploadUrl' in opts.pending ? (opts.pending as PendingUpload) : null
  let remembering: Promise<void> = Promise.resolve()
  let lastRemembered = remembered?.updatedAt ?? 0
  const forget = () => (opts.pending ? pendingUploads.remove(opts.pending.fileId).catch(() => undefined) : undefined)
  const keep = (record: PendingUpload) => {
    remembered = record
    lastRemembered = record.updatedAt
    remembering = remembering.then(() => pendingUploads.put(record)).catch(() => undefined)
    return remembering
  }
  const touch = () => {
    // Written now and then, so a long upload is not taken for an abandoned one.
    if (!remembered || Date.now() - lastRemembered < 60_000) return
    void keep({ ...remembered, updatedAt: Date.now() })
  }

  // No SHA-256 to check the content by: the blocks sealed so far, kept in
  // the record before each goes out.
  const known = [...(remembered?.sealedBlocks ?? [])]
  const blocks: SealedBlockLog | undefined =
    opts.sha256 || !opts.pending
      ? undefined
      : {
          known,
          record: async (index, hash) => {
            known[index] = hash
            await remembering
            if (remembered) await pendingUploads.put((remembered = { ...remembered, sealedBlocks: known.slice(), updatedAt: Date.now() }))
          },
        }

  const source = new EncryptedFileSource(opts.plaintext, first, {
    open,
    signer,
    sha256: opts.sha256,
    blocks,
    tail: opts.tail,
    onTail: async (made) => {
      // The record must hold the tail before any of it is sent.
      await remembering
      if (remembered) await pendingUploads.put((remembered = { ...remembered, tail: storeTail(made), updatedAt: Date.now() }))
    },
  })
  const uploadsEndpoint = `${await resolveApiBase()}/drive/uploads/`
  const plainTotal = opts.file.size
  let lastPlainSent = 0

  const report = (accepted: number) => {
    // Each block is `overhead` bytes over its plaintext; the header and the tail carry none.
    if (accepted <= header) return
    const sealed = accepted - header
    const blockOverhead = stride - DRIVE_BLOCK_SIZE
    const plain = Math.max(0, Math.min(plainTotal, sealed - blockOverhead * Math.ceil(sealed / stride)))
    if (plain > lastPlainSent) {
      lastPlainSent = plain
      opts.onProgress?.(plain, plainTotal)
    }
  }

  const running = new Promise<{ uploadUrl: string; content: ContentCommitment }>((resolve, reject) => {
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
      const content = source.content
      source.close()
      if (error) reject(error)
      else if (!content) reject(new Error('the upload ended before its tail was made'))
      else resolve({ uploadUrl: upload.url ?? opts.uploadUrl ?? '', content })
    }

    // The file is only its name for tus: the bytes come from `source`.
    const upload = new tus.Upload(opts.file, {
      endpoint: opts.uploadUrl ? null : uploadsEndpoint,
      uploadUrl: opts.uploadUrl ?? null,
      uploadSize: source.size,
      chunkSize: PATCH_BLOCKS * stride,
      fileReader: { openFile: async () => source },
      retryDelays: [0, 1000, 3000, 5000, 10000],
      // Resuming is ours (pendingUploads); tus's own needs a fingerprint of
      // the input, which a re-encrypted stream does not have.
      storeFingerprintForResuming: false,
      removeFingerprintOnSuccess: true,
      async onBeforeRequest(req) {
        const token = typeof opts.accessToken === 'function' ? await opts.accessToken() : opts.accessToken
        req.setHeader('Authorization', `Bearer ${token}`)
        for (const [name, value] of Object.entries(clientHeaders())) req.setHeader(name, value)
      },
      // An expired token is recoverable: the next attempt's onBeforeRequest
      // fetches a fresh one. Other client errors are not retried here.
      onShouldRetry(err, _attempt, options) {
        if (source.wrongFile) return false
        const status = statusOf(err)
        if (status === 401) return true
        if (isFinal(status) || refusalOf(err)) return false
        return (options.retryDelays?.length ?? 0) > 0
      },
      metadata: opts.create?.metadata ?? {},
      onUploadUrlAvailable() {
        const pending = opts.create?.pending
        if (!pending || !upload.url) return
        const now = Date.now()
        void keep({ ...pending, uploadUrl: upload.url, startedAt: now, updatedAt: now })
      },
      onProgress(bytesSent) {
        report(bytesSent)
      },
      // The Create response (201) echoes the file's id: it must be the one
      // this client made and sealed everything under.
      onAfterResponse(req, res) {
        if (res.getStatus() === 426) latchClientTooOld()
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
        if (source.wrongFile) {
          // Not the file the upload started with. Caught before any of it
          // went out, the upload stays as it was, to go on with the right
          // file; otherwise blocks of the other file may be on the server,
          // and the upload is discarded with its record.
          if (source.wrongFile === 'sent') {
            void upload.abort(true).catch(() => {})
            void forget()
          }
          finish(new NotTheSameFile())
          return
        }
        const settled = settleUploadError(statusOf(err), refusalOf(err), Boolean(opts.uploadUrl))
        if (settled.kind !== 'wait') {
          if (settled.forget) void forget()
          finish(settled.kind === 'refused' ? refusalOf(err) : settled.kind === 'gone' ? new UploadNoLongerOnServer() : err)
          return
        }
        const status = statusOf(err)
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
        // The record stays until the revision is committed.
        opts.onProgress?.(plainTotal, plainTotal)
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
  return running
}
