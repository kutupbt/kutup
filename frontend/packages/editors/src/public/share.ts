// A public link (docs/plans/drive-file-sharing.md): a folder's files or one
// file, readable without an account. Everything is opened here with the key
// from the link's fragment; the server only ever serves ciphertext. Drive
// lists a folder's link, Office shows a document reached by one.

import {
  fromBase64,
  openDriveObject,
  openFileMetadataV1,
  openFileRecordV1,
  openPublicLinkCollectionKeyV1,
  openPublicLinkFileKeyV1,
  resolveServed,
  REVISION_CONTENT_HEADER,
  REVISION_HEADER,
  type ContentCommitment,
  type DriveObjectExpected,
} from '@kutup/crypto'
import { unlockCollectionKeyring, type EpochLinkV1 } from '@kutup/crypto/collectionKeyring'
import { fileKeyAtV1 } from '@kutup/crypto/fileKeyring'
import { editorKindFor } from '@kutup/drive-core/editorKind'
import { openPublicPlayback, type Playback, type PlaybackFallback } from '@kutup/drive-core/playback'
import { fetchDecryptedChunks } from '@kutup/files/download/fetchDecrypt'
import { streamDownload } from '@kutup/files/download/streamDownload'
import { driveStreamLimits } from '@kutup/files/stream/limits'
import { isListName, stateToListJson } from '@kutup/map/list'
import { resolveApiBase } from '@kutup/session/apiBase'
import type { FileKeyHistoryEntry } from '@kutup/session/api-types'
import api from '@kutup/session/client'
import { getAccessToken } from '@kutup/session/store'
import { apiErrorCode } from '@kutup/ui/lib/apiError'

interface ShareInfo {
  /** 'collection': a folder's files; 'file': one file (docs/plans/drive-file-sharing.md). */
  shareType: 'collection' | 'file'
  targetId: string
  collectionKeyEnvelope: string
  collectionKeyEpoch: number
  ownerAccountId: string
  /** Who shared it (`alice@example.org`): the page says so. */
  ownerAccount: string
  /** Signs the folder's key history. */
  ownerAuthorityPublicKey: string
  expiresAt?: string | null
  /** A link to one file: the file (its key is `collectionKeyEnvelope`, of generation `collectionKeyEpoch`). */
  file?: PublicFileRow
}

export interface PublicFileRow {
  id: string
  collectionId: string
  metadataEnvelope: string
  fileKeyEnvelope: string
  keyEpoch: number
  keyGeneration: number
  metadataRevision: number
  createdAt: string
  /** The key generation of what a download serves (docs/plans/drive-move.md). */
  contentKeyGeneration: number
  keyHistory?: FileKeyHistoryEntry[]
}

export interface PublicFile {
  row: PublicFileRow
  /** The key the downloaded content opens with (of `row.contentKeyGeneration`). */
  fileKey: Uint8Array | null
  /** The file's current key (of `row.keyGeneration`), to reach any older one. */
  currentKey: Uint8Array | null
  name: string | null
  mimeType: string
  size: number
  /** The current content its metadata commits to (docs/plans/drive-block-format.md §2); null when it did not open. */
  content: ContentCommitment | null
  /** A note's or place list's latest saved state, as its metadata names it; null when none (or it did not open). */
  stateRevisionId: string | null
}

export interface PublicShare {
  shareType: 'collection' | 'file'
  /** Who shared it (`alice@example.org`). */
  ownerAccount: string
  /** The folder's files, or the one file. */
  files: PublicFile[]
}

export type PublicFailure =
  | 'missingKey'
  | 'notFound'
  | 'expired'
  | 'removed'
  | 'blocked'
  | 'blockedLegal'
  | 'sharingOff'
  | 'signInRequired'
  | 'badKey'
  | 'waiting'
  | 'other'

export class PublicLinkError extends Error {
  constructor(readonly failure: PublicFailure) {
    super(failure)
  }
}

/** Why a link did not open, for the page to say. */
export function publicFailure(error: unknown): PublicFailure {
  return error instanceof PublicLinkError ? error.failure : 'other'
}

/** The key lives only in the fragment (`#key=…`), which browsers never send to a server. */
export function linkKey(): Uint8Array | null {
  try {
    const key = new URLSearchParams(window.location.hash.slice(1)).get('key')
    const bytes = key ? fromBase64(key) : null
    return bytes && bytes.length === 32 ? bytes : null
  } catch {
    return null
  }
}

/**
 * Why the server refused a link: unknown, expired, or taken down (by an
 * administrator, or with its owner's account: `410` `link_removed`).
 */
export function linkFailure(error: unknown): PublicFailure {
  const response = (error as { response?: { status?: number; data?: { code?: unknown } } }).response
  // The server's controls on public links (docs/plans/server-personal-data.md, A11).
  const code = response?.data?.code
  if (code === 'link_blocked') return response?.status === 451 ? 'blockedLegal' : 'blocked'
  if (code === 'sharing_off') return 'sharingOff'
  if (code === 'sign_in_required') return 'signInRequired'
  if (apiErrorCode(error) === 'not_found') return 'notFound'
  if (response?.status !== 410) return 'other'
  return response.data?.code === 'link_removed' ? 'removed' : 'expired'
}

const shareBase = (token: string) => `/drive/public-links/${encodeURIComponent(token)}`

/**
 * The viewer's own sign-in, when they have one here: a server whose links
 * open only for signed-in viewers asks for it on every request
 * (docs/plans/server-personal-data.md, A11). Anyone else is anonymous.
 */
export function viewerToken(): string {
  return getAccessToken() ?? ''
}

export async function loadShare(token: string): Promise<PublicShare> {
  const key = linkKey()
  if (!key) throw new PublicLinkError('missingKey')
  let share: ShareInfo
  try {
    share = (await api.get<ShareInfo>(shareBase(token))).data
  } catch (error) {
    throw new PublicLinkError(linkFailure(error))
  }
  if (share.expiresAt && Date.parse(share.expiresAt) < Date.now()) throw new PublicLinkError('expired')
  const files = share.shareType === 'file' ? [await loadFile(share, key)] : await loadFolder(token, share, key)
  return { shareType: share.shareType, ownerAccount: share.ownerAccount, files }
}

async function loadFolder(token: string, share: ShareInfo, key: Uint8Array): Promise<PublicFile[]> {
  let collectionKey: Uint8Array
  try {
    collectionKey = await openPublicLinkCollectionKeyV1(share.collectionKeyEnvelope, key, {
      collectionId: share.targetId,
      ownerAccountId: share.ownerAccountId,
      epoch: share.collectionKeyEpoch,
    })
  } catch {
    throw new PublicLinkError('badKey')
  }
  // Older folder keys, for files stored before the folder's last rotation:
  // unlocked through its owner-signed history, fetched only if needed.
  let keyring: Promise<Uint8Array[]> | null = null
  const keyAt = (epoch: number): Promise<Uint8Array> => {
    if (epoch === share.collectionKeyEpoch) return Promise.resolve(collectionKey)
    keyring ??= api
      .get<EpochLinkV1[]>(`${shareBase(token)}/epochs`)
      .then(({ data: chain }) => {
        if (chain.length !== share.collectionKeyEpoch) throw new Error('incomplete folder key history')
        return unlockCollectionKeyring(collectionKey, share.targetId, share.ownerAccountId, share.ownerAuthorityPublicKey, chain)
      })
    return keyring.then((keys) => {
      const key = keys[epoch - 1]
      if (!key) throw new Error('no such folder key epoch')
      return key
    })
  }
  const { data } = await api.get<PublicFileRow[]>(`${shareBase(token)}/files`)
  return Promise.all(
    data.map(async (row) => {
      const opened = await keyAt(row.keyEpoch)
        .then((key) => openFileRecordV1(row, key))
        .catch(() => null)
      // What a download serves may be sealed under a key the file left
      // behind at a re-key; the file's own chain reaches it.
      const contentKey = opened
        ? await fileKeyAtV1(opened.fileKey, row.id, row.keyGeneration, row.keyHistory ?? [], row.contentKeyGeneration)
            .catch(() => null)
        : null
      return {
        row,
        fileKey: contentKey,
        currentKey: opened?.fileKey ?? null,
        name: opened?.metadata.name ?? null,
        mimeType: opened?.metadata.mimeType ?? 'application/octet-stream',
        size: opened?.metadata.size ?? 0,
        content: opened?.metadata.content ?? null,
        stateRevisionId: opened?.metadata.stateRevisionId ?? null,
      }
    }),
  )
}

/** A link to one file: its key from the link, then its name and content by its own key. */
async function loadFile(share: ShareInfo, key: Uint8Array): Promise<PublicFile> {
  const row = share.file
  if (!row) throw new PublicLinkError('notFound')
  let fileKey: Uint8Array
  try {
    fileKey = await openPublicLinkFileKeyV1(share.collectionKeyEnvelope, key, {
      fileId: share.targetId,
      ownerAccountId: share.ownerAccountId,
      generation: share.collectionKeyEpoch,
    })
  } catch {
    throw new PublicLinkError('badKey')
  }
  // The file moved to a newer key the owner has not handed to the link yet.
  if (share.collectionKeyEpoch !== row.keyGeneration) throw new PublicLinkError('waiting')
  const metadata = await openFileMetadataV1(row, fileKey).catch(() => null)
  const contentKey = await fileKeyAtV1(fileKey, row.id, row.keyGeneration, row.keyHistory ?? [], row.contentKeyGeneration).catch(() => null)
  return {
    row,
    fileKey: contentKey,
    currentKey: fileKey,
    name: metadata?.name ?? null,
    mimeType: metadata?.mimeType ?? 'application/octet-stream',
    size: metadata?.size ?? 0,
    content: metadata?.content ?? null,
    stateRevisionId: metadata?.stateRevisionId ?? null,
  }
}

/** What the file's current content must be: the revision and digest its metadata commits to, and its size. */
function currentExpected(file: PublicFile): DriveObjectExpected {
  if (!file.content) throw new Error('file is not open')
  return { fileId: file.row.id, generation: file.row.contentKeyGeneration, content: file.content, size: file.size }
}

/** The file key of `generation`, through the file's own key chain. */
export function publicFileKeyAt(file: PublicFile, generation: number): Promise<Uint8Array> {
  if (!file.currentKey) return Promise.reject(new Error('file is not open'))
  return fileKeyAtV1(file.currentKey, file.row.id, file.row.keyGeneration, file.row.keyHistory ?? [], generation)
}

/** Where a file's own calls go through the link: its pictures (`/assets/…`). */
export function publicFileBase(token: string, fileId: string): string {
  return `${shareBase(token)}/files/${fileId}`
}

/**
 * A note's text or a place list's places as last saved. Their edits are Yjs
 * state, not whole-file versions, so the download alone is the upload. Null
 * for other files, or when nothing was saved since the upload.
 *
 * The state read is the one the file's sealed metadata names
 * (`stateRevisionId`, committed with each saved state): the page asks for
 * it by id and refuses any other the server serves, so it can't be handed
 * an older genuine state under the current metadata
 * (docs/plans/drive-block-format.md §8).
 */
export async function editedContent(token: string, file: PublicFile): Promise<Uint8Array | null> {
  const name = file.name ?? ''
  const list = isListName(name)
  if (!file.currentKey || (!list && editorKindFor(name) !== 'text')) return null
  // Nothing saved since the upload, as the metadata says: the upload is it.
  const stateRevisionId = file.stateRevisionId
  if (!stateRevisionId) return null
  // A state the metadata names but the server doesn't serve is refused (a 404 too).
  const response = await api.get<ArrayBuffer>(`${shareBase(token)}/files/${file.row.id}/state`, {
    params: { revision: stateRevisionId },
    responseType: 'arraybuffer',
  })
  const generation = Number(response.headers['x-kutup-key-generation'])
  const key = await publicFileKeyAt(file, generation)
  // That state, opened against the sealed record served with it.
  const expected = await resolveServed(key, { fileId: file.row.id, generation, revisionId: stateRevisionId, served: true }, {
    revisionId: typeof response.headers[REVISION_HEADER] === 'string' ? response.headers[REVISION_HEADER] : null,
    revisionContentEnvelope:
      typeof response.headers[REVISION_CONTENT_HEADER] === 'string' ? response.headers[REVISION_CONTENT_HEADER] : null,
  })
  const state = await openDriveObject(new Uint8Array(response.data), key, expected)
  if (list) return stateToListJson(state)
  const Y = await import('yjs')
  const doc = new Y.Doc()
  try {
    Y.applyUpdateV2(doc, state)
    return new TextEncoder().encode(doc.getText('content').toJSON())
  } finally {
    doc.destroy()
  }
}

/** The file as it is now, whole, to show it: its latest edit included. */
export async function readPublicFile(token: string, file: PublicFile, signal?: AbortSignal): Promise<Uint8Array> {
  if (!file.fileKey) throw new Error('file is not open')
  const edited = await editedContent(token, file)
  if (edited) return edited
  const url = `${await resolveApiBase()}${shareBase(token)}/files/${file.row.id}/download`
  const parts: Uint8Array[] = []
  let length = 0
  for await (const { plain } of fetchDecryptedChunks(url, file.fileKey, currentExpected(file), viewerToken(), signal)) {
    parts.push(plain)
    length += plain.length
  }
  const bytes = new Uint8Array(length)
  let at = 0
  for (const part of parts) {
    bytes.set(part, at)
    at += part.length
  }
  return bytes
}

/**
 * A video or song through the link, for its player: streamed by block
 * through the service worker (docs/plans/drive-block-format.md §4) with the
 * link's key and the default limits, or read whole where no worker controls
 * the page.
 */
export async function openPublicFilePlayback(
  token: string,
  file: PublicFile,
  signal?: AbortSignal,
  onProgress?: (read: number) => void,
  onFallback?: (next: PlaybackFallback) => void,
): Promise<Playback> {
  const fileKey = file.fileKey
  if (!fileKey) throw new Error('file is not open')
  return openPublicPlayback(
    {
      url: `${await resolveApiBase()}${shareBase(token)}/files/${file.row.id}/download`,
      size: file.size,
      mimeType: file.mimeType,
      content: () => Promise.resolve({ fileKey, expected: currentExpected(file) }),
      accessToken: viewerToken(),
      readWhole: (readSignal) => readPublicFile(token, file, readSignal),
    },
    signal,
    onProgress,
    onFallback,
  )
}

/** Save the file as it is now (a note or list with its edits) to this device. */
export async function downloadPublicFile(token: string, file: PublicFile): Promise<void> {
  if (!file.fileKey || !file.name) return
  // A note or place list: its saved edits, turned back into the file.
  const edited = await editedContent(token, file)
  if (edited) {
    saveBytes(edited, file.name, file.mimeType)
    return
  }
  await streamDownload({
    url: `${await resolveApiBase()}${shareBase(token)}/files/${file.row.id}/download`,
    fileKey: file.fileKey,
    context: currentExpected(file),
    filename: file.name,
    mimeType: file.mimeType,
    expectedPlainSize: file.size,
    blobFallbackMaxBytes: async () => (await driveStreamLimits({ anonymous: true })).blobFallbackMaxBytes,
    accessToken: viewerToken(),
  })
}

function saveBytes(bytes: Uint8Array, filename: string, mimeType: string) {
  const url = URL.createObjectURL(new Blob([bytes.slice()], { type: mimeType }))
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  a.click()
  setTimeout(() => URL.revokeObjectURL(url), 1000)
}
