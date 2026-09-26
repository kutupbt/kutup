import {
  DRIVE_ENVELOPE_PURPOSE,
  openDriveEnvelope,
  sealDriveEnvelope,
  type DriveEnvelopeContextV1,
} from './driveEnvelope'
import { sealPreviousFileKeyV1 } from './fileKeyring'
import { getCryptoWasm } from './rustWasm'
import { generateKey } from './symmetric'

/**
 * A file record (docs/plans/drive-move.md): a random file key, wrapped under
 * its folder's key — the one envelope that names the folder — and the
 * metadata sealed under the file key, bound to the file alone. `keyEpoch` is
 * the folder epoch the wrap is sealed at; `keyGeneration` counts the file's
 * own keys (a re-key adds one).
 */

/** Where a photo's date came from (docs/plans/photos.md). */
export type TakenFromV1 = 'exif' | 'video' | 'filename' | 'file' | 'edited'

/**
 * When and where a photo or video was taken, and what it is. Every field is
 * optional; Rust (`kutup-crypto` `file_metadata`) holds the limits.
 */
export interface MediaMetadataV1 {
  /** UTC milliseconds. */
  takenAt?: number
  /** The local time zone where it was taken, minutes east of UTC. */
  takenOffset?: number
  takenFrom?: TakenFromV1
  lat?: number
  lon?: number
  /** As shown (after rotation). */
  width?: number
  height?: number
  durationMs?: number
  camera?: string
  /** SHA-256 of the content, base64. */
  hash?: string
  caption?: string
}

export interface FileMetadataV1 {
  name: string
  mimeType: string
  size: number
  media?: MediaMetadataV1
}

export interface FileWireV1 {
  id: string
  collectionId: string
  metadataEnvelope: string
  fileKeyEnvelope: string
  keyEpoch: number
  keyGeneration: number
  metadataRevision: number
}

export interface CreatedFileRecordV1 {
  fileId: string
  fileKey: Uint8Array
  metadataEnvelope: string
  fileKeyEnvelope: string
  keyEpoch: number
  keyGeneration: 1
  metadataRevision: 1
}

function validateCounter(value: number, what: string): void {
  if (!Number.isSafeInteger(value) || value < 1 || value > 0xffff_ffff) {
    throw new Error(`invalid ${what}`)
  }
}

function validateRevision(value: number): void {
  if (!Number.isSafeInteger(value) || value < 1) {
    throw new Error('invalid file metadata revision')
  }
}

/** The canonical bytes, checked by the Rust format (`canonicalFileMetadata`). */
async function encodeMetadata(metadata: FileMetadataV1): Promise<Uint8Array> {
  const module = await getCryptoWasm()
  const plain: FileMetadataV1 = { name: metadata.name, mimeType: metadata.mimeType, size: metadata.size }
  if (metadata.media) plain.media = metadata.media
  return new TextEncoder().encode(module.canonicalFileMetadata(JSON.stringify(plain)))
}

async function decodeMetadata(bytes: Uint8Array): Promise<FileMetadataV1> {
  const module = await getCryptoWasm()
  const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes)
  return JSON.parse(module.canonicalFileMetadata(text)) as FileMetadataV1
}

/** The file key's wrap under its folder's key at `keyEpoch`. */
function fileKeyContext(
  fileId: string,
  collectionId: string,
  keyEpoch: number,
  keyGeneration: number,
): DriveEnvelopeContextV1 {
  validateCounter(keyEpoch, 'folder key epoch')
  validateCounter(keyGeneration, 'file key generation')
  return {
    purpose: DRIVE_ENVELOPE_PURPOSE.fileKey,
    epoch: keyEpoch,
    revision: BigInt(keyGeneration),
    objectId: fileId,
    parentId: collectionId,
  }
}

/** The metadata under the file key of `keyGeneration`: the file's alone. */
function metadataContext(
  fileId: string,
  keyGeneration: number,
  revision: number,
): DriveEnvelopeContextV1 {
  validateCounter(keyGeneration, 'file key generation')
  validateRevision(revision)
  return {
    purpose: DRIVE_ENVELOPE_PURPOSE.fileMetadata,
    epoch: keyGeneration,
    revision: BigInt(revision),
    objectId: fileId,
    parentId: fileId,
  }
}

/** Construct both envelopes before any upload reaches the server. */
export async function createFileRecordV1(
  collectionId: string,
  keyEpoch: number,
  collectionKey: Uint8Array,
  metadata: FileMetadataV1,
): Promise<CreatedFileRecordV1> {
  const fileId = crypto.randomUUID().toLowerCase()
  const fileKey = await generateKey()
  const fileKeyEnvelope = await sealDriveEnvelope(
    fileKey,
    collectionKey,
    fileKeyContext(fileId, collectionId, keyEpoch, 1),
  )
  const metadataEnvelope = await sealDriveEnvelope(
    await encodeMetadata(metadata),
    fileKey,
    metadataContext(fileId, 1, 1),
  )
  return {
    fileId,
    fileKey,
    metadataEnvelope,
    fileKeyEnvelope,
    keyEpoch,
    keyGeneration: 1,
    metadataRevision: 1,
  }
}

/** Open a file's key (under `collectionKey`, the folder key at the row's
 * `keyEpoch`) and its metadata, each only in its exact context. */
export async function openFileRecordV1(
  row: FileWireV1,
  collectionKey: Uint8Array,
): Promise<{ fileKey: Uint8Array; metadata: FileMetadataV1 }> {
  const fileKey = await openDriveEnvelope(
    row.fileKeyEnvelope,
    collectionKey,
    fileKeyContext(row.id, row.collectionId, row.keyEpoch, row.keyGeneration),
  )
  const metadataBytes = await openDriveEnvelope(
    row.metadataEnvelope,
    fileKey,
    metadataContext(row.id, row.keyGeneration, row.metadataRevision),
  )
  return { fileKey, metadata: await decodeMetadata(metadataBytes) }
}

/**
 * A file's name and details from its own key: for a file shared by itself
 * (docs/plans/drive-file-sharing.md), whose recipient has no folder key.
 */
export async function openFileMetadataV1(
  row: Pick<FileWireV1, 'id' | 'keyGeneration' | 'metadataRevision' | 'metadataEnvelope'>,
  fileKey: Uint8Array,
): Promise<FileMetadataV1> {
  const metadataBytes = await openDriveEnvelope(
    row.metadataEnvelope,
    fileKey,
    metadataContext(row.id, row.keyGeneration, row.metadataRevision),
  )
  return decodeMetadata(metadataBytes)
}

export async function renameFileRecordV1(
  row: Pick<FileWireV1, 'id' | 'keyGeneration' | 'metadataRevision'>,
  fileKey: Uint8Array,
  metadata: FileMetadataV1,
): Promise<{ metadataEnvelope: string; metadataRevision: number }> {
  validateRevision(row.metadataRevision)
  const metadataRevision = row.metadataRevision + 1
  const metadataEnvelope = await sealDriveEnvelope(
    await encodeMetadata(metadata),
    fileKey,
    metadataContext(row.id, row.keyGeneration, metadataRevision),
  )
  return { metadataEnvelope, metadataRevision }
}

/**
 * A new file key for a file its folder has rotated past
 * (docs/plans/drive-share-revocation.md): the next generation, wrapped at the
 * folder's current `keyEpoch`, the same metadata (same revision) sealed under
 * it, and the key it leaves sealed under it too, so everything stored before
 * stays readable wherever the file goes (docs/plans/drive-move.md).
 */
export async function rekeyFileRecordV1(
  row: Pick<FileWireV1, 'id' | 'collectionId' | 'keyGeneration' | 'metadataRevision'>,
  currentFileKey: Uint8Array,
  keyEpoch: number,
  collectionKey: Uint8Array,
  metadata: FileMetadataV1,
): Promise<{
  fileKey: Uint8Array
  keyGeneration: number
  fileKeyEnvelope: string
  metadataEnvelope: string
  previousKeyEnvelope: string
}> {
  const keyGeneration = row.keyGeneration + 1
  const fileKey = await generateKey()
  const fileKeyEnvelope = await sealDriveEnvelope(
    fileKey,
    collectionKey,
    fileKeyContext(row.id, row.collectionId, keyEpoch, keyGeneration),
  )
  const metadataEnvelope = await sealDriveEnvelope(
    await encodeMetadata(metadata),
    fileKey,
    metadataContext(row.id, keyGeneration, row.metadataRevision),
  )
  const previousKeyEnvelope = await sealPreviousFileKeyV1(
    currentFileKey,
    fileKey,
    row.id,
    keyGeneration,
  )
  return { fileKey, keyGeneration, fileKeyEnvelope, metadataEnvelope, previousKeyEnvelope }
}

/**
 * The file's current key wrapped for another folder, at that folder's
 * current epoch: everything a move sends (docs/plans/drive-move.md).
 */
export async function wrapFileKeyForV1(
  file: Pick<FileWireV1, 'id' | 'keyGeneration'>,
  fileKey: Uint8Array,
  collectionId: string,
  keyEpoch: number,
  collectionKey: Uint8Array,
): Promise<string> {
  return sealDriveEnvelope(
    fileKey,
    collectionKey,
    fileKeyContext(file.id, collectionId, keyEpoch, file.keyGeneration),
  )
}
