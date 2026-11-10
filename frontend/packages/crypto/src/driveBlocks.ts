// Drive revisions in the block format (docs/plans/drive-block-format.md §2):
// 4 MiB blocks sealed and opened in kutup-crypto-wasm, bound to the file,
// the key generation and the revision, with a signed manifest whose digest
// the file's sealed metadata commits to. Rust owns the format; these are
// typed wrappers.

import { toBase64 } from './base64'
import { getCryptoWasm, type WasmBlockEncryptor } from './rustWasm'

/** The plaintext size of a block (Proton's 4 MiB). */
export const DRIVE_BLOCK_SIZE = 4 * 1024 * 1024

/** What a revision's object is bound to. */
export interface DriveRevisionContext {
  fileId: string
  /** The random UUID the client picks for this content object. */
  revisionId: string
  /** The generation of the file key that seals it. */
  generation: number
}

/** What a file's sealed metadata commits to: the current revision and its sealed manifest's SHA-256 (canonical base64). */
export interface ContentCommitment {
  revisionId: string
  manifestSha256: string
}

/** Who signs a manifest: the uploader's account master key and account id. */
export interface ManifestSigner {
  masterKey: Uint8Array
  accountId: string
}

/**
 * Seals a revision block by block as its bytes are read: the header, each
 * block, then the signed manifest and trailer. Synthetic nonces make sealing
 * the same plaintext again give the same bytes, so an interrupted upload
 * resumes by sealing again from the block the server's offset falls in.
 */
export interface DriveBlockEncryptor {
  readonly header: Uint8Array
  readonly size: number
  readonly blockCount: number
  /** The whole object's length: the tus `Upload-Length`, known before sealing. */
  readonly objectLength: number
  /** Where block `index`'s sealed bytes start in the object. */
  sealedOffset(index: number): number
  /** Block `index`'s plaintext length. */
  plainLength(index: number): number
  /** The next block, in order, exactly its length. */
  sealNext(plaintext: Uint8Array): Uint8Array
  /** After the last block: the sealed manifest and trailer, and the digest the metadata commits to. */
  finish(signer: ManifestSigner): { tail: Uint8Array; content: ContentCommitment }
  free(): void
}

export async function newDriveBlockEncryptor(fileKey: Uint8Array, context: DriveRevisionContext, size: number): Promise<DriveBlockEncryptor> {
  const module = await getCryptoWasm()
  const inner: WasmBlockEncryptor = module.driveBlockEncryptor(toBase64(fileKey), context.fileId, context.revisionId, context.generation, size)
  const header = inner.header()
  return {
    header,
    size: inner.size,
    blockCount: inner.blockCount,
    objectLength: inner.objectLength,
    sealedOffset: (index) => inner.blockOffset(index),
    plainLength: (index) => inner.blockLength(index),
    sealNext: (plaintext) => inner.sealNext(plaintext),
    finish: (signer) => {
      const tail = inner.finishSigned(toBase64(signer.masterKey), signer.accountId)
      const manifestSha256 = inner.manifestSha256
      if (!manifestSha256) throw new Error('the block encryptor gave no manifest digest')
      return { tail, content: { revisionId: context.revisionId, manifestSha256 } }
    },
    free: () => inner.free(),
  }
}

/**
 * A whole revision sealed at once: editor snapshots, versions saved from a
 * buffer, vault and list saves. The same format as a streamed upload.
 */
export async function sealDriveFile(
  plaintext: Uint8Array,
  fileKey: Uint8Array,
  context: DriveRevisionContext,
  signer: ManifestSigner,
): Promise<{ bytes: Uint8Array; content: ContentCommitment }> {
  const module = await getCryptoWasm()
  const sealed = module.driveSealFile(plaintext, toBase64(fileKey), context.fileId, context.revisionId, context.generation, toBase64(signer.masterKey), signer.accountId)
  try {
    return { bytes: sealed.bytes, content: { revisionId: context.revisionId, manifestSha256: sealed.manifestSha256 } }
  } finally {
    sealed.free()
  }
}

/**
 * Opens a whole revision against what the file's metadata commits to (the
 * revision, its manifest's digest and the size): an older or foreign object
 * under the same header is refused before anything opens.
 */
export async function openDriveFile(
  object: Uint8Array,
  fileKey: Uint8Array,
  expected: { fileId: string; generation: number },
  content: ContentCommitment,
  size: number,
): Promise<Uint8Array> {
  const module = await getCryptoWasm()
  return module.driveOpenFile(object, toBase64(fileKey), expected.fileId, expected.generation, content.revisionId, content.manifestSha256, size)
}

/** A new revision's id: a random UUID, chosen by the client before it seals (lowercase, as the header and the server name it). */
export function newRevisionId(): string {
  return crypto.randomUUID().toLowerCase()
}

/** The Drive object family's layout, from Rust. */
async function driveLayout() {
  const module = await getCryptoWasm()
  return { module, layout: module.blockLayout('drive') }
}

/**
 * What a Drive object must be to open:
 * - the file's current content: the revision and manifest digest its sealed
 *   metadata commits to, and the metadata's size;
 * - a version from the file's history (a saved version or a note's
 *   snapshot): its header must name the revision the listing asked for
 *   (`revisionId`, the version's id; null for the original upload, which the
 *   listing does not name). The metadata commits to the current content
 *   only, so a version's manifest digest and size are its own (§2, "Versions
 *   in the history list open by their own revision id"): its blocks are
 *   still checked against its manifest, and the manifest against its header.
 */
export type DriveObjectExpected =
  | { fileId: string; generation: number; content: ContentCommitment; size: number }
  | { fileId: string; generation: number; revisionId: string | null }

/** The revision id a Drive object's header names (bytes 32..48: after magic, suite, purpose, reserved, generation and file id). */
function headerRevisionId(object: Uint8Array, headerBytes: number): string {
  if (object.length < headerBytes) throw new Error('Drive object is shorter than its header')
  const hex = Array.from(object.subarray(32, 48), (byte) => byte.toString(16).padStart(2, '0')).join('')
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`
}

/**
 * A history version's own commitment, from the object: its sealed manifest's
 * SHA-256 and the plaintext size its length gives. Rust then checks both
 * against the manifest itself, the manifest against the header, and every
 * block against the manifest.
 */
async function ownCommitment(object: Uint8Array, revisionId: string | null): Promise<{ content: ContentCommitment; size: number }> {
  const { module, layout } = await driveLayout()
  const { headerBytes, blockSize, blockOverhead, trailerBytes } = layout
  if (object.length < headerBytes + trailerBytes) throw new Error('Drive object is too short')
  const manifestLength = module.blockTrailerManifestLength('drive', object.subarray(object.length - trailerBytes))
  const manifestEnd = object.length - trailerBytes
  const manifestStart = manifestEnd - manifestLength
  const blocksLength = manifestStart - headerBytes
  if (manifestStart < headerBytes || blocksLength < blockOverhead) throw new Error('Drive object is malformed')
  const count = Math.ceil(blocksLength / (blockSize + blockOverhead))
  const size = blocksLength - count * blockOverhead
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', object.slice(manifestStart, manifestEnd)))
  return {
    content: { revisionId: revisionId ?? headerRevisionId(object, headerBytes), manifestSha256: toBase64(digest) },
    size,
  }
}

/** Opens a whole Drive object, the current content or a history version (`DriveObjectExpected`). */
export async function openDriveObject(object: Uint8Array, fileKey: Uint8Array, expected: DriveObjectExpected): Promise<Uint8Array> {
  const binding = { fileId: expected.fileId, generation: expected.generation }
  if ('content' in expected) return openDriveFile(object, fileKey, binding, expected.content, expected.size)
  const own = await ownCommitment(object, expected.revisionId)
  return openDriveFile(object, fileKey, binding, own.content, own.size)
}
