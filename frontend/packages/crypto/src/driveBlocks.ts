// Drive revisions in the block format (docs/plans/drive-block-format.md §2):
// 4 MiB blocks sealed and opened in kutup-crypto-wasm, bound to the file,
// the key generation and the revision, with a signed manifest whose digest
// the file's sealed metadata commits to. Rust owns the format; these are
// typed wrappers.

import { toBase64 } from './base64'
import { deriveAccountIdentityKeys } from './identity'
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

/**
 * Who signs a manifest: the uploader's account master key (its Drive
 * signing key), account id and incarnation id. The manifest names both
 * ids, so a reader can tell which of the account's keys signed after a
 * reset.
 */
export interface ManifestSigner {
  masterKey: Uint8Array
  accountId: string
  /** The account's incarnation: the hash of its authority key (lowercase hex). */
  incarnationId: string
}

/** The signer an account is, from its master key: the incarnation is the one its authority key gives. */
export async function manifestSignerOf(masterKey: Uint8Array, accountId: string): Promise<ManifestSigner> {
  const { incarnationId } = await deriveAccountIdentityKeys(toBase64(masterKey))
  return { masterKey, accountId, incarnationId }
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
      const tail = inner.finishSigned(toBase64(signer.masterKey), signer.accountId, signer.incarnationId)
      const manifestSha256 = inner.manifestSha256
      if (!manifestSha256) throw new Error('the block encryptor gave no manifest digest')
      return { tail, content: { revisionId: context.revisionId, manifestSha256 } }
    },
    free: () => inner.free(),
  }
}

/**
 * What one revision is, sealed under the file key of the generation that
 * seals its object (docs/plans/drive-block-format.md §2): its id, its sealed
 * manifest's digest and its plaintext size. Every upload and save sends it
 * with the revision (the commit, a multipart upload or save); readers of
 * any revision but the current content open it before the object.
 */
export async function sealRevisionContent(
  fileKey: Uint8Array,
  context: DriveRevisionContext,
  content: ContentCommitment,
  size: number,
): Promise<string> {
  if (content.revisionId !== context.revisionId) throw new Error('the content is another revision')
  const module = await getCryptoWasm()
  return module.sealRevisionContent(toBase64(fileKey), context.fileId, context.revisionId, content.manifestSha256, size, context.generation)
}

/** Opens a revision's sealed content record for exactly this file, revision and key generation. */
export async function openRevisionContent(
  envelope: string,
  fileKey: Uint8Array,
  expected: DriveRevisionContext,
): Promise<{ content: ContentCommitment; size: number }> {
  const module = await getCryptoWasm()
  const opened = module.openRevisionContent(envelope, toBase64(fileKey), expected.fileId, expected.revisionId, expected.generation)
  return { content: { revisionId: opened.revisionId, manifestSha256: opened.manifestSha256 }, size: opened.size }
}

/**
 * A whole revision sealed at once: editor snapshots, versions saved from a
 * buffer, vault and list saves. The same format as a streamed upload, with
 * its sealed content record (`revisionContentEnvelope`) to send along.
 */
export async function sealDriveFile(
  plaintext: Uint8Array,
  fileKey: Uint8Array,
  context: DriveRevisionContext,
  signer: ManifestSigner,
): Promise<{ bytes: Uint8Array; content: ContentCommitment; revisionContentEnvelope: string }> {
  const module = await getCryptoWasm()
  const sealed = module.driveSealFile(plaintext, toBase64(fileKey), context.fileId, context.revisionId, context.generation, toBase64(signer.masterKey), signer.accountId, signer.incarnationId)
  let bytes: Uint8Array
  let content: ContentCommitment
  try {
    bytes = sealed.bytes
    content = { revisionId: context.revisionId, manifestSha256: sealed.manifestSha256 }
  } finally {
    sealed.free()
  }
  return { bytes, content, revisionContentEnvelope: await sealRevisionContent(fileKey, context, content, plaintext.length) }
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
  const opened = module.driveOpenFile(object, toBase64(fileKey), expected.fileId, expected.generation, content.revisionId, content.manifestSha256, size)
  let bytes: Uint8Array
  try {
    bytes = opened.takeBytes()
  } catch (error) {
    opened.free()
    throw error
  }
  const { signerAccountId: accountId, signerIncarnationId: incarnationId } = opened
  const check = signerCheck
  if (!check || !accountId || !incarnationId) {
    opened.free()
    return bytes
  }
  // Who signed is checked beside the open, never in its way: a signature
  // that doesn't hold warns (as Drive's other signatures), it doesn't block.
  void Promise.resolve()
    .then(() =>
      check({
        fileId: expected.fileId,
        revisionId: content.revisionId,
        accountId,
        incarnationId,
        signedBy: (driveSigningPublicKey) => opened.signedBy(driveSigningPublicKey),
      }),
    )
    .catch(() => {})
    .finally(() => opened.free())
  return bytes
}

/**
 * An opened revision's manifest signature: the account and incarnation it
 * names as its uploader, and whether a Drive signing public key (base64)
 * made it. Good only while the check it is handed to runs.
 */
export interface ManifestSignature {
  fileId: string
  revisionId: string
  accountId: string
  /** Lowercase hex: which of the account's keys signed (the hash of its authority key). */
  incarnationId: string
  /** A block reader in a Worker answers asynchronously. */
  signedBy(driveSigningPublicKey: string): boolean | Promise<boolean>
}

/** What every open hands its manifest's signature to (drive-core checks it against the identity pins). */
export type ManifestSignerCheck = (signature: ManifestSignature) => void | Promise<void>

let signerCheck: ManifestSignerCheck | null = null

/** Sets (or, with null, removes) the check every opened revision's signature goes to. */
export function setManifestSignerCheck(check: ManifestSignerCheck | null): void {
  signerCheck = check
}

/** The check set with `setManifestSignerCheck`, for readers that open a revision by block (`@kutup/files` blockReader). */
export function manifestSignerCheck(): ManifestSignerCheck | null {
  return signerCheck
}

/** A new revision's id: a random UUID, chosen by the client before it seals (lowercase, as the header and the server name it). */
export function newRevisionId(): string {
  return crypto.randomUUID().toLowerCase()
}

/**
 * What a Drive object must be to open. Every reader takes a committed
 * digest (docs/plans/drive-block-format.md §2); none takes it from the
 * object:
 * - the file's current content: the revision and manifest digest its sealed
 *   metadata commits to, and the metadata's size;
 * - any other revision (a history version, a note's snapshot, the original
 *   upload): its id and its sealed content record
 *   (`revisionContentEnvelope`, from the version list or the response that
 *   served it), opened first for exactly this file, revision and key
 *   generation. A revision without one (the streaming format) can't open.
 */
export type DriveObjectExpected =
  | { fileId: string; generation: number; content: ContentCommitment; size: number }
  | { fileId: string; generation: number; revisionId: string; revisionContentEnvelope: string | null }

/** The digest and size `expected` commits the object to: the metadata's, or the revision's sealed record, opened. */
export async function committedContent(fileKey: Uint8Array, expected: DriveObjectExpected): Promise<{ content: ContentCommitment; size: number }> {
  if ('content' in expected) return { content: expected.content, size: expected.size }
  if (!expected.revisionContentEnvelope) throw new Error('this revision has no committed content')
  const opened = await openRevisionContent(expected.revisionContentEnvelope, fileKey, {
    fileId: expected.fileId,
    revisionId: expected.revisionId,
    generation: expected.generation,
  })
  if (opened.content.revisionId !== expected.revisionId) throw new Error('the record is for another revision')
  return opened
}

/** Opens a whole Drive object, the current content or another revision (`DriveObjectExpected`), against its committed digest. */
export async function openDriveObject(object: Uint8Array, fileKey: Uint8Array, expected: DriveObjectExpected): Promise<Uint8Array> {
  const committed = await committedContent(fileKey, expected)
  return openDriveFile(object, fileKey, { fileId: expected.fileId, generation: expected.generation }, committed.content, committed.size)
}

/**
 * The current content's served record (`x-kutup-revision-content`), when the
 * server sent one, must say what the metadata commits to: the file's row and
 * its metadata never disagree about what is current.
 */
export async function checkServedRecord(
  fileKey: Uint8Array,
  expected: { fileId: string; generation: number; content: ContentCommitment; size: number },
  servedRevisionId: string | null,
  servedEnvelope: string | null,
): Promise<void> {
  if (!servedEnvelope) return
  if (servedRevisionId !== null && servedRevisionId !== expected.content.revisionId) {
    throw new Error('the server served another revision than the metadata commits to')
  }
  const opened = await openRevisionContent(servedEnvelope, fileKey, {
    fileId: expected.fileId,
    revisionId: expected.content.revisionId,
    generation: expected.generation,
  })
  if (opened.content.manifestSha256 !== expected.content.manifestSha256 || opened.size !== expected.size) {
    throw new Error("the revision's record disagrees with the file's metadata")
  }
}

/**
 * A revision whose sealed record comes with the response rather than from a
 * listing: the original upload (`/files/{id}/original`) and a public link's
 * saved state (`/share/{token}/state/{id}`). The caller names the revision
 * from what the file's sealed metadata commits to (`originalRevisionId`,
 * `stateRevisionId`), so the server can't pick another genuine revision:
 * the response must name this one, and its record (`x-kutup-revision`,
 * `x-kutup-revision-content`) is opened for it.
 */
export interface ServedRevision {
  fileId: string
  generation: number
  /** The revision the file's metadata names. */
  revisionId: string
  served: true
}

/** What a reader asks to open: a committed revision, or the one the response names. */
export type DriveObjectToOpen = DriveObjectExpected | ServedRevision

/** The response headers naming the revision served and carrying its sealed record. */
export const REVISION_HEADER = 'x-kutup-revision'
export const REVISION_CONTENT_HEADER = 'x-kutup-revision-content'

/**
 * What the object must be, given what its response says it is: a served
 * revision must be the one the caller named from the metadata, and opens
 * against the record served with it (the record binds the id, so a record
 * of another revision fails too); the current content checks the record
 * served with it, when there is one, against its metadata.
 */
export async function resolveServed(
  fileKey: Uint8Array,
  expected: DriveObjectToOpen,
  served: { revisionId: string | null; revisionContentEnvelope: string | null },
): Promise<DriveObjectExpected> {
  if ('served' in expected) {
    if (served.revisionId !== expected.revisionId) {
      throw new Error("the server served another revision than the file's metadata names")
    }
    return {
      fileId: expected.fileId,
      generation: expected.generation,
      revisionId: expected.revisionId,
      revisionContentEnvelope: served.revisionContentEnvelope,
    }
  }
  if ('content' in expected) await checkServedRecord(fileKey, expected, served.revisionId, served.revisionContentEnvelope)
  return expected
}
