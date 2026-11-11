// fetchDecryptedChunks — fetch a Drive object and yield its plaintext,
// shared by single-file downloads (streamDownload.ts), folder-as-ZIP
// downloads (../zipDownload.ts) and every reader of a whole file.
//
// The object is in the block format (docs/plans/drive-block-format.md §2):
// a header bound to the file, its key generation and the revision, 4 MiB
// blocks, and a signed manifest of the blocks' hashes. It is read whole and
// opened in Rust against what the caller expects (`DriveObjectToOpen`):
// the current content against the revision and manifest digest its metadata
// commits to (and the record served with it must agree), any other revision
// against its sealed content record (from the listing, or, for the original
// upload, served with it). Reading by
// block with Range requests, in a Worker, is slice 4 (§10).
//
// Throws on: HTTP error, a header for another file, generation or revision,
// a manifest other than the committed one, a wrong size, and any block that
// fails its hash or its AEAD (wrong key, tampered, reordered or cut).

import {
  openDriveObject,
  resolveServed,
  REVISION_CONTENT_HEADER,
  REVISION_HEADER,
  type DriveObjectToOpen,
} from '@kutup/crypto'

export interface DecryptedChunk {
  plain: Uint8Array
  /** No more chunks follow. */
  isFinal: boolean
}

/** The whole object at `url`, opened against `expected`. */
export async function fetchDriveObject(
  url: string,
  fileKey: Uint8Array,
  expected: DriveObjectToOpen,
  accessToken: string,
  signal?: AbortSignal,
): Promise<Uint8Array> {
  const resp = await fetch(url, {
    // Public-link downloads are anonymous: no token, no header.
    headers: accessToken ? { Authorization: `Bearer ${accessToken}` } : {},
    signal,
  })
  if (!resp.ok) {
    throw new Error(
      `download HTTP ${resp.status}: ${await resp.text().catch(() => '')}`,
    )
  }
  const committed = await resolveServed(fileKey, expected, {
    revisionId: resp.headers.get(REVISION_HEADER),
    revisionContentEnvelope: resp.headers.get(REVISION_CONTENT_HEADER),
  })
  const object = new Uint8Array(await resp.arrayBuffer())
  return openDriveObject(object, fileKey, committed)
}

export async function* fetchDecryptedChunks(
  url: string,
  fileKey: Uint8Array,
  expected: DriveObjectToOpen,
  accessToken: string,
  signal?: AbortSignal,
): AsyncGenerator<DecryptedChunk, void, void> {
  yield { plain: await fetchDriveObject(url, fileKey, expected, accessToken, signal), isFinal: true }
}

export function appendBytes(
  a: Uint8Array<ArrayBufferLike>,
  b: Uint8Array<ArrayBufferLike>,
): Uint8Array<ArrayBufferLike> {
  if (a.length === 0) return b
  const out = new Uint8Array(a.length + b.length)
  out.set(a, 0)
  out.set(b, a.length)
  return out
}
