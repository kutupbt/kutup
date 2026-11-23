// fetchDecryptedChunks — read a Drive object block by block and yield its
// plaintext, shared by single-file downloads (streamDownload.ts),
// folder-as-ZIP downloads (../zipDownload.ts) and every reader of a whole
// file.
//
// The object is in the block format (docs/plans/drive-block-format.md §2):
// a header bound to the file, its key generation and the revision, 4 MiB
// blocks, and a signed manifest of the blocks' hashes. It is read with HTTP
// Range by the block reader (../blockReader, in a dedicated Worker), the
// same one the players stream from: the header, the trailer and the
// manifest first, opened against what the caller expects
// (`DriveObjectToOpen`: the current content against the revision and
// manifest digest its metadata commits to, any other revision against its
// sealed content record), then each block in order, its hash checked
// against the manifest before it opens. One block is fetched ahead.
//
// Throws on: HTTP error, a header for another file, generation or revision,
// a manifest other than the committed one, a wrong size, and any block that
// fails its hash or its AEAD (wrong key, tampered, reordered or cut).

import type { DriveObjectToOpen } from '@kutup/crypto/driveBlocks'
import { openBlockReader, type AccessToken } from '../blockReader/client'
import type { BlockReaderSettings } from '../blockReader/protocol'
import { DEFAULT_STREAM_LIMITS } from '../stream/limits'

export interface DecryptedChunk {
  plain: Uint8Array
  /** No more chunks follow. */
  isFinal: boolean
}

/** A whole download reads in order: the block it hands over and the one after. */
const DOWNLOAD_SETTINGS: BlockReaderSettings = {
  cacheBlocks: 2,
  readaheadBlocks: 1,
  responseMaxBytes: DEFAULT_STREAM_LIMITS.responseMaxBytes,
}

/** The object at `url`, opened against `expected`, block by block (one 4 MiB block per chunk). */
export async function* fetchDecryptedChunks(
  url: string,
  fileKey: Uint8Array,
  expected: DriveObjectToOpen,
  accessToken: AccessToken,
  signal?: AbortSignal,
  /** Headers each range request adds (a protected public link's proof). */
  headers?: Record<string, string>,
): AsyncGenerator<DecryptedChunk, void, void> {
  const reader = await openBlockReader({ source: { family: 'drive', url, fileKey, expected, headers }, accessToken, settings: DOWNLOAD_SETTINGS, signal })
  try {
    const { blockCount } = reader.opened
    for (let index = 0; index < blockCount; index++) {
      signal?.throwIfAborted()
      yield { plain: await reader.block(index), isFinal: index === blockCount - 1 }
    }
  } finally {
    reader.close()
  }
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
