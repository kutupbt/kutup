// An object of the block format read by block with HTTP Range
// (docs/plans/drive-block-format.md §2 "Reading", §4): a Drive revision or
// a Chat attachment (`BlockReaderTarget.family`). The same code runs in
// the dedicated reader Worker (blockReader.worker.ts) and, where there are
// no Workers (tests), in the page.
//
// The order is what makes it safe:
// 1. the header (its first bytes), with the response's revision headers;
// 2. what the object must be: for Drive the metadata's commitment, or the
//    revision's sealed record (`resolveServed`, `committedContent`); for a
//    Chat attachment its E2EE descriptor's manifest digest and lengths;
// 3. the trailer, then the sealed manifest, opened in Rust against that
//    digest and size (the header must name the file, generation and
//    revision, or the attachment). Nothing is fetched by block before this succeeds;
// 4. each block by its own Range, its sealed bytes hashed against the
//    manifest's entry and then opened at its index (`openBlock`).
// The manifest's signer is checked by the page before it releases a byte
// (client.ts).

import { toBase64 } from '@kutup/crypto/base64'
import { exactBytes } from '@kutup/crypto/bytes'
import { committedContent, REVISION_CONTENT_HEADER, REVISION_HEADER, resolveServed } from '@kutup/crypto/driveBlocks'
import { getCryptoWasm, type WasmBlockReader } from '@kutup/crypto/rustWasm'
import { answerSpan, BlockCache, blockOf, type StreamRange } from './plan'
import { STREAM_PROTOCOL_VERSION, type BlockReaderSettings, type BlockReaderTarget, type OpenedObject, type StreamChunkAnswer } from './protocol'

export interface ReaderIo {
  fetch: typeof fetch
  /** The bearer token for the next request ('' for none). */
  token: () => string
  /** This page's `X-Kutup-Client` (docs/plans/api-surface.md §1.2), when known. */
  client?: () => string | null
}

/** A ranged answer the reader can't use. */
export class RangeFetchError extends Error {
  constructor(
    message: string,
    readonly status?: number,
  ) {
    super(message)
    this.name = 'RangeFetchError'
  }
}

function contentRange(header: string | null): { start: number; end: number; total: number } | null {
  const match = /^bytes (\d+)-(\d+)\/(\d+)$/.exec(header?.trim() ?? '')
  if (!match) return null
  return { start: Number(match[1]), end: Number(match[2]), total: Number(match[3]) }
}

export class BlockObjectReader {
  private readonly cache: BlockCache
  private readonly inflight = new Map<number, Promise<Uint8Array>>()
  private closed = false

  private constructor(
    private readonly wasm: WasmBlockReader,
    readonly opened: OpenedObject,
    private readonly total: number,
    private readonly settings: BlockReaderSettings,
    private readonly range: (start: number, end: number) => Promise<Uint8Array>,
    private readonly controller: AbortController,
  ) {
    this.cache = new BlockCache(Math.max(1, settings.cacheBlocks))
  }

  /** Opens the revision at `target.url`: header, trailer and manifest, checked before any block is read. */
  static async open(target: BlockReaderTarget, settings: BlockReaderSettings, io: ReaderIo, signal?: AbortSignal): Promise<BlockObjectReader> {
    const controller = new AbortController()
    const onAbort = () => controller.abort(signal?.reason)
    if (signal?.aborted) onAbort()
    signal?.addEventListener('abort', onAbort, { once: true })

    let total: number | null = null
    let served: Headers | null = null
    // One range, whole: the server may answer a long one in parts.
    const range = async (start: number, end: number): Promise<Uint8Array> => {
      const out = new Uint8Array(end - start + 1)
      let at = start
      while (at <= end) {
        const token = io.token()
        const client = io.client?.()
        const resp = await io.fetch(target.url, {
          headers: {
            Range: `bytes=${at}-${end}`,
            ...(token ? { Authorization: `Bearer ${token}` } : {}),
            ...(client ? { 'X-Kutup-Client': client } : {}),
          },
          signal: controller.signal,
          cache: 'no-store',
        })
        if (resp.status !== 206) {
          throw new RangeFetchError(`range HTTP ${resp.status}: ${await resp.text().catch(() => '')}`, resp.status)
        }
        const answered = contentRange(resp.headers.get('Content-Range'))
        if (!answered || answered.start !== at || answered.end > end || answered.end < at) {
          throw new RangeFetchError('the server answered another range than asked')
        }
        if (total === null) {
          total = answered.total
          served = resp.headers
        } else if (answered.total !== total) {
          throw new RangeFetchError('the object changed while it was read')
        }
        const body = new Uint8Array(await resp.arrayBuffer())
        if (body.length !== answered.end - answered.start + 1) throw new RangeFetchError('the server sent another length than its range')
        out.set(body, at - start)
        at = answered.end + 1
      }
      return out
    }

    let wasmReader: WasmBlockReader | null = null
    try {
      const module = await getCryptoWasm()
      const layout = module.blockLayout(target.family)
      // 1. The header, and what the response says it serves.
      const header = await range(0, layout.headerBytes - 1)
      // Set by the first answer (the closure's writes aren't tracked).
      const objectLength = total as number | null
      const headers = served as Headers | null
      if (objectLength === null || !headers) throw new RangeFetchError('no length for the object')
      // 2. What it must be: a Drive revision's commitment (from its
      // metadata, or its own sealed record), or a Chat attachment's
      // descriptor, which the page holds already.
      let expected: { id: string; revisionId: string; manifestSha256: string; size: number }
      let generation = 0
      if (target.family === 'drive') {
        const resolved = await resolveServed(target.fileKey, target.expected, {
          revisionId: headers.get(REVISION_HEADER),
          revisionContentEnvelope: headers.get(REVISION_CONTENT_HEADER),
        })
        const committed = await committedContent(target.fileKey, resolved)
        expected = { id: resolved.fileId, revisionId: committed.content.revisionId, manifestSha256: committed.content.manifestSha256, size: committed.size }
        generation = resolved.generation
      } else {
        if (objectLength !== target.objectLength) throw new RangeFetchError("the object's length is not the descriptor's")
        expected = { id: target.attachmentId, revisionId: target.attachmentId, manifestSha256: target.manifestSha256, size: target.size }
      }
      // 3. The trailer, then the sealed manifest, opened against that digest and size.
      if (objectLength < layout.headerBytes + layout.trailerBytes) throw new RangeFetchError('the object is too short')
      const trailer = await range(objectLength - layout.trailerBytes, objectLength - 1)
      const manifestLength = module.blockTrailerManifestLength(target.family, trailer)
      const manifestStart = objectLength - layout.trailerBytes - manifestLength
      if (manifestStart < layout.headerBytes) throw new RangeFetchError('the manifest does not fit the object')
      const manifest = await range(manifestStart, objectLength - layout.trailerBytes - 1)
      wasmReader =
        target.family === 'drive'
          ? module.driveBlockReader(
              toBase64(target.fileKey),
              expected.id,
              generation,
              expected.revisionId,
              expected.manifestSha256,
              expected.size,
              header,
              manifest,
            )
          : module.chatMediaBlockReader(toBase64(target.attachmentKey), expected.id, expected.manifestSha256, header, manifest)
      if (wasmReader.size !== expected.size) throw new RangeFetchError("the object's size is not the one expected")
      if (wasmReader.objectLength !== objectLength) throw new RangeFetchError("the object's length is not the manifest's")
      const accountId = wasmReader.signerAccountId
      const incarnationId = wasmReader.signerIncarnationId
      const opened: OpenedObject = {
        fileId: expected.id,
        revisionId: expected.revisionId,
        size: wasmReader.size,
        blockCount: wasmReader.blockCount,
        blockSize: layout.blockSize,
        signer: accountId && incarnationId ? { accountId, incarnationId } : null,
      }
      signal?.removeEventListener('abort', onAbort)
      const reader = new BlockObjectReader(wasmReader, opened, objectLength, settings, range, controller)
      signal?.addEventListener('abort', () => reader.close(), { once: true })
      return reader
    } catch (error) {
      wasmReader?.free()
      signal?.removeEventListener('abort', onAbort)
      controller.abort()
      throw error
    }
  }

  /** Whether this Drive signing public key (base64) made the manifest's signature. */
  signedBy(key: string): boolean {
    if (this.closed) return false
    try {
      this.wasm.verifySigner(key)
      return true
    } catch {
      return false
    }
  }

  /** Block `index`'s verified plaintext, and the blocks after it fetched ahead. */
  async block(index: number): Promise<Uint8Array> {
    const plain = await this.load(index)
    for (let ahead = 1; ahead <= this.settings.readaheadBlocks; ahead++) {
      const next = index + ahead
      if (next >= this.opened.blockCount) break
      this.load(next).catch(() => {})
    }
    return plain
  }

  private load(index: number): Promise<Uint8Array> {
    if (this.closed) return Promise.reject(new DOMException('the reader is closed', 'AbortError'))
    if (!Number.isSafeInteger(index) || index < 0 || index >= this.opened.blockCount) {
      return Promise.reject(new RangeError(`no block ${index}`))
    }
    const cached = this.cache.get(index)
    if (cached) return Promise.resolve(cached)
    const pending = this.inflight.get(index)
    if (pending) return pending
    const loading = (async () => {
      const start = this.wasm.blockOffset(index)
      const sealed = await this.range(start, start + this.wasm.sealedBlockLength(index) - 1)
      if (this.closed) throw new DOMException('the reader is closed', 'AbortError')
      // Its hash against the manifest's entry, then its AEAD at its index.
      const plain = this.wasm.openBlock(index, sealed)
      this.cache.set(index, plain)
      return plain
    })()
    this.inflight.set(index, loading)
    const forget = () => {
      if (this.inflight.get(index) === loading) this.inflight.delete(index)
    }
    loading.then(forget, forget)
    return loading
  }

  /** One stream answer to `range`: to the end of the block its first byte is in, at most `responseMaxBytes`. */
  async answer(range: StreamRange, mimeType: string): Promise<{ answer: StreamChunkAnswer; transfer: Transferable[] }> {
    const span = answerSpan({ size: this.opened.size, blockSize: this.opened.blockSize }, range, this.settings.responseMaxBytes)
    if (!span) return { answer: { v: STREAM_PROTOCOL_VERSION, kind: 'unsatisfiable', total: this.opened.size }, transfer: [] }
    const index = blockOf(span.start, this.opened.blockSize)
    const plain = await this.block(index)
    const from = span.start - index * this.opened.blockSize
    // A copy of its own, transferred: the cached block stays.
    const bytes = exactBytes(plain.subarray(from, from + (span.end - span.start + 1)))
    return {
      answer: { v: STREAM_PROTOCOL_VERSION, kind: 'bytes', start: span.start, total: this.opened.size, mimeType, bytes },
      transfer: [bytes],
    }
  }

  /** Stops every fetch, drops the cached blocks and frees the Rust reader. */
  close(): void {
    if (this.closed) return
    this.closed = true
    this.controller.abort()
    this.cache.clear()
    this.inflight.clear()
    this.wasm.free()
  }

  /** The object's sealed length, as the server gave it. */
  get objectLength(): number {
    return this.total
  }
}

/** Answers one stream request on `port`, whatever happens. */
export async function answerOnPort(
  reader: BlockObjectReader | null,
  port: MessagePort,
  range: StreamRange,
  mimeType: string,
): Promise<void> {
  try {
    if (!reader) throw new Error('the stream is not open')
    const { answer, transfer } = await reader.answer(range, mimeType)
    port.postMessage(answer, transfer)
  } catch (error) {
    const answer: StreamChunkAnswer = { v: STREAM_PROTOCOL_VERSION, kind: 'error', message: error instanceof Error ? error.message : String(error) }
    port.postMessage(answer)
  } finally {
    port.close()
  }
}
