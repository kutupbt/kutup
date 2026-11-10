// A Drive revision, sealed as tus asks for it (tus-js-client's
// `fileReader`): any byte range of the object, produced from the plaintext
// on demand. tus's own stream source keeps everything it reads until the
// range it wants, which on resuming a 9 GB upload means 9 GB in memory; this
// keeps a few blocks at most.
//
// The object is the block format (docs/plans/drive-block-format.md §2): the
// 48-byte header, one sealed block per 4 MiB of plaintext (40 bytes longer),
// then the sealed manifest and the trailer (the tail), whose digest the
// file's metadata commits to. Its length is known before anything is sealed.
//
// Block nonces are synthetic: sealing the same plaintext again gives the
// same bytes, so a range already sent (a retried request, an upload resumed
// after a reload, from wherever the server stopped, even inside a block) is
// produced again by sealing from the block it falls in. The encryptor only
// moves forward and the manifest needs every block's hash, so reaching a
// block seals the ones before it again and drops them; one earlier than the
// encryptor stands starts it over. The manifest's own nonce is random: the
// tail is made once, kept (`onTail` persists it before any of it is sent),
// and never made again.

import { DRIVE_BLOCK_SIZE, type ContentCommitment, type DriveBlockEncryptor, type ManifestSigner } from '@kutup/crypto'
import { fromBase64, toBase64 } from '@kutup/crypto/base64'

/** The plaintext, read in pieces (a `File` from disk). */
export interface PlaintextSource {
  size: number
  read(start: number, end: number): Promise<Uint8Array>
}

export function fileSource(file: Blob): PlaintextSource {
  return {
    size: file.size,
    read: async (start, end) => new Uint8Array(await file.slice(start, end).arrayBuffer()),
  }
}

/**
 * What tus-js-client reads an upload's body from. The value is a Blob: tus
 * measures what it got by `value.size`, which a Uint8Array does not have
 * (it would take the last range for empty and stop short of the end).
 */
export interface TusFileSource {
  size: number
  slice(start: number, end: number): Promise<{ value: Blob; done: boolean }>
  close(): void
}

/** A revision's tail once made: the sealed manifest and trailer, and what the metadata commits to. */
export interface SealedTail {
  tail: Uint8Array
  content: ContentCommitment
}

/** A tail as the browser keeps it with a pending upload (`pendingUploads`). */
export interface StoredTail {
  tail: string
  content: ContentCommitment
}

export function storeTail(tail: SealedTail): StoredTail {
  return { tail: toBase64(tail.tail), content: tail.content }
}

export function loadTail(stored: StoredTail): SealedTail {
  return { tail: fromBase64(stored.tail), content: stored.content }
}

export interface EncryptedSourceOptions {
  /** A new encryptor for the revision, from its start: the same bytes every time. */
  open: () => Promise<DriveBlockEncryptor>
  /** Who signs the manifest. */
  signer: ManifestSigner
  /** The tail made before (an upload resumed after a reload). */
  tail?: SealedTail
  /** Called once the tail is made, before any of it is handed out: keep it. */
  onTail?: (tail: SealedTail) => Promise<void>
}

/** How many sealed blocks stay at hand for ranges asked again (a PATCH spans up to three). */
const KEEP_BLOCKS = 4

export class EncryptedFileSource implements TusFileSource {
  readonly size: number
  private readonly blockCount: number
  private readonly header: Uint8Array
  /** A full block's sealed length, and where the tail starts. */
  private readonly stride: number
  private readonly tailStart: number
  private encryptor: DriveBlockEncryptor | null
  /** The block the encryptor seals next. */
  private next = 0
  private readonly kept = new Map<number, Uint8Array>()
  private tail: SealedTail | null

  constructor(
    private readonly plaintext: PlaintextSource,
    /** An encryptor for the revision, not yet used: its layout is the object's. */
    first: DriveBlockEncryptor,
    private readonly options: EncryptedSourceOptions,
  ) {
    if (first.size !== plaintext.size) throw new Error('the encryptor is for another size')
    this.encryptor = first
    this.size = first.objectLength
    this.blockCount = first.blockCount
    this.header = first.header
    this.stride = first.sealedOffset(1) - first.sealedOffset(0)
    const last = this.blockCount - 1
    this.tailStart = first.sealedOffset(last) + first.plainLength(last) + (this.stride - DRIVE_BLOCK_SIZE)
    this.tail = options.tail ?? null
    if (this.tail && this.tail.tail.length !== this.size - this.tailStart) throw new Error('the kept tail is for another object')
  }

  /** What the metadata commits to, once the tail is made. */
  get content(): ContentCommitment | null {
    return this.tail?.content ?? null
  }

  async slice(start: number, end: number): Promise<{ value: Blob; done: boolean }> {
    const { bytes, done } = await this.bytes(start, end)
    return { value: new Blob([bytes as Uint8Array<ArrayBuffer>]), done }
  }

  /** The object at [start, end), as bytes. */
  async bytes(start: number, end: number): Promise<{ bytes: Uint8Array; done: boolean }> {
    const stop = Math.min(end, this.size)
    if (start >= stop) return { bytes: new Uint8Array(0), done: true }
    const out = new Uint8Array(stop - start)
    let at = start
    while (at < stop) {
      let piece: Uint8Array
      let from: number
      if (at < this.header.length) {
        piece = this.header
        from = 0
      } else if (at >= this.tailStart) {
        piece = (await this.sealedTail()).tail
        from = this.tailStart
      } else {
        const index = Math.min(this.blockCount - 1, Math.floor((at - this.header.length) / this.stride))
        piece = await this.block(index)
        from = this.header.length + index * this.stride
      }
      const within = at - from
      const take = Math.min(piece.length - within, stop - at)
      if (take <= 0) throw new Error('a sealed piece is shorter than its place in the object')
      out.set(piece.subarray(within, within + take), at - start)
      at += take
    }
    return { bytes: out, done: stop >= this.size }
  }

  close(): void {
    this.kept.clear()
    this.encryptor?.free()
    this.encryptor = null
  }

  private async block(index: number): Promise<Uint8Array> {
    return this.kept.get(index) ?? this.sealUpTo(index)
  }

  /** Seals on to block `index` (from the start again when it is behind) and gives that block. */
  private async sealUpTo(index: number): Promise<Uint8Array> {
    if (!this.encryptor || this.next > index) {
      this.encryptor?.free()
      this.encryptor = await this.options.open()
      this.next = 0
    }
    const encryptor = this.encryptor
    let sealed: Uint8Array = new Uint8Array(0)
    while (this.next <= index) {
      const at = this.next
      const length = encryptor.plainLength(at)
      const from = at * DRIVE_BLOCK_SIZE
      const plain = length > 0 ? await this.plaintext.read(from, from + length) : new Uint8Array(0)
      if (plain.length !== length) throw new Error('the file changed while it was being read')
      sealed = encryptor.sealNext(plain)
      this.kept.set(at, sealed)
      this.kept.delete(at - KEEP_BLOCKS)
      this.next = at + 1
    }
    return sealed
  }

  /** The tail: kept, or made once one encryptor has sealed every block. */
  private async sealedTail(): Promise<SealedTail> {
    if (this.tail) return this.tail
    const last = this.blockCount - 1
    if (this.next !== this.blockCount) await this.sealUpTo(last)
    const encryptor = this.encryptor
    if (!encryptor || this.next !== this.blockCount) throw new Error('the revision is not sealed to its end')
    const made = encryptor.finish(this.options.signer)
    if (made.tail.length !== this.size - this.tailStart) throw new Error('the tail is not the length the layout gives')
    // Kept before any of it goes out: the manifest's nonce is random, so it
    // can never be made the same again.
    await this.options.onTail?.(made)
    this.tail = made
    return made
  }
}
