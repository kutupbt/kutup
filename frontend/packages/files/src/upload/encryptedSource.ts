// A Drive file blob, encrypted as tus asks for it (tus-js-client's
// `fileReader`): any byte range of the ciphertext, produced from the
// plaintext on demand. tus's own stream source keeps everything it reads
// until the range it wants, which on resuming a 9 GB upload means 9 GB in
// memory; this keeps two encrypted messages at most.
//
// The ciphertext is the 56-byte prefix (Drive header, secretstream header)
// and then one message per 5 MiB of plaintext, each 17 bytes longer. tus
// sends ranges of one message's length, which the prefix shifts across two
// messages. A range already sent is asked for again when a request is
// retried: the last two messages stay at hand. A range further on (an
// upload resumed after a reload) is reached by encrypting the messages
// before it again and dropping them; the encryptor only moves forward, so
// one earlier than that starts the stream over from its header.

import {
  DRIVE_FILE_BLOB_CIPHER_CHUNK,
  DRIVE_FILE_BLOB_PREFIX_BYTES,
  fileBlobCipherSize,
  type FileBlobStreamEncryptorV1,
} from '@kutup/crypto/fileBlob'
import { PLAIN_CHUNK } from '@kutup/crypto/streamEncryptor'

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

export class EncryptedFileSource implements TusFileSource {
  readonly size: number
  private readonly messages: number
  private encryptor: FileBlobStreamEncryptorV1 | null = null
  /** The message the encryptor produces next. */
  private next = 0
  private readonly kept = new Map<number, Uint8Array>()

  constructor(
    private readonly plaintext: PlaintextSource,
    /** The stream from its start: the same prefix, the same bytes every time. */
    private readonly openStream: () => Promise<FileBlobStreamEncryptorV1>,
    private readonly prefix: Uint8Array,
  ) {
    if (prefix.length !== DRIVE_FILE_BLOB_PREFIX_BYTES) throw new Error('Drive file-blob prefix has the wrong length')
    this.size = fileBlobCipherSize(plaintext.size)
    this.messages = Math.max(1, Math.ceil(plaintext.size / PLAIN_CHUNK))
  }

  async slice(start: number, end: number): Promise<{ value: Blob; done: boolean }> {
    const { bytes, done } = await this.bytes(start, end)
    return { value: new Blob([bytes as Uint8Array<ArrayBuffer>]), done }
  }

  /** The ciphertext at [start, end), as bytes. */
  async bytes(start: number, end: number): Promise<{ bytes: Uint8Array; done: boolean }> {
    const stop = Math.min(end, this.size)
    if (start >= stop) return { bytes: new Uint8Array(0), done: true }
    const out = new Uint8Array(stop - start)
    let at = start
    while (at < stop) {
      if (at < DRIVE_FILE_BLOB_PREFIX_BYTES) {
        const upTo = Math.min(DRIVE_FILE_BLOB_PREFIX_BYTES, stop)
        out.set(this.prefix.subarray(at, upTo), at - start)
        at = upTo
        continue
      }
      const index = Math.floor((at - DRIVE_FILE_BLOB_PREFIX_BYTES) / DRIVE_FILE_BLOB_CIPHER_CHUNK)
      const message = await this.message(index)
      const within = at - DRIVE_FILE_BLOB_PREFIX_BYTES - index * DRIVE_FILE_BLOB_CIPHER_CHUNK
      const take = Math.min(message.length - within, stop - at)
      if (take <= 0) throw new Error('encrypted message is shorter than its place in the file')
      out.set(message.subarray(within, within + take), at - start)
      at += take
    }
    return { bytes: out, done: stop >= this.size }
  }

  close(): void {
    this.kept.clear()
    this.encryptor = null
  }

  private async message(index: number): Promise<Uint8Array> {
    const kept = this.kept.get(index)
    if (kept) return kept
    if (index >= this.messages) throw new Error('range beyond the end of the file')
    if (!this.encryptor || index < this.next) {
      this.encryptor = await this.openStream()
      this.next = 0
      this.kept.clear()
    }
    let message: Uint8Array = new Uint8Array(0)
    while (this.next <= index) {
      const at = this.next
      const from = at * PLAIN_CHUNK
      const to = Math.min(from + PLAIN_CHUNK, this.plaintext.size)
      const plain = from < to ? await this.plaintext.read(from, to) : new Uint8Array(0)
      if (plain.length !== to - from) throw new Error('the file changed while it was being read')
      message = this.encryptor.push(plain, at === this.messages - 1)
      this.kept.set(at, message)
      this.kept.delete(at - 2)
      this.next = at + 1
    }
    return message
  }
}
