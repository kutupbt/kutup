import { getCryptoWasm } from './rustWasm'

/** A chunk-at-a-time content hash (SHA-256, base64): a photo's `media.hash`. */
export interface ContentHasher {
  update(chunk: Uint8Array): void
  /** The hash; the hasher is spent. */
  finish(): string
}

export async function newContentHasher(): Promise<ContentHasher> {
  const module = await getCryptoWasm()
  const hasher = new module.ContentHasher()
  return {
    update: (chunk) => hasher.update(chunk),
    finish: () => {
      try {
        return hasher.finish()
      } finally {
        hasher.free()
      }
    },
  }
}

/** Hash a whole Blob, a slice at a time (never all of it in memory). */
export async function hashBlob(blob: Blob, signal?: AbortSignal): Promise<string> {
  const hasher = await newContentHasher()
  const slice = 4 * 1024 * 1024
  for (let pos = 0; pos < blob.size; pos += slice) {
    if (signal?.aborted) throw new DOMException('Hashing cancelled', 'AbortError')
    hasher.update(new Uint8Array(await blob.slice(pos, pos + slice).arrayBuffer()))
  }
  return hasher.finish()
}
