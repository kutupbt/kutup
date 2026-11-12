// What a block reader answers, worked out without any I/O
// (docs/plans/drive-block-format.md §4): which block a byte falls in, the
// span one ranged answer carries, and a small LRU of verified blocks.

/** A byte range as a media element asks for it: `bytes=a-b`, `bytes=a-`, or `bytes=-k` (the last k bytes). */
export type StreamRange = { start: number; end: number | null } | { suffix: number }

/** The plaintext of an object read by block. */
export interface BlockGeometry {
  /** Plaintext bytes in all. */
  size: number
  /** Plaintext bytes per block; the last block may be shorter. */
  blockSize: number
}

export function blockCountOf({ size, blockSize }: BlockGeometry): number {
  // An empty file is one empty last block.
  return Math.max(1, Math.ceil(size / blockSize))
}

/** The block byte `offset` falls in. */
export function blockOf(offset: number, blockSize: number): number {
  return Math.floor(offset / blockSize)
}

/** Block `index`'s plaintext length. */
export function blockPlainLength({ size, blockSize }: BlockGeometry, index: number): number {
  return Math.max(0, Math.min(blockSize, size - index * blockSize))
}

/** The first and last byte `range` names in an object of `size` bytes, or null when it names none (a 416). */
export function resolveRange(range: StreamRange, size: number): { start: number; end: number } | null {
  if ('suffix' in range) {
    if (range.suffix <= 0 || size === 0) return null
    return { start: Math.max(0, size - range.suffix), end: size - 1 }
  }
  if (range.start >= size || (range.end !== null && range.end < range.start)) return null
  return { start: range.start, end: range.end === null ? size - 1 : Math.min(range.end, size - 1) }
}

/**
 * The bytes one answer to `range` carries: from its first byte to the end of
 * the block that byte is in, never past what was asked, and at most
 * `maxBytes`. A shorter 206 is valid HTTP; the player asks again for the
 * rest. Null when the range names no byte.
 */
export function answerSpan(geometry: BlockGeometry, range: StreamRange, maxBytes: number): { start: number; end: number } | null {
  const resolved = resolveRange(range, geometry.size)
  if (!resolved) return null
  const blockEnd = (blockOf(resolved.start, geometry.blockSize) + 1) * geometry.blockSize - 1
  const end = Math.min(resolved.end, blockEnd, resolved.start + Math.max(1, maxBytes) - 1)
  return { start: resolved.start, end }
}

/** Verified plaintext blocks, the least recently used dropped first. */
export class BlockCache {
  private readonly blocks = new Map<number, Uint8Array>()

  constructor(private readonly capacity: number) {}

  get(index: number): Uint8Array | undefined {
    const block = this.blocks.get(index)
    if (block) {
      this.blocks.delete(index)
      this.blocks.set(index, block)
    }
    return block
  }

  has(index: number): boolean {
    return this.blocks.has(index)
  }

  set(index: number, block: Uint8Array): void {
    this.blocks.delete(index)
    this.blocks.set(index, block)
    while (this.blocks.size > Math.max(1, this.capacity)) {
      const oldest = this.blocks.keys().next().value as number
      this.blocks.delete(oldest)
    }
  }

  get size(): number {
    return this.blocks.size
  }

  clear(): void {
    this.blocks.clear()
  }
}

/** iOS gives a tab little memory: one block fewer there (docs/plans/drive-block-format.md §7). */
export function cacheBlocksFor(setting: number, userAgent: string, maxTouchPoints = 0): number {
  const ios = /iPad|iPhone|iPod/.test(userAgent) || (/Macintosh/.test(userAgent) && maxTouchPoints > 1)
  return Math.max(1, ios ? setting - 1 : setting)
}
