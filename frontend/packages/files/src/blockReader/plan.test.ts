import { describe, expect, it } from 'vitest'
import { answerSpan, BlockCache, blockCountOf, blockPlainLength, cacheBlocksFor, resolveRange } from './plan'

const B = 4 * 1024 * 1024

describe('the block plan', () => {
  it('counts blocks as the format does: an empty file is one empty block', () => {
    expect(blockCountOf({ size: 0, blockSize: B })).toBe(1)
    expect(blockCountOf({ size: B, blockSize: B })).toBe(1)
    expect(blockCountOf({ size: B + 1, blockSize: B })).toBe(2)
    expect(blockPlainLength({ size: 2 * B + 17, blockSize: B }, 2)).toBe(17)
    expect(blockPlainLength({ size: 2 * B, blockSize: B }, 1)).toBe(B)
  })

  it('resolves a-b, a- and -k against the size, or names no byte', () => {
    expect(resolveRange({ start: 0, end: 1 }, 100)).toEqual({ start: 0, end: 1 })
    expect(resolveRange({ start: 10, end: null }, 100)).toEqual({ start: 10, end: 99 })
    expect(resolveRange({ start: 90, end: 500 }, 100)).toEqual({ start: 90, end: 99 })
    expect(resolveRange({ suffix: 10 }, 100)).toEqual({ start: 90, end: 99 })
    expect(resolveRange({ suffix: 500 }, 100)).toEqual({ start: 0, end: 99 })
    expect(resolveRange({ start: 100, end: null }, 100)).toBeNull()
    expect(resolveRange({ start: 0, end: null }, 0)).toBeNull()
    expect(resolveRange({ suffix: 5 }, 0)).toBeNull()
    expect(resolveRange({ start: 5, end: 4 }, 100)).toBeNull()
  })

  it('answers to the end of the block the first byte is in, never past what was asked or the cap', () => {
    const file = { size: 3 * B, blockSize: B }
    // Safari asks for the whole file: one block back.
    expect(answerSpan(file, { start: 0, end: 3 * B - 1 }, 5 * 1024 * 1024)).toEqual({ start: 0, end: B - 1 })
    // Its probe.
    expect(answerSpan(file, { start: 0, end: 1 }, 5 * 1024 * 1024)).toEqual({ start: 0, end: 1 })
    // Inside a block: to its end.
    expect(answerSpan(file, { start: B + 10, end: null }, 5 * 1024 * 1024)).toEqual({ start: B + 10, end: 2 * B - 1 })
    // The cap below a block.
    expect(answerSpan(file, { start: 0, end: null }, 1000)).toEqual({ start: 0, end: 999 })
    // The tail an MP4 with its moov at the end asks for.
    expect(answerSpan(file, { suffix: 100 }, 5 * 1024 * 1024)).toEqual({ start: 3 * B - 100, end: 3 * B - 1 })
    expect(answerSpan(file, { start: 3 * B, end: null }, 5 * 1024 * 1024)).toBeNull()
  })

  it('a short last block ends the answer at the end of the file', () => {
    const file = { size: 2 * B + 17, blockSize: B }
    expect(answerSpan(file, { start: 2 * B, end: null }, 5 * 1024 * 1024)).toEqual({ start: 2 * B, end: 2 * B + 16 })
    expect(answerSpan(file, { start: 2 * B + 16, end: 2 * B + 100 }, 5 * 1024 * 1024)).toEqual({ start: 2 * B + 16, end: 2 * B + 16 })
  })

  it('keeps the most recently used blocks', () => {
    const cache = new BlockCache(2)
    cache.set(0, new Uint8Array([0]))
    cache.set(1, new Uint8Array([1]))
    expect(cache.get(0)).toEqual(new Uint8Array([0]))
    cache.set(2, new Uint8Array([2]))
    expect(cache.has(1)).toBe(false)
    expect(cache.has(0)).toBe(true)
    expect(cache.has(2)).toBe(true)
    expect(cache.size).toBe(2)
    cache.clear()
    expect(cache.size).toBe(0)
  })

  it('keeps one block fewer on iOS, never none', () => {
    expect(cacheBlocksFor(3, 'Mozilla/5.0 (X11; Linux x86_64) Chrome/140')).toBe(3)
    expect(cacheBlocksFor(3, 'Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X)')).toBe(2)
    // iPadOS says it is a Mac, with touch.
    expect(cacheBlocksFor(3, 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)', 5)).toBe(2)
    expect(cacheBlocksFor(3, 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)', 0)).toBe(3)
    expect(cacheBlocksFor(1, 'iPhone')).toBe(1)
  })
})
