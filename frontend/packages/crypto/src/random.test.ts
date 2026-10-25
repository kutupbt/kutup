import { describe, expect, it } from 'vitest'

import { hash } from './hash'
import { fillRandom, randomBytes } from './random'

describe('the one random source', () => {
  it('gives the length asked for, past the Web Crypto quota', () => {
    expect(randomBytes(0)).toHaveLength(0)
    expect(randomBytes(32)).toHaveLength(32)
    const big = randomBytes(200_000)
    expect(big).toHaveLength(200_000)
    // The tail was filled too, not left zero.
    expect(big.subarray(150_000).some((byte) => byte !== 0)).toBe(true)
    expect(randomBytes(32)).not.toEqual(randomBytes(32))
  })

  it('fills a view in place, within its window', () => {
    const backing = new Uint8Array(48)
    const view = new Uint32Array(backing.buffer, 16, 4)
    expect(fillRandom(view)).toBe(view)
    expect(backing.subarray(0, 16).every((byte) => byte === 0)).toBe(true)
    expect(backing.subarray(32).every((byte) => byte === 0)).toBe(true)
  })
})

describe('the suite hash', () => {
  it('is SHA-256 under suite 1', async () => {
    const digest = await hash(new TextEncoder().encode('abc'))
    expect(Array.from(digest, (byte) => byte.toString(16).padStart(2, '0')).join('')).toBe(
      'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
    )
  })
})
