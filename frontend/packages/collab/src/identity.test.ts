import { describe, it, expect } from 'vitest'
import { randomSenderSeqPrefix } from './identity'

describe('randomSenderSeqPrefix', () => {
  it('returns a BigInt with the lower 32 bits zero (counter slot)', () => {
    for (let i = 0; i < 50; i++) {
      const p = randomSenderSeqPrefix()
      // The lower 32 bits MUST be zero — that's the per-frame counter slot.
      expect(p & 0xFFFFFFFFn).toBe(0n)
    }
  })

  it('returns a BigInt strictly greater than mustExceed', () => {
    const high = 1234567890n << 32n
    for (let i = 0; i < 50; i++) {
      const p = randomSenderSeqPrefix(high)
      expect(p).toBeGreaterThan(high)
    }
  })

  it('produces different prefixes across calls (entropy sanity)', () => {
    const seen = new Set<string>()
    for (let i = 0; i < 100; i++) {
      seen.add(randomSenderSeqPrefix().toString())
    }
    // 100 calls of a 32-bit random space have ~0% collision; fewer than
    // 95 distinct outputs would mean the RNG is weakened.
    expect(seen.size).toBeGreaterThanOrEqual(95)
  })

  it('upper 31 bits span the full range across many calls', () => {
    // 31 bits, not 32: the top bit is masked off to keep the resulting
    // bigint within signed int64 (Postgres BIGINT). Still 2^31 distinct
    // prefixes — collision odds remain negligible.
    let maxUpper = 0n
    let topBitSet = false
    for (let i = 0; i < 1000; i++) {
      const upper = randomSenderSeqPrefix() >> 32n
      if (upper > maxUpper) maxUpper = upper
      if (upper >= 0x80000000n) topBitSet = true
    }
    // After 1000 samples the max upper value is comfortably > 2^28.
    expect(maxUpper).toBeGreaterThan(1n << 28n)
    expect(topBitSet, 'top bit must NEVER be set (would overflow signed int64)').toBe(false)
  })

  it('mustExceed=0 always wins on first roll', () => {
    // With mustExceed=0n and a 32-bit random in the upper half, any non-
    // zero output passes. Even random=0 would loop, but the loop
    // terminates because crypto.getRandomValues won't return 0 every
    // iteration.
    const p = randomSenderSeqPrefix(0n)
    expect(p).toBeGreaterThan(0n)
  })
})
