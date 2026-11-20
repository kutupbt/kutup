import { describe, it, expect } from 'vitest'
import { generateKey } from './symmetric'

describe('symmetric — generateKey', () => {
  it('returns 32-byte (256-bit) keys', async () => {
    const k = await generateKey()
    expect(k.length).toBe(32)
  })

  it('returns different keys on each call', async () => {
    const a = await generateKey()
    const b = await generateKey()
    expect(Array.from(a)).not.toEqual(Array.from(b))
  })
})
