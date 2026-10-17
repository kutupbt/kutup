import { describe, expect, it } from 'vitest'
import { DEFAULT_OPTIONS, entropyBits, generatePassword, randomBelow, randomVaultKey, strengthOf } from './generator'

describe('the password generator', () => {
  it('makes passwords of the length asked, with every chosen kind', () => {
    for (let i = 0; i < 50; i++) {
      const p = generatePassword(DEFAULT_OPTIONS)
      expect(p).toHaveLength(20)
      expect(p).toMatch(/[a-z]/)
      expect(p).toMatch(/[A-Z]/)
      expect(p).toMatch(/[0-9]/)
      expect(p).toMatch(/[^a-zA-Z0-9]/)
    }
  })

  it('leaves out look-alikes and kinds not chosen', () => {
    const p = generatePassword({ ...DEFAULT_OPTIONS, length: 200, symbols: false, avoidLookAlikes: true })
    expect(p).not.toMatch(/[0O1lI|]/)
    expect(p).toMatch(/^[a-zA-Z0-9]+$/)
  })

  it('refuses no kinds at all', () => {
    expect(() => generatePassword({ ...DEFAULT_OPTIONS, lower: false, upper: false, digits: false, symbols: false })).toThrow()
  })

  it('draws uniformly in range', () => {
    const seen = new Set<number>()
    for (let i = 0; i < 500; i++) {
      const n = randomBelow(7)
      expect(n).toBeGreaterThanOrEqual(0)
      expect(n).toBeLessThan(7)
      seen.add(n)
    }
    expect(seen.size).toBe(7)
  })

  it('estimates strength', () => {
    expect(entropyBits(DEFAULT_OPTIONS)).toBeGreaterThan(120)
    expect(strengthOf('abc')).toBe('weak')
    expect(strengthOf('Summer2024')).toBe('fair')
    expect(strengthOf(generatePassword(DEFAULT_OPTIONS))).toBe('strong')
  })
})

describe('randomVaultKey', () => {
  it('is five groups of five base32 characters, different each time', () => {
    const keys = new Set(Array.from({ length: 50 }, () => randomVaultKey()))
    expect(keys.size).toBe(50)
    for (const key of keys) expect(key).toMatch(/^[0-9a-hjkmnp-tv-z]{5}(-[0-9a-hjkmnp-tv-z]{5}){4}$/)
  })
})
