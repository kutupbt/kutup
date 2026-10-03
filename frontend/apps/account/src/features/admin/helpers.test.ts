import { describe, expect, it } from 'vitest'
import { bytesToGib, generateTempPassword, gibToBytes } from './helpers'

describe('admin helpers', () => {
  it('convert quotas between GiB and bytes', () => {
    expect(gibToBytes(10)).toBe(10 * 1024 ** 3)
    expect(bytesToGib(gibToBytes(2.5))).toBe(2.5)
  })

  it('generate unambiguous, unique temporary passwords', () => {
    const a = generateTempPassword()
    expect(a).toHaveLength(20)
    expect(a).not.toMatch(/[0O1lI]/)
    expect(generateTempPassword()).not.toBe(a)
  })
})
