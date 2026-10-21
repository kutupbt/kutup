import { describe, expect, it } from 'vitest'
import { bytesToGib, generateTempPassword, gibToBytes, windowUnit } from './helpers'

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

  it('name rate-limit windows in their largest whole unit', () => {
    expect(windowUnit(60)).toEqual({ unit: 'minutes', count: 1 })
    expect(windowUnit(900)).toEqual({ unit: 'minutes', count: 15 })
    expect(windowUnit(3600)).toEqual({ unit: 'hours', count: 1 })
    expect(windowUnit(86_400)).toEqual({ unit: 'days', count: 1 })
    expect(windowUnit(90)).toEqual({ unit: 'seconds', count: 90 })
  })
})
