import { describe, expect, it } from 'vitest'
import { isNewerFormatError } from './newerFormat'

describe('isNewerFormatError', () => {
  it('tells newer from corrupt', () => {
    expect(isNewerFormatError('newer format: file metadata')).toBe(true)
    expect(isNewerFormatError(new Error('newer format: x'))).toBe(true)
    expect(isNewerFormatError('invalid input: file metadata: decode')).toBe(false)
    expect(isNewerFormatError(undefined)).toBe(false)
  })
})
