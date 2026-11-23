import { describe, expect, it } from 'vitest'
import { encodeLinkFragment, parseLinkFragment } from './linkFragment'

describe('public link fragments', () => {
  it('carry the key behind v1., and read back', () => {
    const key = Uint8Array.from({ length: 32 }, (_, i) => i * 7)
    const fragment = encodeLinkFragment(key)
    expect(fragment).toMatch(/^#v1\.[A-Za-z0-9_-]{43}$/)
    expect(parseLinkFragment(fragment)).toEqual({ kind: 'key', key })
  })

  it('tell a newer format from a broken one', () => {
    expect(parseLinkFragment('#v2.anything')).toEqual({ kind: 'newer' })
    expect(parseLinkFragment('#key=abc')).toEqual({ kind: 'invalid' })
    expect(parseLinkFragment('#v1.short')).toEqual({ kind: 'invalid' })
    expect(parseLinkFragment('')).toEqual({ kind: 'invalid' })
  })
})
