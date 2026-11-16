import { describe, expect, it } from 'vitest'
import { compareBytes } from './backup'

const utf8 = (text: string) => new TextEncoder().encode(text)

describe('compareBytes', () => {
  it('orders by UTF-8 bytes, not by JavaScript string comparison', () => {
    // As UTF-16 strings U+FFFF sorts after the surrogate pair of U+1F600;
    // in UTF-8 bytes it sorts before (docs/plans/format-evolution.md, rule 10).
    expect('￿' > '😀').toBe(true)
    expect(compareBytes(utf8('￿'), utf8('😀'))).toBeLessThan(0)
    expect(compareBytes(utf8('ab'), utf8('abc'))).toBeLessThan(0)
    expect(compareBytes(utf8('abc'), utf8('abc'))).toBe(0)
  })
})
