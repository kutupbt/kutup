import { describe, expect, it } from 'vitest'
import { isAddress, parseRecipients } from './recipients'

describe('recipients', () => {
  it('splits pasted lists into mailboxes', () => {
    expect(parseRecipients('Ayşe Yılmaz <Ayse@Kutup.dev>, bob@example.org; "Carol C" <carol@x.org>\n')).toEqual([
      { name: 'Ayşe Yılmaz', address: 'ayse@kutup.dev' },
      { name: '', address: 'bob@example.org' },
      { name: 'Carol C', address: 'carol@x.org' },
    ])
  })

  it('accepts addresses and refuses what is not one', () => {
    expect(isAddress('ayse@kutup.dev')).toBe(true)
    expect(isAddress('a.b+tag@mail.example.co.uk')).toBe(true)
    expect(isAddress('ayse@kutup')).toBe(false)
    expect(isAddress('Ayşe <ayse@kutup.dev>')).toBe(false)
    expect(isAddress('a b@c.org')).toBe(false)
  })
})
