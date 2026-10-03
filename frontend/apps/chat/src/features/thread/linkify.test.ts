import { describe, expect, it } from 'vitest'
import { linkify } from './linkify'

describe('linkify', () => {
  it('links http(s) and www. addresses, leaving trailing punctuation as text', () => {
    expect(linkify('see https://kutup.example/a?b=1, and www.example.org.')).toEqual([
      { kind: 'text', value: 'see ' },
      { kind: 'link', value: 'https://kutup.example/a?b=1', href: 'https://kutup.example/a?b=1' },
      { kind: 'text', value: ', and ' },
      { kind: 'link', value: 'www.example.org', href: 'https://www.example.org' },
      { kind: 'text', value: '.' },
    ])
  })

  it('never links other schemes', () => {
    expect(linkify('javascript:alert(1) data:text/html,x')).toEqual([
      { kind: 'text', value: 'javascript:alert(1) data:text/html,x' },
    ])
  })
})
