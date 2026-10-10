import { describe, expect, it } from 'vitest'
import { hasKutupLinks, kutupHref, kutupLinkMarkdown, parseKutupHref } from './kutupLinks'

const ID = '3185a533-e57e-46f0-a684-424414a9954a'

describe('Kutup links', () => {
  it('reads file and folder links, and nothing else', () => {
    expect(parseKutupHref(`kutup:file/${ID}`)).toEqual({ type: 'file', id: ID })
    expect(parseKutupHref(`kutup:folder/${ID.toUpperCase()}`)).toEqual({ type: 'folder', id: ID })
    expect(parseKutupHref('kutup:asset/img-1')).toBeNull()
    expect(parseKutupHref(`kutup:file/${ID}/../x`)).toBeNull()
    expect(parseKutupHref('https://example.org')).toBeNull()
  })

  it('round-trips', () => {
    expect(parseKutupHref(kutupHref({ type: 'folder', id: ID }))).toEqual({ type: 'folder', id: ID })
  })

  it('writes Markdown with the name escaped', () => {
    expect(kutupLinkMarkdown('Trip [2026]', { type: 'file', id: ID })).toBe(`[Trip \\[2026\\]](kutup:file/${ID})`)
    expect(kutupLinkMarkdown('photo', { type: 'file', id: ID }, true)).toBe(`![photo](kutup:file/${ID})`)
  })

  it('spots links in a note', () => {
    expect(hasKutupLinks(`see [a](kutup:file/${ID})`)).toBe(true)
    expect(hasKutupLinks('see [a](https://x.y) and ![p](kutup:asset/img-1)')).toBe(false)
  })
})
