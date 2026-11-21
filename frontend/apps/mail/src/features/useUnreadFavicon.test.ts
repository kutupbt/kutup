import { describe, expect, it } from 'vitest'
import { badgeFavicon } from './useUnreadFavicon'

const SVG = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 56 44"><polygon points="10,13 16,22 10,31 4,22"/></svg>'

describe('the unread favicon', () => {
  it('draws the count on the icon, inside its svg', () => {
    const out = badgeFavicon(SVG, 7)
    expect(out.startsWith(SVG.slice(0, -'</svg>'.length))).toBe(true)
    expect(out).toContain('>7</text>')
    expect(out.endsWith('</svg>')).toBe(true)
    expect(out.match(/<\/svg>/g)).toHaveLength(1)
  })

  it('reads 99+ above 99, smaller', () => {
    expect(badgeFavicon(SVG, 100)).toContain('font-size="13" fill="#fff">99+</text>')
    expect(badgeFavicon(SVG, 99)).toContain('font-size="18" fill="#fff">99</text>')
  })
})
