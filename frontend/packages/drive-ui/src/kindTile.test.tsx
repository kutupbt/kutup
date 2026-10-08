// @vitest-environment jsdom
import { describe, expect, it } from 'vitest'
import { kindTileSvg } from './kindTile'

describe('kindTileSvg', () => {
  it('draws the kind in the theme colours, and falls back without them', async () => {
    document.documentElement.style.setProperty('--kind-spreadsheet', '#15803d')
    document.documentElement.style.setProperty('--kind-glyph', '#ffffff')
    const svg = await kindTileSvg('spreadsheet')
    expect(svg).toMatch(/^<svg xmlns="http:\/\/www.w3.org\/2000\/svg"/)
    expect(svg).toContain('fill="#15803d"')
    expect(svg).toContain('stroke="#ffffff"')
    expect(new DOMParser().parseFromString(svg, 'image/svg+xml').querySelector('parsererror')).toBeNull()

    document.documentElement.removeAttribute('style')
    expect(await kindTileSvg('pdf')).toContain('fill="#64748b"')
  })
})
