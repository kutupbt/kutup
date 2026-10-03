import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'

const css = readFileSync(join(__dirname, 'tokens.css'), 'utf8')

function block(selector: string): Set<string> {
  const start = css.indexOf(`${selector} {`)
  const end = css.indexOf('\n}', start)
  const body = css.slice(start, end)
  return new Set([...body.matchAll(/^\s*(--[a-z0-9-]+):/gm)].map((m) => m[1]))
}

// Theme-independent by design: the stage (call screens) stays dark in both
// themes, and the radius is not a colour.
const SHARED = new Set(['--radius'])
const isStage = (token: string) => token.startsWith('--stage')

describe('design tokens', () => {
  const light = block(':root')
  const dark = block('.dark')

  it('redefine every themed light token for dark', () => {
    const themed = [...light].filter((t) => !isStage(t) && !SHARED.has(t))
    expect(themed.filter((t) => !dark.has(t))).toEqual([])
  })

  it('define nothing for dark that light lacks', () => {
    expect([...dark].filter((t) => !light.has(t))).toEqual([])
  })

  it('keep the stage out of the dark block', () => {
    expect([...dark].filter(isStage)).toEqual([])
  })

  it('keep the sidebar readable in both themes', () => {
    const failures: string[] = []
    for (const selector of [':root', '.dark']) {
      const start = css.indexOf(`${selector} {`)
      const body = css.slice(start, css.indexOf('\n}', start))
      const hex = (name: string) => body.match(new RegExp(`--${name}:\\s*(#[0-9a-f]{6});`))?.[1]
      const surface = hex('chrome')!
      for (const [name, minimum] of [['chrome-foreground', 7], ['chrome-muted', 4.5], ['chrome-active', 4.5]] as const) {
        for (const background of [surface, hex('chrome-accent')!]) {
          const ratio = contrast(hex(name)!, background)
          if (ratio < minimum) failures.push(`${selector} --${name} on ${background} ${ratio.toFixed(2)}`)
        }
      }
    }
    expect(failures).toEqual([])
  })

  it('expose every token as a Tailwind colour', () => {
    const exposed = new Set([...css.matchAll(/--color-([a-z0-9-]+): var\(--\1\)/g)].map((m) => `--${m[1]}`))
    const colours = [...light].filter((t) => !SHARED.has(t))
    expect(colours.filter((t) => !exposed.has(t))).toEqual([])
  })

  it('keep every file-kind tile readable under its glyph (4.5:1) in both themes', () => {
    const values = (selector: string) => {
      const start = css.indexOf(`${selector} {`)
      const body = css.slice(start, css.indexOf('\n}', start))
      return new Map([...body.matchAll(/^\s*--(kind-[a-z-]+):\s*(#[0-9a-f]{6});/gm)].map((m) => [m[1], m[2]]))
    }
    const failures: string[] = []
    for (const selector of [':root', '.dark']) {
      const tokens = values(selector)
      const glyph = tokens.get('kind-glyph')
      expect(glyph, `${selector} --kind-glyph`).toBeDefined()
      for (const [name, hex] of tokens) {
        if (name === 'kind-glyph') continue
        const ratio = contrast(hex, glyph!)
        if (ratio < 4.5) failures.push(`${selector} --${name} ${ratio.toFixed(2)}`)
      }
    }
    expect(failures).toEqual([])
  })
})

function luminance(hex: string): number {
  const [r, g, b] = [1, 3, 5].map((i) => parseInt(hex.slice(i, i + 2), 16) / 255)
  const linear = (c: number) => (c <= 0.04045 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4)
  return 0.2126 * linear(r) + 0.7152 * linear(g) + 0.0722 * linear(b)
}

function contrast(a: string, b: string): number {
  const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x)
  return (hi + 0.05) / (lo + 0.05)
}
