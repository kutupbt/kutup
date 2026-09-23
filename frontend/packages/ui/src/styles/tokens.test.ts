import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'

const css = readFileSync(join(__dirname, 'tokens.css'), 'utf8')

function block(selector: string): Set<string> {
  const start = css.indexOf(`${selector} {`)
  const end = css.indexOf('\n}', start)
  const body = css.slice(start, end)
  return new Set([...body.matchAll(/^\s*(--[a-z0-9-]+):/gm)].map((m) => m[1]!))
}

// Theme-independent by design: the chrome keeps one palette in both themes,
// and the radius is not a colour.
const SHARED = new Set(['--radius'])
const isChrome = (token: string) => token.startsWith('--chrome')

describe('design tokens', () => {
  const light = block(':root')
  const dark = block('.dark')

  it('redefine every themed light token for dark', () => {
    const themed = [...light].filter((t) => !isChrome(t) && !SHARED.has(t))
    expect(themed.filter((t) => !dark.has(t))).toEqual([])
  })

  it('define nothing for dark that light lacks', () => {
    expect([...dark].filter((t) => !light.has(t))).toEqual([])
  })

  it('keep the chrome out of the dark block', () => {
    expect([...dark].filter(isChrome)).toEqual([])
  })

  it('expose every token as a Tailwind colour', () => {
    const exposed = new Set([...css.matchAll(/--color-([a-z0-9-]+): var\(--\1\)/g)].map((m) => `--${m[1]}`))
    const colours = [...light].filter((t) => !SHARED.has(t))
    expect(colours.filter((t) => !exposed.has(t))).toEqual([])
  })
})
