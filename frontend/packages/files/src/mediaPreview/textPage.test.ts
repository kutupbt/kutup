import { describe, expect, it } from 'vitest'
import { layoutTextPage } from './textPage'

describe('text page layout', () => {
  it('draws Markdown headings larger and bold, rules as rules', () => {
    const page = layoutTextPage('# Title\n\nBody text\n---\nMore', 'prose', 384, 512)
    const [title] = page.lines
    expect(title).toMatchObject({ text: 'Title', bold: true })
    expect(title!.size).toBeGreaterThan(page.lines.find((l) => l.text === 'Body text')!.size)
    expect(page.lines.some((l) => l.rule)).toBe(true)
  })

  it('wraps prose at spaces and cuts code lines', () => {
    const long = 'word '.repeat(60)
    expect(layoutTextPage(long, 'prose', 384, 512).lines.filter((l) => l.text).length).toBeGreaterThan(3)
    const code = layoutTextPage(`const x = ${'a'.repeat(200)}`, 'code', 384, 512)
    expect(code.lines).toHaveLength(1)
  })

  it('stops at the bottom of the page and never reads past the start of a huge file', () => {
    const page = layoutTextPage('line\n'.repeat(100_000), 'code', 384, 512)
    const last = page.lines.at(-1)!
    expect(last.y).toBeLessThan(512)
    expect(page.lines.length).toBeLessThan(40)
  })

  it('keeps headings literal in code', () => {
    expect(layoutTextPage('# not a heading', 'code', 384, 512).lines[0]).toMatchObject({ text: '# not a heading', bold: false })
  })
})
