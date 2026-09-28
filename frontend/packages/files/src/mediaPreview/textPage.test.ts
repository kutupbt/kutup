import { describe, expect, it } from 'vitest'
import { layoutTextPage, stripInline } from './textPage'

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

  it('draws fenced code in a shaded box, without its fences', () => {
    const page = layoutTextPage('ygfyfy\n\n```python\nprint("hi")\n```\nafter', 'prose', 384, 512)
    expect(page.lines.map((l) => l.text)).toEqual(['ygfyfy', 'print("hi")', 'after'])
    const code = page.lines[1]!
    expect(code.mono).toBe(true)
    const box = page.boxes.find((b) => b.kind === 'code')!
    expect(box.y).toBeLessThan(code.y)
    expect(box.y + box.height).toBeGreaterThan(code.y + code.size)
    expect(page.lines[2]!.y).toBeGreaterThan(box.y + box.height)
  })

  it('keeps an unclosed fence as code to the end', () => {
    const page = layoutTextPage('```\nlet a = 1', 'prose', 384, 512)
    expect(page.lines[0]).toMatchObject({ text: 'let a = 1', mono: true })
    expect(page.boxes).toHaveLength(1)
  })

  it('gives list items markers and indents, tasks their boxes', () => {
    const page = layoutTextPage('- one\n  - nested\n1. first\n- [ ] todo\n- [x] done', 'prose', 384, 512)
    const [one, nested, first, todo, done] = page.lines
    expect(one).toMatchObject({ text: 'one', marker: { kind: 'bullet' } })
    expect(nested!.markerX!).toBeGreaterThan(one!.markerX!)
    expect(first).toMatchObject({ text: 'first', marker: { kind: 'number', text: '1.' } })
    expect(todo).toMatchObject({ text: 'todo', marker: { kind: 'task', checked: false } })
    expect(done).toMatchObject({ text: 'done', marker: { kind: 'task', checked: true } })
    expect(one!.x).toBeGreaterThan(one!.markerX!)
  })

  it('draws quotes muted beside a bar, and tables as rows', () => {
    const page = layoutTextPage('> quoted\n\n| a | b |\n|---|---|\n| 1 | 2 |', 'prose', 384, 512)
    expect(page.lines[0]).toMatchObject({ text: 'quoted', muted: true })
    expect(page.boxes.some((b) => b.kind === 'quote')).toBe(true)
    const cells = page.lines.slice(1)
    expect(cells.map((l) => l.text)).toEqual(['a', 'b', '1', '2'])
    // Columns line up; rows go down.
    expect(cells[1]!.x).toBeGreaterThan(cells[0]!.x)
    expect(cells[2]!.x).toBe(cells[0]!.x)
    expect(cells[2]!.y).toBeGreaterThan(cells[0]!.y)
  })

  it('leaves inline marks out', () => {
    expect(stripInline('**bold**, *it*, `code`, [link](https://x.y) and ![alt](p.png) ~~gone~~')).toBe('bold, it, code, link and alt gone')
    // A lone star is text.
    expect(stripInline('2 * 3')).toBe('2 * 3')
  })

  it('keeps fences literal in code files', () => {
    expect(layoutTextPage('```js', 'code', 384, 512).lines[0]).toMatchObject({ text: '```js', mono: true })
  })
})
