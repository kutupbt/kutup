import type { Element, Root } from 'hast'
import { describe, expect, it } from 'vitest'
import { parseCodeMeta, rehypeCodeLines } from './codeBlocks'

describe('parseCodeMeta', () => {
  it('reads the title, line numbers and highlighted lines', () => {
    const meta = parseCodeMeta('title="greet.py" showLineNumbers {2,4-6}')
    expect(meta.title).toBe('greet.py')
    expect(meta.lineNumbers).toBe(true)
    expect([...meta.highlight]).toEqual([2, 4, 5, 6])
  })

  it('takes single quotes and any order', () => {
    const meta = parseCodeMeta("{3} title='a b.ts'")
    expect(meta).toMatchObject({ title: 'a b.ts', lineNumbers: false })
    expect([...meta.highlight]).toEqual([3])
  })

  it('has no options for plain fences', () => {
    expect(parseCodeMeta(null)).toMatchObject({ title: null, lineNumbers: false })
    expect(parseCodeMeta('').highlight.size).toBe(0)
    // Only the exact word counts.
    expect(parseCodeMeta('showLineNumbersX').lineNumbers).toBe(false)
  })

  it('ignores bad ranges and caps runaway ones', () => {
    expect([...parseCodeMeta('{0,2,5-3}').highlight]).toEqual([2])
    expect(parseCodeMeta('{a,2}').highlight.size).toBe(0)
    expect(parseCodeMeta('{1-99999999}').highlight.size).toBe(100_000)
  })
})

describe('rehypeCodeLines', () => {
  const block = (properties: Element['properties']): Root => ({
    type: 'root',
    children: [{
      type: 'element',
      tagName: 'pre',
      properties: {},
      children: [{
        type: 'element',
        tagName: 'code',
        properties,
        children: [
          // A highlight.js span running across a line break.
          { type: 'element', tagName: 'span', properties: { className: ['hljs-string'] }, children: [{ type: 'text', value: '"a\nb"' }] },
          { type: 'text', value: '\nlast\n' },
        ],
      }],
    }],
  })
  const lines = (tree: Root) => ((tree.children[0] as Element).children[0] as Element).children as Element[]

  it('gives each line its own span, keeping the highlighting on both sides of a break', () => {
    const tree = block({ dataLineNumbers: 'true', dataHighlight: '2' })
    rehypeCodeLines()(tree)
    const out = lines(tree)
    expect(out).toHaveLength(3)
    expect(out.map((l) => l.properties.className)).toEqual([['code-line'], ['code-line', 'highlighted'], ['code-line']])
    expect((out[0].children[0] as Element).properties.className).toEqual(['hljs-string'])
    expect((out[1].children[0] as Element).properties.className).toEqual(['hljs-string'])
  })

  it('leaves blocks without options alone', () => {
    const tree = block({})
    rehypeCodeLines()(tree)
    expect(lines(tree)[0].tagName).toBe('span')
    expect(lines(tree)).toHaveLength(2)
  })
})
