import { EditorSelection, EditorState } from '@codemirror/state'
import { EditorView } from '@codemirror/view'
import { markdown, markdownLanguage } from '@codemirror/lang-markdown'
import { afterEach, describe, expect, it } from 'vitest'
import { hasStructure, htmlToMarkdown, isLinkTarget, linkMarkdown, pasteMarkdown } from './pasteMarkdown'

describe('htmlToMarkdown', () => {
  it('keeps the shape of rich text', () => {
    expect(htmlToMarkdown('<h2>Plan</h2><p>Some <strong>bold</strong> and <em>italic</em> with <a href="https://example.org">a link</a>.</p>')).toBe(
      '## Plan\n\nSome **bold** and _italic_ with [a link](https://example.org).',
    )
    expect(htmlToMarkdown('<ul><li>one</li><li>two</li></ul><ol><li>first</li><li>second</li></ol>')).toBe('- one\n- two\n\n1. first\n2. second')
    expect(htmlToMarkdown('<ul><li>outer<ul><li>inner</li></ul></li></ul>')).toBe('- outer\n  - inner')
    expect(htmlToMarkdown('<blockquote><p>quoted</p></blockquote><pre><code>let a = 1</code></pre>')).toBe('> quoted\n\n```\nlet a = 1\n```')
  })

  it('makes tables and task lists GitHub-flavoured', () => {
    const table = htmlToMarkdown('<table><thead><tr><th>Day</th><th>City</th></tr></thead><tbody><tr><td>1</td><td>Istanbul</td></tr></tbody></table>')
    expect(table).toContain('| Day | City |')
    expect(table).toMatch(/\| 1 +\| Istanbul \|/)
    expect(htmlToMarkdown('<ul><li><input type="checkbox" checked> done</li></ul>')).toBe('- [x] done')
  })

  it('drops what should not come along', () => {
    expect(htmlToMarkdown('<p>hi</p><script>alert(1)</script><style>p{}</style>')).toBe('hi')
    expect(htmlToMarkdown('<p><a href="javascript:alert(1)">click</a></p>')).toBe('click')
    expect(htmlToMarkdown('<p><img alt="chart" src="data:image/png;base64,AAAA"></p>')).toBe('chart')
    expect(htmlToMarkdown('<p><img alt="logo" src="https://example.org/logo.png"></p>')).toBe('![logo](https://example.org/logo.png)')
  })

  it('straightens Google Docs', () => {
    const docs =
      '<b style="font-weight:normal;" id="docs-internal-guid-1234"><p><span style="font-weight:400">plain </span>' +
      '<span style="font-weight:700">strong</span> <span style="font-style:italic">slanted</span></p></b>'
    expect(htmlToMarkdown(docs)).toBe('plain **strong** _slanted_')
  })
})

describe('what a paste becomes', () => {
  it('converts structured HTML only', () => {
    expect(hasStructure('<p>para</p>')).toBe(true)
    // A code editor's clipboard: styled spans in divs.
    expect(hasStructure('<div style="color:#000"><span style="color:#f00">const</span> a</div>')).toBe(false)
  })

  it('knows a link target', () => {
    expect(isLinkTarget(' https://example.org/a?b=1 ')).toBe(true)
    expect(isLinkTarget('mailto:me@example.org')).toBe(true)
    expect(isLinkTarget('kutup:file/3185a533-e57e-46f0-a684-424414a9954a')).toBe(true)
    expect(isLinkTarget('javascript:alert(1)')).toBe(false)
    expect(isLinkTarget('two words')).toBe(false)
    expect(linkMarkdown('a [b]', 'https://x.y')).toBe('[a \\[b\\]](https://x.y)')
  })

  // Each view is destroyed after its test: a live one schedules a layout
  // measurement, which jsdom cannot do.
  const views: EditorView[] = []
  afterEach(() => {
    for (const v of views.splice(0)) v.destroy()
  })
  const view = (doc: string, from: number, to = from) => {
    const v = new EditorView({
      state: EditorState.create({ doc, selection: EditorSelection.range(from, to), extensions: [markdown({ base: markdownLanguage })] }),
      parent: document.createElement('div'),
    })
    views.push(v)
    return v
  }

  it('starts pasted blocks after a blank line', () => {
    const v = view('text\n', 5)
    expect(pasteMarkdown(v, 'a', '<h2>Head</h2><p>body</p>', false)).toBe(true)
    expect(v.state.doc.toString()).toBe('text\n\n## Head\n\nbody')
  })

  it('links selected text to a pasted URL', () => {
    const v = view('see the docs here', 8, 12)
    expect(pasteMarkdown(v, 'https://example.org', '', false)).toBe(true)
    expect(v.state.doc.toString()).toBe('see the [docs](https://example.org) here')
  })

  it('pastes rich text as Markdown, but not plain pastes or into code', () => {
    const rich = '<ul><li><strong>a</strong></li></ul>'
    const v = view('x', 1)
    expect(pasteMarkdown(v, 'a', rich, false)).toBe(true)
    expect(v.state.doc.toString()).toBe('x- **a**')
    expect(pasteMarkdown(view('x', 1), 'a', rich, true)).toBe(false)
    expect(pasteMarkdown(view('```\ncode\n```', 6), 'a', rich, false)).toBe(false)
    // A URL with nothing selected pastes as itself.
    expect(pasteMarkdown(view('x', 1), 'https://example.org', '', false)).toBe(false)
  })
})
