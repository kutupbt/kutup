import { markdown, markdownLanguage } from '@codemirror/lang-markdown'
import { forceParsing } from '@codemirror/language'
import { EditorState } from '@codemirror/state'
import { EditorView } from '@codemirror/view'
import { describe, expect, it } from 'vitest'
import { codeBlockPreview } from './codeBlockPreview'

const NOTE = 'Intro\n\n```python title="greet.py" showLineNumbers {2}\ndef greet(name):\n    return name\n```\n\nAfter\n'

function view(cursor: number): EditorView {
  const state = EditorState.create({
    doc: NOTE,
    selection: { anchor: cursor },
    extensions: [markdown({ base: markdownLanguage }), codeBlockPreview({ copy: 'Copy code', copied: 'Copied' })],
  })
  const view = new EditorView({ state, parent: document.body })
  // Finish the parse through the view, as its background parser does in the
  // app, so the preview is rebuilt from the full tree however slow the run.
  forceParsing(view, state.doc.length, 5000)
  return view
}

describe('code block live preview', () => {
  it('draws a block away from the cursor as Read mode does', () => {
    const v = view(0)
    const block = v.dom.querySelector('.cm-lp-codeblock')
    expect(block).not.toBeNull()
    expect(block!.querySelector('.code-block-title')?.textContent).toBe('greet.py')
    const code = block!.querySelector('pre code')!
    expect(code.classList.contains('language-python')).toBe(true)
    expect(code.getAttribute('data-line-numbers')).toBe('true')
    expect(code.querySelectorAll('.code-line')).toHaveLength(2)
    expect(code.querySelector('.code-line.highlighted')?.textContent).toContain('return name')
    expect(code.querySelector('.hljs-keyword')).not.toBeNull()
    // The fences are not shown.
    expect(v.dom.textContent).not.toContain('```')
    v.destroy()
  })

  it('opens a block when the cursor arrows onto it, from below and from above', async () => {
    const { runScopeHandlers } = await import('@codemirror/view')
    const below = view(NOTE.indexOf('After'))
    // "After" is two lines below the fence: the first press reaches the empty line.
    runScopeHandlers(below, new KeyboardEvent('keydown', { key: 'ArrowUp' }), 'editor')
    expect(below.dom.querySelector('.cm-lp-codeblock')).not.toBeNull()
    below.dispatch({ selection: { anchor: NOTE.indexOf('```\n\nAfter') + 4 } })
    expect(runScopeHandlers(below, new KeyboardEvent('keydown', { key: 'ArrowUp' }), 'editor')).toBe(true)
    expect(below.state.doc.lineAt(below.state.selection.main.head).text).toBe('```')
    expect(below.dom.querySelector('.cm-lp-codeblock')).toBeNull()
    below.destroy()

    const above = view(NOTE.indexOf('\n\n```python') + 1)
    expect(runScopeHandlers(above, new KeyboardEvent('keydown', { key: 'ArrowDown' }), 'editor')).toBe(true)
    expect(above.state.doc.lineAt(above.state.selection.main.head).text).toMatch(/^```python/)
    above.destroy()
  })

  it('shows the Markdown while the cursor is in the block', () => {
    const v = view(NOTE.indexOf('def greet'))
    expect(v.dom.querySelector('.cm-lp-codeblock')).toBeNull()
    expect(v.dom.textContent).toContain('```python')
    v.destroy()
  })
})
