import { EditorSelection, EditorState, type StateCommand } from '@codemirror/state'
import { markdown } from '@codemirror/lang-markdown'
import { describe, expect, it } from 'vitest'
import { continueOrEndList, INSERTS, insertBlock, insertLink, setLineStyle, toggleWrap } from './markdownCommands'

/** Runs a command on `doc` with the selection at [from, to]; returns text and selection. */
function run(command: StateCommand, doc: string, from: number, to = from) {
  let state = EditorState.create({ doc, selection: EditorSelection.range(from, to), extensions: [markdown()] })
  command({ state, dispatch: (tr) => (state = tr.state) })
  const { from: f, to: t } = state.selection.main
  return { doc: state.doc.toString(), selected: state.sliceDoc(f, t), cursor: f }
}

describe('toggleWrap', () => {
  it('wraps the selection and keeps it selected', () => {
    expect(run(toggleWrap('**'), 'say hi now', 4, 6)).toMatchObject({ doc: 'say **hi** now', selected: 'hi' })
  })

  it('unwraps on a second press', () => {
    const once = run(toggleWrap('**'), 'say hi now', 4, 6)
    expect(run(toggleWrap('**'), once.doc, 6, 8)).toMatchObject({ doc: 'say hi now', selected: 'hi' })
  })

  it('unwraps when the marks are selected too', () => {
    expect(run(toggleWrap('`'), 'a `b` c', 2, 5)).toMatchObject({ doc: 'a b c', selected: 'b' })
  })

  it('puts the cursor between the marks when nothing is selected', () => {
    expect(run(toggleWrap('_'), 'ab', 1)).toMatchObject({ doc: 'a__b', cursor: 2, selected: '' })
  })
})

describe('insertLink', () => {
  it('turns the selection into link text and selects the url to type over', () => {
    expect(run(insertLink, 'see docs here', 4, 8)).toMatchObject({ doc: 'see [docs](url) here', selected: 'url' })
  })

  it('without a selection, puts the cursor in the brackets', () => {
    expect(run(insertLink, 'x', 1)).toMatchObject({ doc: 'x[](url)', cursor: 2 })
  })
})

describe('continueOrEndList', () => {
  it('continues bullets, numbers and task lists', () => {
    expect(run(continueOrEndList, '- milk', 6).doc).toBe('- milk\n- ')
    expect(run(continueOrEndList, '1. one', 6).doc).toBe('1. one\n2. ')
    expect(run(continueOrEndList, '- [x] milk', 10).doc).toBe('- [x] milk\n- [ ] ')
  })

  it('ends the list on an empty item, at once', () => {
    expect(run(continueOrEndList, '- milk\n- ', 9)).toMatchObject({ doc: '- milk\n', cursor: 7 })
    expect(run(continueOrEndList, '- [ ] a\n- [ ] ', 14).doc).toBe('- [ ] a\n')
    expect(run(continueOrEndList, '> quote\n> ', 10).doc).toBe('> quote\n')
  })

  it('moves a nested empty item up a level first', () => {
    expect(run(continueOrEndList, '- a\n  - ', 8).doc).toBe('- a\n- ')
  })

  it('leaves Enter outside lists to the default keymap', () => {
    const state = EditorState.create({ doc: 'text', selection: EditorSelection.cursor(4), extensions: [markdown()] })
    expect(continueOrEndList({ state, dispatch: () => undefined })).toBe(false)
  })
})

describe('setLineStyle', () => {
  it('turns lines into a heading, replacing any marker', () => {
    expect(run(setLineStyle('h2'), 'title', 0).doc).toBe('## title')
    expect(run(setLineStyle('h1'), '- item', 0).doc).toBe('# item')
  })

  it('makes a numbered list that counts, over several lines', () => {
    expect(run(setLineStyle('number'), 'a\nb\nc', 0, 5).doc).toBe('1. a\n2. b\n3. c')
  })

  it('makes tasks and quotes, keeping indentation', () => {
    expect(run(setLineStyle('task'), '  milk', 2).doc).toBe('  - [ ] milk')
    expect(run(setLineStyle('quote'), '## hi', 0).doc).toBe('> hi')
  })

  it('toggles back to plain text when every line already has the style', () => {
    expect(run(setLineStyle('bullet'), '- a\n- b', 0, 7).doc).toBe('a\nb')
    expect(run(setLineStyle('body'), '### x', 0).doc).toBe('x')
  })
})

describe('insertBlock', () => {
  it('fills an empty line and puts the cursor in the block', () => {
    const r = run(insertBlock(INSERTS.codeBlock.block, INSERTS.codeBlock.cursorAt), 'a\n\nb', 2)
    expect(r.doc).toBe('a\n```\n\n```\nb')
    expect(r.cursor).toBe(5)
  })

  it('goes on the next line after text', () => {
    expect(run(insertBlock(INSERTS.table.block, INSERTS.table.cursorAt), 'text', 2).doc).toBe('text\n| Column 1 | Column 2 |\n| --- | --- |\n|  |  |')
  })
})
