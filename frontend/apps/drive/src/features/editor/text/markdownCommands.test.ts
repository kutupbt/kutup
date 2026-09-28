import { EditorSelection, EditorState, type StateCommand } from '@codemirror/state'
import { markdown } from '@codemirror/lang-markdown'
import { describe, expect, it } from 'vitest'
import { continueOrEndList, insertLink, toggleWrap } from './markdownCommands'

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
