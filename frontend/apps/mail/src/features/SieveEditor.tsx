import { useEffect, useRef } from 'react'
import { history, defaultKeymap, historyKeymap, indentWithTab } from '@codemirror/commands'
import { defaultHighlightStyle, StreamLanguage, syntaxHighlighting } from '@codemirror/language'
import { sieve } from '@codemirror/legacy-modes/mode/sieve'
import { lintGutter, setDiagnostics, type Diagnostic } from '@codemirror/lint'
import { Compartment, EditorState } from '@codemirror/state'
import { oneDark } from '@codemirror/theme-one-dark'
import { EditorView, keymap, lineNumbers } from '@codemirror/view'
import { useTheme } from 'next-themes'

/** A mark in the script: an error at `from`..`to`, with its message. */
export interface SieveMark {
  from: number
  to: number
  message: string
}

const sieveLanguage = StreamLanguage.define(sieve)

/**
 * The Sieve script's text editor (docs/plans/mail-sieve-editor.md §3), as
 * Proton's `SieveEditor`: Sieve highlighting, line numbers and a gutter of
 * the marks the dialog computes. Loaded on demand, so the mail app's entry
 * stays small.
 */
export default function SieveEditor({ value, onChange, marks, label }: { value: string; onChange: (value: string) => void; marks: SieveMark[]; label: string }) {
  const host = useRef<HTMLDivElement>(null)
  const view = useRef<EditorView | null>(null)
  const theme = useRef(new Compartment())
  const changed = useRef(onChange)
  changed.current = onChange
  const dark = useTheme().resolvedTheme === 'dark'

  useEffect(() => {
    if (!host.current) return
    const editor = new EditorView({
      parent: host.current,
      state: EditorState.create({
        doc: value,
        extensions: [
          lineNumbers(),
          history(),
          keymap.of([...defaultKeymap, ...historyKeymap, indentWithTab]),
          sieveLanguage,
          lintGutter(),
          theme.current.of(dark ? oneDark : syntaxHighlighting(defaultHighlightStyle)),
          EditorView.lineWrapping,
          EditorView.contentAttributes.of({ 'aria-label': label, spellcheck: 'false', autocapitalize: 'off' }),
          EditorView.theme({
            '&': { height: '100%', fontSize: '0.8125rem' },
            '.cm-scroller': { overflow: 'auto', fontFamily: 'var(--font-mono, ui-monospace, monospace)' },
          }),
          EditorView.updateListener.of((update) => {
            if (update.docChanged) changed.current(update.state.doc.toString())
          }),
        ],
      }),
    })
    view.current = editor
    return () => {
      editor.destroy()
      view.current = null
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps -- `value` seeds the editor once; the document is the editor's from then on
  }, [])

  useEffect(() => {
    view.current?.dispatch({ effects: theme.current.reconfigure(dark ? oneDark : syntaxHighlighting(defaultHighlightStyle)) })
  }, [dark])

  useEffect(() => {
    const editor = view.current
    if (!editor) return
    const length = editor.state.doc.length
    const diagnostics: Diagnostic[] = marks.map((mark) => {
      const from = Math.min(Math.max(mark.from, 0), length)
      return { from, to: Math.min(Math.max(mark.to, from), length), severity: 'error', message: mark.message }
    })
    editor.dispatch(setDiagnostics(editor.state, diagnostics))
  }, [marks])

  return <div ref={host} className="h-full min-h-0 overflow-hidden rounded-md border border-border" data-testid="sieve-editor" />
}
