// A code or text file as it is, to read: CodeMirror with its language and
// line numbers, not editable (a public link's page).

import { useEffect, useRef } from 'react'
import { EditorState } from '@codemirror/state'
import { EditorView, lineNumbers } from '@codemirror/view'
import { defaultHighlightStyle, syntaxHighlighting } from '@codemirror/language'
import { oneDark } from '@codemirror/theme-one-dark'
import { extensionOf } from '@kutup/drive-core/editorKind'
import { loadLanguage } from '../text/lang'
import { useResolvedTheme } from '../useResolvedTheme'

export default function CodeView({ filename, text }: { filename: string; text: string }) {
  const ref = useRef<HTMLDivElement>(null)
  const theme = useResolvedTheme()

  useEffect(() => {
    let view: EditorView | null = null
    let alive = true
    void loadLanguage(extensionOf(filename))
      .catch(() => null)
      .then((language) => {
        if (!alive || !ref.current) return
        view = new EditorView({
          parent: ref.current,
          state: EditorState.create({
            doc: text,
            extensions: [
              lineNumbers(),
              EditorState.readOnly.of(true),
              EditorView.editable.of(false),
              EditorView.theme({ '&': { height: '100%' }, '.cm-scroller': { overflow: 'auto' } }),
              theme === 'dark' ? oneDark : syntaxHighlighting(defaultHighlightStyle),
              ...(language ? [language] : []),
            ],
          }),
        })
      })
    return () => {
      alive = false
      view?.destroy()
    }
  }, [filename, text, theme])

  return <div ref={ref} className="h-full w-full overflow-hidden" />
}
