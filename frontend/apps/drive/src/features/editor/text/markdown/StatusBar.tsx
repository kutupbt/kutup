// Footer status bar for the notes editor — line:col, word/char counts,
// and (optionally) live collaborator count. Mirrors VSCode's bottom strip.

import { useTranslation } from 'react-i18next'

interface Props {
  /** 1-based line + column for the primary cursor. */
  cursorLine: number
  cursorCol: number
  /** Plain-text counts derived from the current document. */
  words: number
  chars: number
  /** Number of remote collaborators active right now (excludes self).
   *  Pass 0 to hide the indicator. */
  collaborators: number
  /** Counts of the selected text, when something is selected. */
  selection?: { words: number; chars: number } | null
}

export default function StatusBar({
  cursorLine,
  cursorCol,
  words,
  chars,
  collaborators,
  selection,
}: Props) {
  const { t } = useTranslation()
  return (
    <footer className="flex shrink-0 items-center gap-4 border-t border-border bg-card px-4 py-1.5 text-xs text-muted-foreground">
      <span>
        {t('editor.statusBar.cursor', { line: cursorLine, col: cursorCol })}
      </span>
      {selection ? (
        <span className="font-medium text-foreground">
          {t('editor.statusBar.selected', {
            words: t('editor.statusBar.words', { count: selection.words }),
            chars: t('editor.statusBar.chars', { count: selection.chars }),
          })}
        </span>
      ) : (
        <>
          <span>{t('editor.statusBar.words', { count: words })}</span>
          <span>{t('editor.statusBar.chars', { count: chars })}</span>
        </>
      )}
      {collaborators > 0 && (
        <span className="ml-auto flex items-center gap-1.5">
          <span aria-hidden="true" className="inline-block h-2 w-2 rounded-full bg-primary" />
          {t('editor.statusBar.collaborators', { count: collaborators })}
        </span>
      )}
    </footer>
  )
}
