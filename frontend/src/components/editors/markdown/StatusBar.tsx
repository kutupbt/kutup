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
}

export default function StatusBar({
  cursorLine,
  cursorCol,
  words,
  chars,
  collaborators,
}: Props) {
  const { t } = useTranslation()
  return (
    <footer className="flex shrink-0 items-center gap-4 border-t border-border bg-card px-4 py-1.5 text-xs text-muted-foreground">
      <span>
        {t('notes.statusBar.cursor', { line: cursorLine, col: cursorCol, defaultValue: 'Ln {{line}}, Col {{col}}' })}
      </span>
      <span>
        {t('notes.statusBar.words', { count: words, defaultValue: '{{count}} words' })}
      </span>
      <span>
        {t('notes.statusBar.chars', { count: chars.toLocaleString(), defaultValue: '{{count}} chars' })}
      </span>
      {collaborators > 0 && (
        <span className="ml-auto flex items-center gap-1.5">
          <span aria-hidden="true" className="inline-block h-2 w-2 rounded-full bg-emerald-500" />
          {t('notes.statusBar.collaborators', {
            count: collaborators,
            defaultValue: '{{count}} collaborators',
          })}
        </span>
      )}
    </footer>
  )
}

/** Count words in a string. Splits on whitespace; ignores empty entries.
 *  Markdown markers (#, *, -) are treated as words too — close enough to
 *  the human sense of "how much have I written." */
export function countWords(text: string): number {
  if (!text) return 0
  const matches = text.match(/\S+/g)
  return matches ? matches.length : 0
}
