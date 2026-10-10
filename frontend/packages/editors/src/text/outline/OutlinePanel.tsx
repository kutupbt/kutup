import { X } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { Button } from '@kutup/ui/components/button'
import { cn } from '@kutup/ui/lib/cn'
import type { Heading } from './headings'

/**
 * A Markdown note's headings, beside it: indented by level, the section the
 * cursor is in marked; a click goes there.
 */
export default function OutlinePanel({
  headings,
  current,
  onJump,
  onClose,
}: {
  headings: Heading[]
  /** Index of the heading whose section holds the cursor, or -1. */
  current: number
  onJump: (index: number) => void
  onClose: () => void
}) {
  const { t } = useTranslation()
  const top = headings.reduce((min, h) => Math.min(min, h.level), 6)
  return (
    <aside className="flex h-full w-[280px] min-h-0 shrink-0 flex-col overflow-hidden border-l border-border bg-card">
      <header className="flex h-12 shrink-0 items-center justify-between border-b border-border px-4">
        <h2 className="text-sm font-semibold">{t('editor.outline.title')}</h2>
        <Button type="button" size="icon" variant="ghost" onClick={onClose} aria-label={t('editor.outline.close')} className="h-7 w-7">
          <X className="h-4 w-4" />
        </Button>
      </header>
      <nav aria-label={t('editor.outline.title')} className="flex-1 min-h-0 overflow-y-auto overscroll-contain p-2">
        {headings.length === 0 ? (
          <p className="px-2 py-3 text-sm text-muted-foreground">{t('editor.outline.empty')}</p>
        ) : (
          <ul className="space-y-0.5">
            {headings.map((h, i) => (
              <li key={`${h.line}:${h.text}`}>
                <button
                  type="button"
                  onClick={() => onJump(i)}
                  aria-current={i === current ? 'location' : undefined}
                  style={{ paddingLeft: `${0.5 + (h.level - top) * 0.875}rem` }}
                  className={cn(
                    'block w-full truncate rounded-md py-1 pr-2 text-left text-sm hover:bg-accent focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring',
                    h.level === top ? 'font-medium' : 'text-muted-foreground',
                    i === current && 'bg-accent text-foreground',
                  )}
                  title={h.text}
                >
                  {h.text}
                </button>
              </li>
            ))}
          </ul>
        )}
      </nav>
    </aside>
  )
}
