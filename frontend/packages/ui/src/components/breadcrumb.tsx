import { ChevronRight } from 'lucide-react'
import { Fragment, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Link } from 'react-router-dom'
import { cn } from '../lib/cn'

/**
 * Where you are, and the way back up.
 *
 * The same information on every page, saying what each parent *is* rather
 * than only that one exists (Drive's folder path, a settings section).
 *
 * The last crumb is the current page and is not a link — `aria-current="page"`
 * is what announces that, and a link to where you already are is a trap for
 * anybody navigating by keyboard.
 */
export interface Crumb {
  label: string
  /** Omit on the final crumb. */
  to?: string
  /** Something dragged in the app may be dropped here (a folder up the path). */
  drop?: { accepts: () => boolean; onDrop: () => void }
}

export function Breadcrumb({ items, className }: { items: Crumb[]; className?: string }) {
  const { t } = useTranslation()
  const [over, setOver] = useState<number | null>(null)
  return (
    <nav aria-label={t('common.breadcrumb')} className={cn('min-w-0', className)}>
      <ol className="flex min-w-0 items-center gap-1.5 text-sm">
        {items.map((item, index) => {
          const last = index === items.length - 1
          return (
            <Fragment key={`${item.label}-${index}`}>
              <li className="min-w-0">
                {item.to && !last ? (
                  <Link
                    to={item.to}
                    className={cn(
                      'block truncate rounded px-1 -mx-1 text-muted-foreground transition-colors hover:text-foreground',
                      over === index && 'bg-primary/10 text-foreground ring-2 ring-primary',
                    )}
                    onDragOver={(e) => {
                      if (!item.drop?.accepts()) return
                      e.preventDefault()
                      e.dataTransfer.dropEffect = 'move'
                      setOver(index)
                    }}
                    onDragLeave={() => setOver((current) => (current === index ? null : current))}
                    onDrop={(e) => {
                      setOver(null)
                      if (!item.drop?.accepts()) return
                      e.preventDefault()
                      e.stopPropagation()
                      item.drop.onDrop()
                    }}
                  >
                    {item.label}
                  </Link>
                ) : (
                  <span
                    aria-current={last ? 'page' : undefined}
                    className={cn(
                      'block truncate',
                      last ? 'font-medium text-foreground' : 'text-muted-foreground',
                    )}
                  >
                    {item.label}
                  </span>
                )}
              </li>
              {last ? null : (
                <li aria-hidden className="shrink-0 text-chrome-muted/60">
                  <ChevronRight className="size-3.5" />
                </li>
              )}
            </Fragment>
          )
        })}
      </ol>
    </nav>
  )
}
