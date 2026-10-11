import { Check, ChevronLeft, ChevronRight } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { Button } from '@kutup/ui/components/button'
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from '@kutup/ui/components/dropdown-menu'
import { cn } from '@kutup/ui/lib/cn'
import { pageNumbers } from './paging'

interface PagingProps {
  /** From 1. */
  page: number
  pages: number
  onPage: (page: number) => void
  disabled?: boolean
}

/** Proton's PagingControls at the toolbar's end: previous, "page/pages" with every page to pick, next. */
export function PagingControls({ page, pages, onPage, disabled }: PagingProps) {
  const { t } = useTranslation()
  return (
    <div className="flex items-center">
      <Button variant="ghost" size="icon" className="size-7" aria-label={t('paging.previous')} title={t('paging.previous')} disabled={disabled || page <= 1} onClick={() => onPage(page - 1)}>
        <ChevronLeft />
      </Button>
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Button variant="ghost" size="sm" className="hidden h-7 px-2 tabular-nums sm:inline-flex" aria-label={t('paging.pageOf', { page, pages })} disabled={disabled || pages <= 1}>
            {page}/{pages}
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end" className="max-h-80 overflow-y-auto">
          {Array.from({ length: pages }, (_, i) => i + 1).map((n) => (
            <DropdownMenuItem key={n} aria-label={t('paging.page', { page: n })} aria-checked={n === page} role="menuitemradio" onSelect={() => onPage(n)}>
              <span className="flex-1 tabular-nums">{n}</span>
              <Check className={cn('text-primary', n !== page && 'invisible')} />
            </DropdownMenuItem>
          ))}
        </DropdownMenuContent>
      </DropdownMenu>
      <Button variant="ghost" size="icon" className="size-7" aria-label={t('paging.next')} title={t('paging.next')} disabled={disabled || page >= pages} onClick={() => onPage(page + 1)}>
        <ChevronRight />
      </Button>
    </div>
  )
}

/** Proton's MailboxListPagination at the list's foot, with more than one page. */
export function ListPagination({ page, pages, onPage, disabled }: PagingProps) {
  const { t } = useTranslation()
  if (pages <= 1) return null
  return (
    <nav aria-label={t('paging.label')} className="flex flex-wrap items-center justify-center gap-1 p-3">
      <Button variant="ghost" size="icon" className="size-8" aria-label={t('paging.goPrevious')} title={t('paging.goPrevious')} disabled={disabled || page <= 1} onClick={() => onPage(page - 1)}>
        <ChevronLeft />
      </Button>
      {pageNumbers(page, pages).map((n, i) =>
        n === 'gap' ? (
          <span key={`gap-${i}`} className="px-1 text-muted-foreground" aria-hidden>
            …
          </span>
        ) : (
          <Button
            key={n}
            variant={n === page ? 'default' : 'ghost'}
            size="sm"
            className={cn('h-8 min-w-8 px-2 tabular-nums', n === page && 'font-semibold')}
            aria-label={t('paging.goTo', { page: n })}
            title={t('paging.goTo', { page: n })}
            aria-current={n === page ? 'page' : undefined}
            disabled={disabled}
            onClick={() => onPage(n)}
          >
            {n}
          </Button>
        ),
      )}
      <Button variant="ghost" size="icon" className="size-8" aria-label={t('paging.goNext')} title={t('paging.goNext')} disabled={disabled || page >= pages} onClick={() => onPage(page + 1)}>
        <ChevronRight />
      </Button>
    </nav>
  )
}
