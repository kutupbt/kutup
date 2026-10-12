import { ArrowDownNarrowWide, ArrowDownWideNarrow, Check, ListFilter as FilterIcon } from 'lucide-react'
import type { ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import type { ListFilter, ListSort } from '@kutup/mail-core/api'
import { Button } from '@kutup/ui/components/button'
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuLabel, DropdownMenuSeparator, DropdownMenuTrigger } from '@kutup/ui/components/dropdown-menu'
import { cn } from '@kutup/ui/lib/cn'

const MENU_FILTERS: ListFilter[] = ['read', 'attachments']
const SORTS: ListSort[] = ['newest', 'oldest', 'largest', 'smallest']

/**
 * Proton's list filters (FilterList): Unread at hand, Read and Has
 * attachments with the sort options in Filter, and Reset while any is on.
 * Choosing an active one again turns it off. `children` (the paging) sit
 * at the end; with rows chosen only they show.
 */
export function ListFilters({
  filter,
  sort,
  onChange,
  filtersHidden = false,
  children,
}: {
  filter: ListFilter | null
  sort: ListSort
  onChange: (change: { filter?: ListFilter | null; sort?: ListSort }) => void
  filtersHidden?: boolean
  children?: ReactNode
}) {
  const { t } = useTranslation()
  const inMenu = (filter && filter !== 'unread' ? 1 : 0) + (sort !== 'newest' ? 1 : 0)
  return (
    <div className="flex items-center gap-1 border-b border-border px-2 py-1">
      {filtersHidden ? null : (
        <>
          <Button
            size="sm"
            variant={filter === 'unread' ? 'default' : 'outline'}
            className="h-7"
            aria-pressed={filter === 'unread'}
            onClick={() => onChange({ filter: filter === 'unread' ? null : 'unread' })}
          >
            {t('listFilter.unread')}
          </Button>
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button size="sm" variant={inMenu ? 'default' : 'outline'} className="h-7" title={t('listFilter.title')}>
                <FilterIcon />
                {inMenu ? t('listFilter.filterCount', { count: inMenu }) : t('listFilter.filter')}
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="start" className="w-60">
              <DropdownMenuLabel>{t('listFilter.filter')}</DropdownMenuLabel>
              {MENU_FILTERS.map((option) => (
                <DropdownMenuItem key={option} aria-checked={filter === option} role="menuitemcheckbox" onSelect={() => onChange({ filter: filter === option ? null : option })}>
                  <span className="flex-1">{t(`listFilter.${option}`)}</span>
                  <Check className={cn('text-primary', filter !== option && 'invisible')} />
                </DropdownMenuItem>
              ))}
              <DropdownMenuSeparator />
              <DropdownMenuLabel>{t('listFilter.sortBy')}</DropdownMenuLabel>
              {SORTS.map((option) => (
                <DropdownMenuItem key={option} aria-checked={sort === option} role="menuitemradio" onSelect={() => onChange({ sort: sort === option ? 'newest' : option })}>
                  {option === 'newest' || option === 'largest' ? <ArrowDownWideNarrow /> : <ArrowDownNarrowWide />}
                  <span className="flex-1">{t(`listFilter.sort.${option}`)}</span>
                  <Check className={cn('text-primary', sort !== option && 'invisible')} />
                </DropdownMenuItem>
              ))}
            </DropdownMenuContent>
          </DropdownMenu>
          {filter || sort !== 'newest' ? (
            <Button size="sm" variant="ghost" className="h-7" onClick={() => onChange({ filter: null, sort: 'newest' })}>
              {t('listFilter.reset')}
            </Button>
          ) : null}
        </>
      )}
      <span className="ml-auto" />
      {children}
    </div>
  )
}
