import { Check, ChevronDown, X } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { Button } from '@kutup/ui/components/button'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuRadioGroup,
  DropdownMenuRadioItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@kutup/ui/components/dropdown-menu'
import { cn } from '@kutup/ui/lib/cn'
import { activeFilters, CREATORS, MODIFIED_WITHIN, NO_FILTERS, PLACES, type SearchFilters } from './filters'

const chip = (on: boolean) =>
  cn('h-8 rounded-full border border-border px-3 text-xs font-medium', on && 'border-primary/50 bg-primary/10 text-foreground')

/** One filter as a chip: its name until one is chosen, then the choice; "Any" turns it off. */
function Choice<T extends string>({
  id,
  name,
  value,
  options,
  label,
  onChange,
}: {
  id: string
  name: string
  value: T | null
  options: readonly T[]
  label: (option: T) => string
  onChange: (value: T | null) => void
}) {
  const { t } = useTranslation()
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="ghost" size="sm" className={chip(value !== null)} data-testid={`search-filter-${id}`} aria-label={name}>
          {value ? label(value) : name}
          <ChevronDown className="size-3.5" aria-hidden />
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="start" className="w-52">
        <DropdownMenuRadioGroup value={value ?? ''} onValueChange={(v) => onChange(v === '' ? null : (v as T))}>
          <DropdownMenuRadioItem value="">{t('search.filters.any')}</DropdownMenuRadioItem>
          <DropdownMenuSeparator />
          {options.map((option) => (
            <DropdownMenuRadioItem key={option} value={option}>
              {label(option)}
            </DropdownMenuRadioItem>
          ))}
        </DropdownMenuRadioGroup>
      </DropdownMenuContent>
    </DropdownMenu>
  )
}

/**
 * The search filters beside the toolbar's type filter: when an item was
 * last changed, where it is, who created it, and whether you share it.
 */
export function FilterBar({ filters, onChange }: { filters: SearchFilters; onChange: (next: SearchFilters) => void }) {
  const { t } = useTranslation()
  return (
    <div className="flex flex-wrap items-center gap-2 border-b border-border px-3 py-2 md:px-6" role="group" aria-label={t('search.filters.label')}>
      <Choice
        id="modified"
        name={t('search.filters.modified')}
        value={filters.modified}
        options={MODIFIED_WITHIN}
        label={(o) => t(`search.filters.modifiedWithin.${o}`)}
        onChange={(modified) => onChange({ ...filters, modified })}
      />
      <Choice
        id="place"
        name={t('search.filters.place')}
        value={filters.place}
        options={PLACES}
        label={(o) => t(`search.filters.places.${o}`)}
        onChange={(place) => onChange({ ...filters, place })}
      />
      <Choice
        id="created-by"
        name={t('search.filters.createdBy')}
        value={filters.createdBy}
        options={CREATORS}
        label={(o) => t(`search.filters.creators.${o}`)}
        onChange={(createdBy) => onChange({ ...filters, createdBy })}
      />
      <Button
        variant="ghost"
        size="sm"
        className={chip(filters.sharedByMe)}
        aria-pressed={filters.sharedByMe}
        data-testid="search-filter-shared"
        onClick={() => onChange({ ...filters, sharedByMe: !filters.sharedByMe })}
      >
        {filters.sharedByMe ? <Check className="size-3.5" aria-hidden /> : null}
        {t('search.filters.sharedByMe')}
      </Button>
      {activeFilters(filters) > 0 ? (
        <Button variant="ghost" size="sm" className="h-8 text-xs" onClick={() => onChange(NO_FILTERS)} data-testid="search-filter-clear">
          <X className="size-3.5" aria-hidden />
          {t('search.filters.clear')}
        </Button>
      ) : null}
    </div>
  )
}
