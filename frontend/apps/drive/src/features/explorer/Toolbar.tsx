import { ArrowDownUp, Image, ImageOff, LayoutGrid, List, ListFilter } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { Button } from '@kutup/ui/components/button'
import {
  DropdownMenu,
  DropdownMenuCheckboxItem,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuRadioGroup,
  DropdownMenuRadioItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@kutup/ui/components/dropdown-menu'
import { cn } from '@kutup/ui/lib/cn'
import { FILE_KINDS, type ItemKind } from './kinds'
import type { ExplorerPrefs, useExplorerPrefs } from './prefs'
import { SORT_FIELDS, type SortDir, type SortField } from './sort'

type Update = ReturnType<typeof useExplorerPrefs>[1]

/** "Newest first" reads better than "descending"; the words depend on the field. */
function directionLabels(field: SortField): Record<SortDir, string> {
  return {
    modified: { desc: 'explorer.dir.newest', asc: 'explorer.dir.oldest' },
    name: { asc: 'explorer.dir.az', desc: 'explorer.dir.za' },
    size: { desc: 'explorer.dir.largest', asc: 'explorer.dir.smallest' },
    type: { asc: 'explorer.dir.az', desc: 'explorer.dir.za' },
  }[field]
}

/** The natural first choice per field: newest, A–Z, largest, A–Z. */
const DIRECTION_ORDER: Record<SortField, readonly SortDir[]> = {
  modified: ['desc', 'asc'],
  name: ['asc', 'desc'],
  size: ['desc', 'asc'],
  type: ['asc', 'desc'],
}

/**
 * The list's controls, in the top-right corner of the content (Dolphin and
 * Google Drive both put them there): sort, type filter, list/grid.
 */
export function Toolbar({ prefs, update }: { prefs: ExplorerPrefs; update: Update }) {
  const { t } = useTranslation()
  const { sort, kinds, view } = prefs
  const labels = directionLabels(sort.field)
  const kindOptions: readonly ItemKind[] = ['folder', ...FILE_KINDS]

  return (
    <div className="flex items-center gap-1">
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Button variant="ghost" size="sm" aria-label={t('explorer.sortBy')}>
            <ArrowDownUp />
            <span className="hidden sm:inline">
              {t(`explorer.fields.${sort.field}`)} · {t(labels[sort.dir])}
            </span>
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end" className="w-56">
          <DropdownMenuLabel>{t('explorer.sortBy')}</DropdownMenuLabel>
          <DropdownMenuRadioGroup value={sort.field} onValueChange={(v) => update({ field: v as SortField, dir: DIRECTION_ORDER[v as SortField][0] })}>
            {SORT_FIELDS.map((field) => (
              <DropdownMenuRadioItem key={field} value={field}>
                {t(`explorer.fields.${field}`)}
              </DropdownMenuRadioItem>
            ))}
          </DropdownMenuRadioGroup>
          <DropdownMenuSeparator />
          <DropdownMenuRadioGroup value={sort.dir} onValueChange={(v) => update({ dir: v as SortDir })}>
            {DIRECTION_ORDER[sort.field].map((dir) => (
              <DropdownMenuRadioItem key={dir} value={dir}>
                {t(labels[dir])}
              </DropdownMenuRadioItem>
            ))}
          </DropdownMenuRadioGroup>
          <DropdownMenuSeparator />
          <DropdownMenuCheckboxItem
            checked={sort.foldersFirst}
            onCheckedChange={(v) => update({ foldersFirst: v === true })}
          >
            {t('explorer.foldersFirst')}
          </DropdownMenuCheckboxItem>
        </DropdownMenuContent>
      </DropdownMenu>

      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Button
            variant="ghost"
            size="sm"
            aria-label={t('explorer.filter')}
            className={cn(kinds.size > 0 && 'bg-accent text-accent-foreground')}
          >
            <ListFilter />
            <span className="hidden sm:inline">
              {kinds.size > 0 ? t('explorer.filterCount', { count: kinds.size }) : t('explorer.filter')}
            </span>
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end" className="w-56">
          <DropdownMenuLabel>{t('explorer.showOnly')}</DropdownMenuLabel>
          {kindOptions.map((kind) => (
            <DropdownMenuCheckboxItem
              key={kind}
              checked={kinds.has(kind)}
              onSelect={(e) => e.preventDefault()}
              onCheckedChange={(checked) => {
                const next = new Set(kinds)
                if (checked) next.add(kind)
                else next.delete(kind)
                update({ kinds: next })
              }}
            >
              {t(`explorer.kinds.${kind}`)}
            </DropdownMenuCheckboxItem>
          ))}
          {kinds.size > 0 ? (
            <>
              <DropdownMenuSeparator />
              <DropdownMenuItem onSelect={() => update({ kinds: new Set() })}>{t('explorer.clearFilter')}</DropdownMenuItem>
            </>
          ) : null}
        </DropdownMenuContent>
      </DropdownMenu>

      <div className="ml-1 inline-flex rounded-md border border-border p-0.5" role="group" aria-label={t('explorer.view')}>
        {([
          ['list', List],
          ['grid', LayoutGrid],
        ] as const).map(([mode, Icon]) => (
          <button
            key={mode}
            type="button"
            aria-pressed={view === mode}
            aria-label={t(`explorer.views.${mode}`)}
            onClick={() => update({ view: mode })}
            className={cn(
              'rounded p-1.5 text-muted-foreground transition-colors hover:text-foreground',
              'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring [&_svg]:size-4',
              view === mode && 'bg-accent text-accent-foreground',
            )}
          >
            <Icon />
          </button>
        ))}
        {view === 'grid' ? (
          <button
            type="button"
            aria-pressed={prefs.showPreviews}
            aria-label={t('explorer.showPreviews')}
            title={t('explorer.showPreviews')}
            onClick={() => update({ showPreviews: !prefs.showPreviews })}
            className={cn(
              'ml-0.5 rounded border-l border-border p-1.5 text-muted-foreground transition-colors hover:text-foreground',
              'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring [&_svg]:size-4',
              prefs.showPreviews && 'text-foreground',
            )}
          >
            {prefs.showPreviews ? <Image /> : <ImageOff />}
          </button>
        ) : null}
      </div>
    </div>
  )
}
