import { ArrowDown, ArrowUp, MoreHorizontal } from 'lucide-react'
import { Fragment, useCallback, useEffect, useRef, type KeyboardEvent, type MouseEvent, type ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import { Button } from '@kutup/ui/components/button'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@kutup/ui/components/dropdown-menu'
import { cn } from '@kutup/ui/lib/cn'
import { formatBytes, formatFileDate, formatInstant } from '@kutup/ui/lib/format'
import { KindIcon } from './KindIcon'
import type { ViewMode } from './prefs'
import { itemKey, type ExplorerItem, type SortField, type SortSpec } from './sort'

export interface ExplorerAction {
  id: string
  label: string
  icon: ReactNode
  onSelect: () => void
  destructive?: boolean
  /** Draw a separator above this action. */
  separated?: boolean
}

export interface ExplorerProps {
  /** Already sorted and filtered, in display order. */
  items: ExplorerItem[]
  view: ViewMode
  sort: SortSpec
  /** Clicking a column header: the same field flips direction, another field selects it. */
  onSortField: (field: SortField) => void
  selection: ReadonlySet<string>
  onSelectionChange: (next: Set<string>) => void
  onOpen: (item: ExplorerItem) => void
  actionsFor: (item: ExplorerItem) => ExplorerAction[]
  /** Delete / Backspace with a selection. */
  onDeleteKey?: (keys: ReadonlySet<string>) => void
  /** Extra line under a name (e.g. who shared it). */
  subtitleFor?: (item: ExplorerItem) => ReactNode
}

function RowMenu({ item, actions }: { item: ExplorerItem; actions: ExplorerAction[] }) {
  const { t } = useTranslation()
  if (actions.length === 0) return null
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button
          variant="ghost"
          size="icon"
          className="size-8 opacity-70 hover:opacity-100 focus-visible:opacity-100"
          aria-label={t('explorer.actionsFor', { name: item.name })}
          onClick={(e) => e.stopPropagation()}
          onDoubleClick={(e) => e.stopPropagation()}
        >
          <MoreHorizontal />
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" onClick={(e) => e.stopPropagation()}>
        {actions.map((action) => (
          <Fragment key={action.id}>
            {action.separated ? <DropdownMenuSeparator /> : null}
            <DropdownMenuItem destructive={action.destructive} onSelect={action.onSelect}>
              {action.icon}
              {action.label}
            </DropdownMenuItem>
          </Fragment>
        ))}
      </DropdownMenuContent>
    </DropdownMenu>
  )
}

/**
 * The unified Drive list (Dolphin / Google Drive): folders and files in one
 * list, in whatever order the toolbar chose. Selection and keyboard follow
 * desktop file managers — click selects, Ctrl/⌘-click toggles, Shift-click
 * extends, double-click or Enter opens, arrows move, Space toggles, Ctrl+A
 * selects all, Escape clears, Delete hands the selection to the page. A tap
 * on a touch screen opens directly, the way phone file managers do.
 */
export function Explorer(props: ExplorerProps) {
  const { items, selection, onSelectionChange, onOpen, onDeleteKey } = props
  const anchor = useRef<number | null>(null)
  const lastPointer = useRef<string>('mouse')
  const rowRefs = useRef<(HTMLElement | null)[]>([])

  // Selection only ever holds visible items: a filter or navigation drops the rest.
  useEffect(() => {
    const visible = new Set(items.map(itemKey))
    const kept = [...selection].filter((k) => visible.has(k))
    if (kept.length !== selection.size) onSelectionChange(new Set(kept))
  }, [items, selection, onSelectionChange])

  const focusRow = (index: number) => rowRefs.current[index]?.focus()

  const onRowClick = useCallback(
    (event: MouseEvent, index: number) => {
      const key = itemKey(items[index])
      if (lastPointer.current === 'touch' && !event.ctrlKey && !event.metaKey && !event.shiftKey && selection.size === 0) {
        onOpen(items[index])
        return
      }
      if (event.shiftKey && anchor.current !== null) {
        const [from, to] = [anchor.current, index].sort((a, b) => a - b)
        onSelectionChange(new Set(items.slice(from, to + 1).map(itemKey)))
        return
      }
      if (event.ctrlKey || event.metaKey) {
        const next = new Set(selection)
        if (next.has(key)) next.delete(key)
        else next.add(key)
        onSelectionChange(next)
      } else {
        onSelectionChange(new Set([key]))
      }
      anchor.current = index
    },
    [items, selection, onSelectionChange, onOpen],
  )

  const onKeyDown = (event: KeyboardEvent, index: number) => {
    const move = (to: number) => {
      const target = Math.max(0, Math.min(items.length - 1, to))
      focusRow(target)
      if (event.shiftKey && anchor.current !== null) {
        const [from, end] = [anchor.current, target].sort((a, b) => a - b)
        onSelectionChange(new Set(items.slice(from, end + 1).map(itemKey)))
      } else if (!event.ctrlKey && !event.metaKey) {
        onSelectionChange(new Set([itemKey(items[target])]))
        anchor.current = target
      }
    }
    const columns = props.view === 'grid' ? gridColumns(rowRefs.current) : 1
    switch (event.key) {
      case 'ArrowDown':
        event.preventDefault()
        move(index + columns)
        break
      case 'ArrowUp':
        event.preventDefault()
        move(index - columns)
        break
      case 'ArrowRight':
        if (props.view === 'grid') {
          event.preventDefault()
          move(index + 1)
        }
        break
      case 'ArrowLeft':
        if (props.view === 'grid') {
          event.preventDefault()
          move(index - 1)
        }
        break
      case 'Home':
        event.preventDefault()
        move(0)
        break
      case 'End':
        event.preventDefault()
        move(items.length - 1)
        break
      case 'Enter':
        event.preventDefault()
        onOpen(items[index])
        break
      case ' ': {
        event.preventDefault()
        const key = itemKey(items[index])
        const next = new Set(selection)
        if (next.has(key)) next.delete(key)
        else next.add(key)
        onSelectionChange(next)
        anchor.current = index
        break
      }
      case 'a':
      case 'A':
        if (event.ctrlKey || event.metaKey) {
          event.preventDefault()
          onSelectionChange(new Set(items.map(itemKey)))
        }
        break
      case 'Escape':
        onSelectionChange(new Set())
        break
      case 'Delete':
      case 'Backspace':
        if (selection.size > 0 && onDeleteKey) {
          event.preventDefault()
          onDeleteKey(selection)
        }
        break
    }
  }

  const rowProps = (index: number) => ({
    ref: (el: HTMLElement | null) => {
      rowRefs.current[index] = el
    },
    tabIndex: index === 0 || selection.has(itemKey(items[index])) ? 0 : -1,
    'aria-selected': selection.has(itemKey(items[index])),
    onPointerDown: (e: React.PointerEvent) => {
      lastPointer.current = e.pointerType
    },
    onClick: (e: MouseEvent) => onRowClick(e, index),
    onDoubleClick: () => onOpen(items[index]),
    onKeyDown: (e: KeyboardEvent) => onKeyDown(e, index),
  })

  return props.view === 'grid' ? <GridView {...props} rowProps={rowProps} /> : <ListView {...props} rowProps={rowProps} />
}

/** Items per row in the grid, from the rendered tiles' positions. */
function gridColumns(tiles: (HTMLElement | null)[]): number {
  const first = tiles[0]?.getBoundingClientRect().top
  if (first === undefined) return 1
  const perRow = tiles.findIndex((t) => t !== null && t.getBoundingClientRect().top !== first)
  return perRow > 0 ? perRow : tiles.length || 1
}

type RowProps = (index: number) => Record<string, unknown>

function SortHeader({
  field,
  sort,
  onSortField,
  className,
  children,
}: {
  field: SortField
  sort: SortSpec
  onSortField: (field: SortField) => void
  className?: string
  children: ReactNode
}) {
  const active = sort.field === field
  const Icon = sort.dir === 'asc' ? ArrowUp : ArrowDown
  return (
    <th
      scope="col"
      className={cn('h-10 px-3 text-left text-xs font-medium uppercase tracking-wide text-muted-foreground', className)}
      aria-sort={active ? (sort.dir === 'asc' ? 'ascending' : 'descending') : 'none'}
    >
      <button
        type="button"
        onClick={() => onSortField(field)}
        className={cn(
          'inline-flex items-center gap-1 rounded-sm uppercase hover:text-foreground',
          'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring',
          active && 'text-foreground',
        )}
      >
        {children}
        {active ? <Icon className="size-3.5" /> : null}
      </button>
    </th>
  )
}

function ListView({ items, sort, onSortField, selection, actionsFor, subtitleFor, rowProps }: ExplorerProps & { rowProps: RowProps }) {
  const { t, i18n } = useTranslation()
  const lang = i18n.language
  return (
    <div className="overflow-x-auto">
      <table className="w-full table-fixed text-sm" role="grid" aria-multiselectable>
        <thead className="border-b border-border">
          <tr>
            <SortHeader field="name" sort={sort} onSortField={onSortField}>{t('explorer.fields.name')}</SortHeader>
            <SortHeader field="modified" sort={sort} onSortField={onSortField} className="hidden w-40 sm:table-cell">
              {t('explorer.fields.modified')}
            </SortHeader>
            <SortHeader field="size" sort={sort} onSortField={onSortField} className="hidden w-28 md:table-cell">
              {t('explorer.fields.size')}
            </SortHeader>
            <th scope="col" className="w-12"><span className="sr-only">{t('explorer.actions')}</span></th>
          </tr>
        </thead>
        <tbody>
          {items.map((item, index) => {
            const selected = selection.has(itemKey(item))
            return (
              <tr
                key={itemKey(item)}
                {...rowProps(index)}
                className={cn(
                  'group relative cursor-default select-none border-b border-border/60 outline-none transition-colors',
                  'hover:bg-muted/50 focus-visible:bg-muted/70 focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-ring',
                  selected && 'bg-accent hover:bg-accent',
                )}
              >
                <td className="px-3 py-2">
                  <div className="flex min-w-0 items-center gap-3">
                    <KindIcon kind={item.kind} color={item.color} className="size-5" />
                    <div className="min-w-0">
                      <p className={cn('truncate', item.type === 'folder' && 'font-medium')} title={item.name}>
                        {item.name}
                      </p>
                      {subtitleFor ? <p className="truncate text-xs text-muted-foreground">{subtitleFor(item)}</p> : null}
                      <p className="text-xs text-muted-foreground sm:hidden">{formatFileDate(item.modifiedAt, lang)}</p>
                    </div>
                  </div>
                </td>
                <td className="hidden px-3 py-2 text-muted-foreground sm:table-cell" title={formatInstant(item.modifiedAt, lang) ?? undefined}>
                  {formatFileDate(item.modifiedAt, lang)}
                </td>
                <td className="hidden px-3 py-2 text-muted-foreground md:table-cell">
                  {item.size === null ? '—' : formatBytes(item.size, lang)}
                </td>
                <td className="px-1 py-1 text-right">
                  <RowMenu item={item} actions={actionsFor(item)} />
                </td>
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}

function GridView({ items, selection, actionsFor, rowProps }: ExplorerProps & { rowProps: RowProps }) {
  const { i18n } = useTranslation()
  return (
    <ul className="grid grid-cols-[repeat(auto-fill,minmax(9.5rem,1fr))] gap-3 p-4" role="grid" aria-multiselectable>
      {items.map((item, index) => {
        const selected = selection.has(itemKey(item))
        return (
          <li
            key={itemKey(item)}
            {...rowProps(index)}
            className={cn(
              'group relative flex cursor-default select-none flex-col items-center gap-2 rounded-lg border border-border bg-card p-3 text-center outline-none transition-colors',
              'hover:border-primary/40 focus-visible:ring-2 focus-visible:ring-ring',
              selected && 'border-primary bg-accent',
            )}
          >
            <span className="absolute right-1 top-1">
              <RowMenu item={item} actions={actionsFor(item)} />
            </span>
            <KindIcon kind={item.kind} color={item.color} className="mt-3 size-12 stroke-[1.25]" />
            <p className={cn('line-clamp-2 w-full break-words text-sm', item.type === 'folder' && 'font-medium')} title={item.name}>
              {item.name}
            </p>
            <p className="text-xs text-muted-foreground">{formatFileDate(item.modifiedAt, i18n.language)}</p>
          </li>
        )
      })}
    </ul>
  )
}
