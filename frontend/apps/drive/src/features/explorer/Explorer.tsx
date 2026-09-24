import { ArrowDown, ArrowUp, MoreHorizontal } from 'lucide-react'
import { Fragment, useCallback, useEffect, useRef, useState, type DragEvent, type KeyboardEvent, type MouseEvent, type ReactNode } from 'react'
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
import { draggedItems, endItemDrag, startItemDrag } from './dragItems'
import { KindIcon } from './KindIcon'
import type { ViewMode } from './prefs'
import { itemKey, type ExplorerItem, type SortField, type SortSpec } from './sort'
import { useMarquee } from './useMarquee'

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
  /** Space on a file: a look without opening it (Quick Look). */
  onQuickLook?: (item: ExplorerItem) => void
  actionsFor: (item: ExplorerItem) => ExplorerAction[]
  /** Delete / Backspace with a selection. */
  onDeleteKey?: (keys: ReadonlySet<string>) => void
  /** Extra line under a name (e.g. who shared it). */
  subtitleFor?: (item: ExplorerItem) => ReactNode
  /** A grid card's picture (a thumbnail); null or absent shows the kind icon. */
  renderPreview?: (item: ExplorerItem) => ReactNode
  /** Whether an item can be picked up and dropped on a folder (to move it). */
  canDrag?: (item: ExplorerItem) => boolean
  /** Whether the dragged items (their keys) may be dropped on the folder `target`. */
  canDrop?: (dragged: string[], target: ExplorerItem) => boolean
  onDropItems?: (dragged: string[], target: ExplorerItem) => void
  /** An item drag started (true) or ended (false): drop targets outside the list can show. */
  onItemDrag?: (active: boolean) => void
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
 * extends, double-click or Enter opens, arrows move, Space previews a file
 * (Quick Look; Ctrl+Space toggles it in the selection instead), Ctrl+A
 * selects all, Escape clears, Delete hands the selection to the page. A tap
 * on a touch screen opens directly, the way phone file managers do.
 *
 * Dragging on empty space draws a selection box (useMarquee); a click there
 * clears the selection. Dragging an item (with the rest of the selection, if
 * it is selected) onto a folder hands them to `onDropItems`. Items carry
 * `data-item-key` so a surrounding ExplorerContextMenu knows what was
 * right-clicked.
 */
export function Explorer(props: ExplorerProps) {
  const { items, selection, onSelectionChange, onOpen, onDeleteKey } = props
  const anchor = useRef<number | null>(null)
  const lastPointer = useRef<string>('mouse')
  const rowRefs = useRef<(HTMLElement | null)[]>([])
  const surface = useRef<HTMLDivElement>(null)
  const [dropKey, setDropKey] = useState<string | null>(null)
  const marquee = useMarquee({
    surface,
    items: () => items.map((item, i) => ({ key: itemKey(item), el: rowRefs.current[i] ?? null })),
    selection: () => selection,
    onSelect: (keys) => {
      anchor.current = null
      onSelectionChange(keys)
    },
    onClear: () => {
      if (selection.size > 0) onSelectionChange(new Set())
    },
  })

  // Selection only ever holds visible items: a filter or navigation drops the rest.
  useEffect(() => {
    const visible = new Set(items.map(itemKey))
    const kept = [...selection].filter((k) => visible.has(k))
    if (kept.length !== selection.size) onSelectionChange(new Set(kept))
  }, [items, selection, onSelectionChange])

  const focusRow = (index: number) => rowRefs.current[index]?.focus()

  // Ctrl/⌘+A and Escape also work when no item has focus yet (after a
  // dialog closes, or on arrival), as long as nothing else wants the keys:
  // not while typing, and not under an open dialog or menu.
  const itemsRef = useRef(items)
  itemsRef.current = items
  const selectionRef = useRef(selection)
  selectionRef.current = selection
  useEffect(() => {
    function onKey(event: globalThis.KeyboardEvent) {
      const active = document.activeElement
      const free = !active || active === document.body || (surface.current?.contains(active) ?? false)
      if (!free || event.defaultPrevented || document.querySelector('[role="dialog"], [role="menu"]')) return
      // Rows handle their own keys.
      if (active instanceof HTMLElement && active.closest('[data-item-key]')) return
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'a') {
        event.preventDefault()
        onSelectionChange(new Set(itemsRef.current.map(itemKey)))
      } else if (event.key === 'Escape' && selectionRef.current.size > 0) {
        onSelectionChange(new Set())
      }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [onSelectionChange])

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
    switch (event.key) {
      case 'ArrowDown':
        event.preventDefault()
        move(props.view === 'grid' ? verticalNeighbour(rowRefs.current, index, 1) : index + 1)
        break
      case 'ArrowUp':
        event.preventDefault()
        move(props.view === 'grid' ? verticalNeighbour(rowRefs.current, index, -1) : index - 1)
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
        if (props.onQuickLook && items[index].type === 'file' && !event.ctrlKey && !event.metaKey) {
          onSelectionChange(new Set([itemKey(items[index])]))
          anchor.current = index
          props.onQuickLook(items[index])
          break
        }
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

  /** The drag-and-drop half of a row: a source, and for a folder, a target. */
  const dragProps = (item: ExplorerItem) => {
    const key = itemKey(item)
    const accepts = (dragged: string[] | null): dragged is string[] =>
      dragged !== null && item.type === 'folder' && !dragged.includes(key) && (props.canDrop?.(dragged, item) ?? false)
    return {
      draggable: Boolean(props.onDropItems && props.canDrag?.(item)),
      'data-drop-target': dropKey === key ? 'true' : undefined,
      onDragStart: (e: DragEvent) => {
        // The selection goes along when the item is part of it.
        const keys = selection.has(key) ? [...selection] : [key]
        if (!selection.has(key)) onSelectionChange(new Set([key]))
        startItemDrag(keys, e)
        props.onItemDrag?.(true)
      },
      onDragEnd: () => {
        endItemDrag()
        setDropKey(null)
        props.onItemDrag?.(false)
      },
      onDragOver: (e: DragEvent) => {
        if (!accepts(draggedItems())) return
        e.preventDefault()
        e.dataTransfer.dropEffect = 'move'
        if (dropKey !== key) setDropKey(key)
      },
      onDragLeave: (e: DragEvent) => {
        if (e.currentTarget.contains(e.relatedTarget as Node | null)) return
        setDropKey((current) => (current === key ? null : current))
      },
      onDrop: (e: DragEvent) => {
        const dragged = draggedItems()
        setDropKey(null)
        if (!accepts(dragged)) return
        e.preventDefault()
        e.stopPropagation()
        endItemDrag()
        props.onDropItems?.(dragged, item)
      },
    }
  }

  const rowProps = (index: number) => ({
    ...dragProps(items[index]),
    ref: (el: HTMLElement | null) => {
      rowRefs.current[index] = el
    },
    'data-item-key': itemKey(items[index]),
    tabIndex: index === 0 || selection.has(itemKey(items[index])) ? 0 : -1,
    'aria-selected': selection.has(itemKey(items[index])),
    onPointerDown: (e: React.PointerEvent) => {
      lastPointer.current = e.pointerType
    },
    onClick: (e: MouseEvent) => onRowClick(e, index),
    onDoubleClick: () => onOpen(items[index]),
    onKeyDown: (e: KeyboardEvent) => onKeyDown(e, index),
  })

  return (
    // Fills the rest of the page, so the space below the last item is
    // somewhere to start a selection box or open the "new" menu.
    <div ref={surface} className="relative flex-1 pb-16" onPointerDown={marquee.onPointerDown}>
      {props.view === 'grid' ? <GridView {...props} rowProps={rowProps} /> : <ListView {...props} rowProps={rowProps} />}
      {marquee.rect ? (
        <div
          aria-hidden
          className="pointer-events-none absolute z-10 rounded-sm border border-primary bg-primary/15"
          style={{ left: marquee.rect.left, top: marquee.rect.top, width: marquee.rect.width, height: marquee.rect.height }}
        />
      ) : null}
    </div>
  )
}

/**
 * The grid tile on the next row up or down, nearest in column — by the
 * rendered positions, since folder chips and file cards differ in height.
 */
function verticalNeighbour(tiles: (HTMLElement | null)[], index: number, direction: 1 | -1): number {
  const from = tiles[index]?.getBoundingClientRect()
  if (!from) return index
  const centre = from.left + from.width / 2
  let best = index
  let bestRow = Infinity
  let bestColumn = Infinity
  tiles.forEach((tile, i) => {
    if (!tile || i === index) return
    const r = tile.getBoundingClientRect()
    const row = direction === 1 ? r.top - from.top : from.top - r.top
    if (row <= 1) return
    const column = Math.abs(r.left + r.width / 2 - centre)
    if (row < bestRow - 1 || (Math.abs(row - bestRow) <= 1 && column < bestColumn)) {
      best = i
      bestRow = row
      bestColumn = column
    }
  })
  return best
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
                  'data-[drop-target=true]:bg-primary/10 data-[drop-target=true]:ring-2 data-[drop-target=true]:ring-inset data-[drop-target=true]:ring-primary',
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

function GridView({ items, selection, actionsFor, renderPreview, rowProps }: ExplorerProps & { rowProps: RowProps }) {
  const { i18n } = useTranslation()
  return (
    <ul className="grid grid-cols-[repeat(auto-fill,minmax(12rem,1fr))] gap-3 p-4" role="grid" aria-multiselectable>
      {items.map((item, index) => {
        const selected = selection.has(itemKey(item))
        const tile = cn(
          'group relative cursor-default select-none rounded-xl border border-border bg-card outline-none transition-colors',
          'hover:border-primary/40 hover:bg-muted/40 focus-visible:ring-2 focus-visible:ring-ring',
          selected && 'border-primary bg-accent hover:bg-accent',
          'data-[drop-target=true]:border-primary data-[drop-target=true]:bg-primary/10 data-[drop-target=true]:ring-2 data-[drop-target=true]:ring-primary',
        )
        if (item.type === 'folder') {
          // A folder has no preview: the same card as a file, with a large
          // folder icon where the picture would be.
          return (
            <li key={itemKey(item)} {...rowProps(index)} className={cn(tile, 'flex flex-col overflow-hidden')}>
              <div className="flex h-11 items-center gap-2 pl-3 pr-1">
                <KindIcon kind={item.kind} color={item.color} className="size-5" />
                <p className="min-w-0 flex-1 truncate text-sm" title={item.name}>{item.name}</p>
                <RowMenu item={item} actions={actionsFor(item)} />
              </div>
              <div className="mx-2 flex aspect-[4/3] items-center justify-center">
                <KindIcon kind={item.kind} color={item.color} className="size-20" />
              </div>
              <p className="px-3 pb-2 pt-1.5 text-xs text-muted-foreground">{formatFileDate(item.modifiedAt, i18n.language)}</p>
            </li>
          )
        }
        return (
          <li key={itemKey(item)} {...rowProps(index)} className={cn(tile, 'flex flex-col overflow-hidden')}>
            {/* Header: what it is and what it is called, like Google Drive's cards. */}
            <div className="flex h-11 items-center gap-2 pl-3 pr-1">
              <KindIcon kind={item.kind} color={item.color} className="size-5" />
              <p className="min-w-0 flex-1 truncate text-sm" title={item.name}>
                {item.name}
              </p>
              <RowMenu item={item} actions={actionsFor(item)} />
            </div>
            <div
              className={cn(
                // Clipped: a tall page must not stretch the card past 4:3.
                'relative mx-2 flex aspect-[4/3] items-center justify-center overflow-hidden rounded-lg',
                selected ? 'bg-background/60' : 'bg-muted/70',
              )}
            >
              {renderPreview?.(item) ?? <KindIcon kind={item.kind} color={item.color} className="size-14" />}
            </div>
            <p className="px-3 pb-2 pt-1.5 text-xs text-muted-foreground">{formatFileDate(item.modifiedAt, i18n.language)}</p>
          </li>
        )
      })}
    </ul>
  )
}
