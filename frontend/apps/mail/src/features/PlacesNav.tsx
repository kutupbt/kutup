import { ChevronDown, ChevronRight, Folder, FolderPlus, MoreHorizontal, Pencil, Plus, Settings2, Tag, Trash2 } from 'lucide-react'
import { useState, type DragEvent, type ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import { Link, NavLink } from 'react-router-dom'
import type { FolderCount } from '@kutup/mail-core/api'
import { MAX_FOLDER_DEPTH, usePlaces, useUpdateFolder, type MailFolder, type MailLabel } from '@kutup/mail-core/places'
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from '@kutup/ui/components/dropdown-menu'
import { Spine } from '@kutup/ui/components/spine'
import { Tooltip } from '@kutup/ui/components/tooltip'
import { cn } from '@kutup/ui/lib/cn'
import { MAIL_DRAG_TYPE, useMailActions, type Movable } from './mailActions'
import { openPlacesDialog } from './placesState'

function readDrag(data: DataTransfer): Movable[] | null {
  try {
    return JSON.parse(data.getData(MAIL_DRAG_TYPE)) as Movable[]
  } catch {
    return null
  }
}

/** A sidebar row like `SidebarNavLink`, indented, with a fold toggle, a drop target and a menu. */
function PlaceRow({
  to,
  icon,
  label,
  depth = 1,
  unread,
  fold,
  menu,
  onDrop,
}: {
  to: string
  icon: ReactNode
  label: string
  depth?: number
  unread: number
  fold?: ReactNode
  menu: ReactNode
  onDrop: (rows: Movable[]) => void
}) {
  const [over, setOver] = useState(false)
  const drop = {
    onDragOver: (e: DragEvent<HTMLLIElement>) => {
      if (!e.dataTransfer.types.includes(MAIL_DRAG_TYPE)) return
      e.preventDefault()
      e.dataTransfer.dropEffect = 'move'
      setOver(true)
    },
    onDragLeave: () => setOver(false),
    onDrop: (e: DragEvent<HTMLLIElement>) => {
      setOver(false)
      const rows = readDrag(e.dataTransfer)
      if (!rows) return
      e.preventDefault()
      onDrop(rows)
    },
  }
  return (
    <li {...drop} className="group/place relative">
      <NavLink
        to={to}
        className={({ isActive }) =>
          cn(
            'relative flex h-9 items-center gap-2 rounded-md pr-8 text-sm transition-colors',
            'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-chrome-active',
            '[&_svg]:size-4 [&_svg]:shrink-0',
            over && 'ring-2 ring-chrome-active',
            isActive ? 'bg-chrome-accent font-medium text-chrome-foreground' : 'text-chrome-muted hover:bg-chrome-accent/60 hover:text-chrome-foreground',
          )
        }
        style={{ paddingLeft: `${0.25 + depth * 0.75}rem` }}
      >
        {({ isActive }) => (
          <>
            {isActive ? <Spine tone="chrome" /> : null}
            {fold ?? <span className="w-4" />}
            {icon}
            <span className="min-w-0 flex-1 truncate">{label}</span>
            {unread > 0 ? <span className="text-xs font-semibold tabular-nums text-chrome-foreground group-hover/place:invisible">{unread}</span> : null}
          </>
        )}
      </NavLink>
      <span className="absolute right-1 top-1/2 -translate-y-1/2 opacity-0 focus-within:opacity-100 group-hover/place:opacity-100">{menu}</span>
    </li>
  )
}

function Section({ title, add, addLabel, children }: { title: string; add: () => void; addLabel: string; children: ReactNode }) {
  const { t } = useTranslation()
  return (
    <li className="pt-3">
      <div className="flex h-7 items-center gap-1 px-3 text-xs font-semibold uppercase tracking-wide text-chrome-muted">
        <span className="flex-1">{title}</span>
        <Tooltip label={addLabel}>
          <button type="button" aria-label={addLabel} onClick={add} className="rounded p-1 hover:bg-chrome-accent hover:text-chrome-foreground">
            <Plus className="size-3.5" />
          </button>
        </Tooltip>
        <Tooltip label={t('places.manage')}>
          <Link to="/settings/folders" aria-label={t('places.manage')} className="rounded p-1 hover:bg-chrome-accent hover:text-chrome-foreground">
            <Settings2 className="size-3.5" />
          </Link>
        </Tooltip>
      </div>
      <ul className="space-y-0.5">{children}</ul>
    </li>
  )
}

function ItemMenu({ children, label }: { children: ReactNode; label: string }) {
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <button type="button" aria-label={label} className="rounded p-1 text-chrome-muted hover:bg-chrome-accent hover:text-chrome-foreground">
          <MoreHorizontal className="size-4" />
        </button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="start">{children}</DropdownMenuContent>
    </DropdownMenu>
  )
}

/**
 * The account's folders and labels in the sidebar, as Proton's (collapsible
 * folder tree, colours, unread counts, "+", a menu per item, mail dropped
 * on them is filed or labelled).
 */
export function PlacesNav({ counts }: { counts: FolderCount[] | undefined }) {
  const { t } = useTranslation()
  const places = usePlaces()
  const update = useUpdateFolder()
  const actions = useMailActions()
  const unread = (key: string) => counts?.find((c) => c.folder === key)?.unread ?? 0
  if (!places.data) return null

  const folderRows = (folders: MailFolder[]): ReactNode[] =>
    folders.flatMap((folder) => [
      <PlaceRow
        key={folder.id}
        to={`/f/${folder.id}`}
        depth={folder.depth}
        icon={<Folder style={{ color: folder.color }} />}
        label={folder.name}
        unread={unread(`folder:${folder.id}`)}
        fold={
          folder.children.length ? (
            <button
              type="button"
              aria-label={folder.expanded ? t('places.collapse', { name: folder.name }) : t('places.expand', { name: folder.name })}
              aria-expanded={folder.expanded}
              onClick={(e) => {
                e.preventDefault()
                update.mutate({ id: folder.id, expanded: !folder.expanded })
              }}
              className="rounded hover:bg-chrome-accent"
            >
              {folder.expanded ? <ChevronDown /> : <ChevronRight />}
            </button>
          ) : undefined
        }
        onDrop={(rows) => actions.move(rows, { folder: folder.id, name: folder.name })}
        menu={
          <ItemMenu label={t('places.folderOptions', { name: folder.name })}>
            <DropdownMenuItem onSelect={() => openPlacesDialog({ kind: 'edit', target: { kind: 'folder', folder } })}>
              <Pencil />
              {t('places.editFolder')}
            </DropdownMenuItem>
            {folder.depth < MAX_FOLDER_DEPTH ? (
              <DropdownMenuItem onSelect={() => openPlacesDialog({ kind: 'edit', target: { kind: 'folder', parentId: folder.id } })}>
                <FolderPlus />
                {t('places.newSubfolder')}
              </DropdownMenuItem>
            ) : null}
            <DropdownMenuItem destructive onSelect={() => openPlacesDialog({ kind: 'delete', folder })}>
              <Trash2 />
              {t('places.deleteFolder')}
            </DropdownMenuItem>
          </ItemMenu>
        }
      />,
      ...(folder.expanded ? folderRows(folder.children) : []),
    ])

  const labelRow = (label: MailLabel) => (
    <PlaceRow
      key={label.id}
      to={`/l/${label.id}`}
      icon={<Tag style={{ color: label.color }} />}
      label={label.name}
      unread={unread(`label:${label.id}`)}
      onDrop={(rows) => actions.mark(rows, { addLabels: [label.id] })}
      menu={
        <ItemMenu label={t('places.labelOptions', { name: label.name })}>
          <DropdownMenuItem onSelect={() => openPlacesDialog({ kind: 'edit', target: { kind: 'label', label } })}>
            <Pencil />
            {t('places.editLabel')}
          </DropdownMenuItem>
          <DropdownMenuItem destructive onSelect={() => openPlacesDialog({ kind: 'delete', label })}>
            <Trash2 />
            {t('places.deleteLabel')}
          </DropdownMenuItem>
        </ItemMenu>
      }
    />
  )

  return (
    <>
      <Section title={t('places.folders')} addLabel={t('places.newFolder')} add={() => openPlacesDialog({ kind: 'edit', target: { kind: 'folder' } })}>
        {places.data.tree.length ? folderRows(places.data.tree) : <li className="px-3 py-1 text-xs text-chrome-muted">{t('places.noFolders')}</li>}
      </Section>
      <Section title={t('places.labels')} addLabel={t('places.newLabel')} add={() => openPlacesDialog({ kind: 'edit', target: { kind: 'label' } })}>
        {places.data.labels.length ? places.data.labels.map(labelRow) : <li className="px-3 py-1 text-xs text-chrome-muted">{t('places.noLabels')}</li>}
      </Section>
    </>
  )
}
