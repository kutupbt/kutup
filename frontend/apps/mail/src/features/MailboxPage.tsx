import { Archive, Check, Copy, Folder as FolderIcon, FolderInput, FolderPlus, Inbox as InboxIcon, Plus, Tag, Keyboard, Mail, MailOpen, OctagonAlert, Paperclip, Search, Star, StarOff, Trash2, UserPlus, UserRound } from 'lucide-react'
import { useEffect, useMemo, useRef, useState, type MouseEvent, type ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import { Link, Navigate, useLocation, useNavigate, useParams, useSearchParams } from 'react-router-dom'
import { toast } from 'sonner'
import { useContactLookup } from '@kutup/contacts-core/api'
import { FOLDERS, NoAddressKey, useDeleteMessages, useFolder, useMailAccount, type FolderId, type MailMessage, type PlaceKey } from '@kutup/mail-core/api'
import { flattenFolders, usePlaces } from '@kutup/mail-core/places'
import { appUrl } from '@kutup/session/apps'
import { Alert } from '@kutup/ui/components/alert'
import { Button } from '@kutup/ui/components/button'
import { Checkbox } from '@kutup/ui/components/checkbox'
import { ConfirmDestructive } from '@kutup/ui/components/confirm-destructive'
import {
  ContextMenu,
  ContextMenuContent,
  ContextMenuItem,
  ContextMenuSeparator,
  ContextMenuSub,
  ContextMenuSubContent,
  ContextMenuSubTrigger,
  ContextMenuTrigger,
} from '@kutup/ui/components/context-menu'
import { Skeleton } from '@kutup/ui/components/skeleton'
import { EmptyState } from '@kutup/ui/components/states'
import { Tooltip } from '@kutup/ui/components/tooltip'
import { apiErrorMessage } from '@kutup/ui/lib/apiError'
import { cn } from '@kutup/ui/lib/cn'
import { formatFileDate, formatInstant } from '@kutup/ui/lib/format'
import { openComposer } from './composerState'
import { MAIL_DRAG_TYPE, movesFor, useMailActions, type Movable, type MoveTarget } from './mailActions'
import { LabelChips } from './LabelChips'
import { Padlock } from './Padlock'
import { PersonAvatar } from './Person'
import { nameFor } from './personName'
import { useSaveContact } from './saveContactState'
import { PickerButton, PickerDialog, type PickerMode } from './PlacePicker'
import { openPlacesDialog } from './placesState'
import { ShortcutsDialog } from './ShortcutsDialog'
import { ThreadView } from './ThreadView'

const KNOWN = new Set<string>([...FOLDERS, 'all'])

type Lookup = ReturnType<typeof useContactLookup>

/** Who a row names: the sender for received mail, the recipients for sent mail and drafts; by their contact names. */
function correspondent(message: MailMessage, t: (key: string) => string, contacts: Lookup): string {
  if (message.direction === 'outbound') {
    const names = [...message.to, ...message.cc].map((m) => nameFor(m, contacts.find(m.address)))
    return names.length ? `${t('list.to')} ${names.join(', ')}` : t('list.noRecipients')
  }
  return message.from ? nameFor(message.from, contacts.find(message.from.address)) : t('list.unknownSender')
}

/** Whom a row's avatar shows: the sender, or the first recipient of sent mail. */
function avatarOf(message: MailMessage) {
  return message.direction === 'outbound' ? (message.to[0] ?? message.cc[0] ?? null) : message.from
}

function ToolbarButton({ label, onClick, children }: { label: string; onClick: () => void; children: ReactNode }) {
  return (
    <Tooltip label={label}>
      <Button variant="ghost" size="icon" aria-label={label} onClick={onClick}>
        {children}
      </Button>
    </Tooltip>
  )
}

function Kbd({ children }: { children: ReactNode }) {
  return <kbd className="ml-auto pl-4 font-sans text-xs text-muted-foreground">{children}</kbd>
}

const DELETES_FOREVER = new Set<FolderId>(['trash', 'spam', 'drafts'])

const MOVE_ICON: Record<MoveTarget, ReactNode> = {
  inbox: <InboxIcon />,
  archive: <Archive />,
  spam: <OctagonAlert />,
  trash: <Trash2 />,
}

const MOVE_KEY: Record<MoveTarget, string> = { inbox: 'I', archive: 'A', spam: 'S', trash: 'T' }

/** A folder: the list beside the open thread, as Proton's column layout. */
export function MailboxPage() {
  const { t, i18n } = useTranslation()
  const { folder: folderParam = 'inbox', threadId, placeId } = useParams()
  const location = useLocation()
  // One of the account's folders (`/f/<id>`) or labels (`/l/<id>`), else a fixed folder.
  const placeKind = location.pathname.startsWith('/f/') ? 'folder' : location.pathname.startsWith('/l/') ? 'label' : null
  const places = usePlaces()
  const [params] = useSearchParams()
  const q = params.get('q') ?? ''
  const navigate = useNavigate()
  const account = useMailAccount()
  const contacts = useContactLookup()
  const saveContact = useSaveContact()
  const fixed = (KNOWN.has(folderParam) ? folderParam : 'inbox') as FolderId
  const place: PlaceKey = placeKind && placeId ? `${placeKind}:${placeId}` : fixed
  // Where the list lives in the address bar.
  const base = placeKind && placeId ? `/${placeKind === 'folder' ? 'f' : 'l'}/${placeId}` : `/${fixed}`
  // Own folders and labels act as All mail does: every move is offered.
  const folder: FolderId = placeKind ? 'all' : fixed
  const placeName = placeKind === 'folder' ? places.data?.folders.get(placeId ?? '')?.name : placeKind === 'label' ? places.data?.labelsById.get(placeId ?? '')?.name : undefined
  const title = placeKind ? (placeName ?? '') : t(`folders.${fixed}`)
  const list = useFolder(place, q)
  const actions = useMailActions()
  const remove = useDeleteMessages()
  const [selected, setSelected] = useState<Set<string>>(new Set())
  // Where Shift extends a selection from, and the row the keyboard is on.
  const anchor = useRef<number | null>(null)
  const [cursor, setCursor] = useState<number | null>(null)
  const [deleting, setDeleting] = useState<string[] | null>(null)
  const [shortcuts, setShortcuts] = useState(false)
  // Move to / Label as opened from the keyboard, with the rows it acts on.
  const [picker, setPicker] = useState<{ mode: PickerMode; rows: MailMessage[] } | null>(null)
  // The rows a right-click menu acts on.
  const [menuFor, setMenuFor] = useState<MailMessage[]>([])
  const messages = useMemo(() => list.data?.pages.flatMap((page) => page.messages) ?? [], [list.data])
  const chosen = messages.filter((m) => selected.has(m.id))
  const search = q ? `?q=${encodeURIComponent(q)}` : ''
  const openIndex = messages.findIndex((m) => m.threadId === threadId)
  const here = cursor ?? (openIndex >= 0 ? openIndex : null)

  useEffect(() => {
    setSelected(new Set())
    anchor.current = null
    setCursor(null)
  }, [place, q])
  // Opening a thread puts the keyboard on it.
  useEffect(() => {
    if (openIndex >= 0) setCursor(openIndex)
  }, [openIndex])
  useEffect(() => {
    if (here !== null && messages[here]) document.getElementById(`mail-row-${messages[here].id}`)?.scrollIntoView({ block: 'nearest' })
  }, [here, messages])

  function selectRange(from: number, to: number, add = true) {
    const [lo, hi] = from < to ? [from, to] : [to, from]
    setSelected((now) => {
      const next = add ? new Set(now) : new Set<string>()
      for (let i = lo; i <= hi; i += 1) if (messages[i]) next.add(messages[i].id)
      return next
    })
  }

  function toggle(index: number) {
    const message = messages[index]
    if (!message) return
    setSelected((now) => {
      const next = new Set(now)
      if (next.has(message.id)) next.delete(message.id)
      else next.add(message.id)
      return next
    })
    anchor.current = index
  }

  /** What an action acts on: the chosen rows, else the open conversation's rows, else the keyboard's row. */
  function targets(): MailMessage[] {
    if (chosen.length) return chosen
    if (threadId) return messages.filter((m) => m.threadId === threadId)
    return here !== null && messages[here] ? [messages[here]] : []
  }

  function move(rows: MailMessage[], target: MoveTarget) {
    actions.move(rows, target, () => {
      setSelected(new Set())
      // Moving the open conversation away closes it.
      if (threadId && rows.some((m) => m.threadId === threadId)) void navigate(`${base}${search}`)
    })
  }

  /** After a picker moved rows: clear the choice, close their conversation. */
  function afterPick(rows: MailMessage[]) {
    setSelected(new Set())
    if (threadId && rows.some((m) => m.threadId === threadId)) void navigate(`${base}${search}`)
  }

  function deleteForever(rows: MailMessage[]) {
    if (rows.length) setDeleting(rows.map((m) => m.id))
  }

  // Proton's list shortcuts (`packages/shared/lib/shortcuts/mail.ts`), kept
  // in a ref so the one listener always sees this render's list.
  const keys = useRef<(event: KeyboardEvent) => void>(() => undefined)
  keys.current = (event: KeyboardEvent) => {
    const target = event.target as HTMLElement | null
    if (event.altKey) return
    if (target && (target.isContentEditable || ['INPUT', 'TEXTAREA', 'SELECT'].includes(target.tagName))) return
    if (document.querySelector('[role="dialog"], [role="menu"]')) return
    const meta = event.metaKey || event.ctrlKey
    const key = event.key
    const step = (delta: number) => {
      if (!messages.length) return
      event.preventDefault()
      const from = here ?? (delta > 0 ? -1 : messages.length)
      const next = Math.max(0, Math.min(messages.length - 1, from + delta))
      if (event.shiftKey) {
        // Shift extends the selection from where it started.
        if (anchor.current === null) anchor.current = here ?? next
        selectRange(anchor.current, next, false)
        setCursor(next)
      } else {
        anchor.current = next
        setCursor(next)
        void navigate(`${base}/${messages[next].threadId}${search}`)
      }
    }
    if (meta) {
      if (key === 'a' || key === 'A') {
        event.preventDefault()
        setSelected(chosen.length === messages.length ? new Set() : new Set(messages.map((m) => m.id)))
      } else if (key === 'Backspace' && DELETES_FOREVER.has(folder)) {
        event.preventDefault()
        deleteForever(targets())
      }
      return
    }
    switch (key) {
      case 'n':
        event.preventDefault()
        openComposer({ kind: 'new' })
        break
      case '/':
        event.preventDefault()
        document.querySelector<HTMLInputElement>('[data-mail-search]')?.focus()
        break
      case '?':
        event.preventDefault()
        setShortcuts(true)
        break
      case 'j':
      case 'J':
      case 'ArrowDown':
        step(1)
        break
      case 'k':
      case 'K':
      case 'ArrowUp':
        step(-1)
        break
      case 'x':
        if (here !== null) {
          event.preventDefault()
          toggle(here)
        }
        break
      case 'Escape':
        if (chosen.length) setSelected(new Set())
        else if (threadId) void navigate(`${base}${search}`)
        break
      case '*': {
        const rows = targets()
        actions.mark(rows, { starred: !rows.every((m) => m.starred) })
        break
      }
      case 'u':
        actions.mark(targets(), { seen: false }, () => {
          if (threadId) void navigate(`${base}${search}`)
        })
        break
      case 'r':
        actions.mark(targets(), { seen: true })
        break
      case 'a':
      case 'i':
      case 's':
      case 't': {
        const to: MoveTarget = key === 'a' ? 'archive' : key === 'i' ? 'inbox' : key === 's' ? (folder === 'spam' ? 'inbox' : 'spam') : 'trash'
        if (movesFor(folder).includes(to)) move(targets(), to)
        break
      }
      case 'm':
      case 'l': {
        const rows = targets()
        if (rows.length && (key === 'l' || movesFor(folder).length)) {
          event.preventDefault()
          setPicker({ mode: key === 'm' ? 'move' : 'label', rows })
        }
        break
      }
      case 'Delete':
        if (DELETES_FOREVER.has(folder)) deleteForever(targets())
        else move(targets(), 'trash')
        break
    }
  }
  useEffect(() => {
    const onKey = (event: KeyboardEvent) => keys.current(event)
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [])

  if (!placeKind && !KNOWN.has(folderParam)) return <Navigate to="/inbox" replace />

  if (account.isError) {
    return (
      <div className="p-6">
        {account.error instanceof NoAddressKey ? (
          <Alert title={t('account.noKeyTitle')}>
            {t('account.noKey')}{' '}
            <a className="underline" href={appUrl('account', '/settings/keys')}>
              {t('account.openAccount')}
            </a>
          </Alert>
        ) : (
          <Alert variant="error">{apiErrorMessage(account.error, t('common.tryAgain'))}</Alert>
        )}
      </div>
    )
  }

  /** A click on a row: Shift chooses a range, Ctrl/Cmd one more; a plain click opens it. */
  function onRowClick(event: MouseEvent, index: number) {
    if (event.shiftKey) {
      event.preventDefault()
      selectRange(anchor.current ?? index, index)
      setCursor(index)
    } else if (event.metaKey || event.ctrlKey) {
      event.preventDefault()
      toggle(index)
      setCursor(index)
    } else {
      anchor.current = index
    }
  }

  const moves = movesFor(folder)
  const moveLabel = (target: MoveTarget) => (folder === 'spam' && target === 'inbox' ? t('actions.notSpam') : t(`actions.moveTo.${target}`))
  const single = menuFor.length === 1 ? menuFor[0] : null
  const singlePerson = single ? avatarOf(single) : null

  const menu = (
    <ContextMenuContent className="w-64">
      {menuFor.some((m) => !m.seen) ? (
        <ContextMenuItem onSelect={() => actions.mark(menuFor, { seen: true })}>
          <MailOpen />
          {t('actions.markRead')}
          <Kbd>R</Kbd>
        </ContextMenuItem>
      ) : null}
      {menuFor.some((m) => m.seen) ? (
        <ContextMenuItem onSelect={() => actions.mark(menuFor, { seen: false })}>
          <Mail />
          {t('actions.markUnread')}
          <Kbd>U</Kbd>
        </ContextMenuItem>
      ) : null}
      {menuFor.every((m) => m.starred) ? (
        <ContextMenuItem onSelect={() => actions.mark(menuFor, { starred: false })}>
          <StarOff />
          {t('actions.unstar')}
          <Kbd>*</Kbd>
        </ContextMenuItem>
      ) : (
        <ContextMenuItem onSelect={() => actions.mark(menuFor, { starred: true })}>
          <Star />
          {t('actions.star')}
          <Kbd>*</Kbd>
        </ContextMenuItem>
      )}
      {moves.length ? <ContextMenuSeparator /> : null}
      {moves.map((target) => (
        <ContextMenuItem key={target} onSelect={() => move(menuFor, target)}>
          {MOVE_ICON[target]}
          {moveLabel(target)}
          <Kbd>{folder === 'spam' && target === 'inbox' ? 'S' : MOVE_KEY[target]}</Kbd>
        </ContextMenuItem>
      ))}
      {moves.length ? (
        <ContextMenuSub>
          <ContextMenuSubTrigger>
            <FolderInput />
            {t('places.moveTo')}
            <Kbd>M</Kbd>
          </ContextMenuSubTrigger>
          <ContextMenuSubContent className="max-h-80 w-60 overflow-y-auto">
            {flattenFolders(places.data?.tree ?? []).map((f) => (
              <ContextMenuItem key={f.id} onSelect={() => actions.move(menuFor, { folder: f.id, name: f.name }, () => afterPick(menuFor))}>
                <span style={{ width: `${(f.depth - 1) * 0.75}rem` }} />
                <FolderIcon style={{ color: f.color }} />
                <span className="truncate">{f.name}</span>
              </ContextMenuItem>
            ))}
            <ContextMenuItem
              onSelect={() =>
                openPlacesDialog({
                  kind: 'edit',
                  target: { kind: 'folder' },
                  onCreated: (id, name) => actions.move(menuFor, { folder: id, name }, () => afterPick(menuFor)),
                })
              }
            >
              <FolderPlus />
              {t('places.newFolder')}
            </ContextMenuItem>
          </ContextMenuSubContent>
        </ContextMenuSub>
      ) : null}
      <ContextMenuSub>
        <ContextMenuSubTrigger>
          <Tag />
          {t('places.labelAs')}
          <Kbd>L</Kbd>
        </ContextMenuSubTrigger>
        <ContextMenuSubContent className="max-h-80 w-60 overflow-y-auto">
          {(places.data?.labels ?? []).map((l) => {
            const all = menuFor.every((m) => m.labels.includes(l.id))
            return (
              <ContextMenuItem key={l.id} onSelect={() => actions.mark(menuFor, all ? { removeLabels: [l.id] } : { addLabels: [l.id] })}>
                {all ? <Check /> : <span className="w-4" />}
                <Tag style={{ color: l.color }} />
                <span className="truncate">{l.name}</span>
              </ContextMenuItem>
            )
          })}
          <ContextMenuItem
            onSelect={() =>
              openPlacesDialog({ kind: 'edit', target: { kind: 'label' }, onCreated: (id) => actions.mark(menuFor, { addLabels: [id] }) })
            }
          >
            <Plus />
            {t('places.newLabel')}
          </ContextMenuItem>
        </ContextMenuSubContent>
      </ContextMenuSub>
      {DELETES_FOREVER.has(folder) ? (
        <>
          <ContextMenuSeparator />
          <ContextMenuItem destructive onSelect={() => deleteForever(menuFor)}>
            <Trash2 />
            {t('actions.deleteForever')}
          </ContextMenuItem>
        </>
      ) : null}
      {single && singlePerson ? (
        <>
          <ContextMenuSeparator />
          <ContextMenuSub>
            <ContextMenuSubTrigger>
              <UserRound />
              <span className="min-w-0 truncate">{nameFor(singlePerson, contacts.find(singlePerson.address))}</span>
            </ContextMenuSubTrigger>
            <ContextMenuSubContent className="w-60">
              <ContextMenuItem onSelect={() => void navigate(`/all?q=${encodeURIComponent(singlePerson.address)}`)}>
                <Search />
                {single.direction === 'outbound' ? t('person.messagesTo') : t('person.messagesFrom')}
              </ContextMenuItem>
              <ContextMenuItem
                onSelect={() =>
                  void navigator.clipboard.writeText(singlePerson.address).then(
                    () => toast.success(t('person.copied')),
                    () => toast.error(t('common.tryAgain')),
                  )
                }
              >
                <Copy />
                {t('person.copy')}
              </ContextMenuItem>
              {!contacts.find(singlePerson.address) && singlePerson.address.toLowerCase() !== account.data?.address.toLowerCase() ? (
                <ContextMenuItem onSelect={() => saveContact(singlePerson)}>
                  <UserPlus />
                  {t('person.saveContact')}
                </ContextMenuItem>
              ) : null}
            </ContextMenuSubContent>
          </ContextMenuSub>
        </>
      ) : null}
    </ContextMenuContent>
  )

  const listPane = (
    <section
      aria-label={title}
      className={cn('flex min-h-0 flex-1 flex-col border-border md:w-[26rem] md:flex-none md:shrink-0 md:border-r', threadId && 'hidden md:flex')}
    >
      <div className="flex min-h-12 items-center gap-1 border-b border-border px-2">
        <Checkbox
          className="mx-2"
          aria-label={t('list.selectAll')}
          checked={messages.length > 0 && chosen.length === messages.length ? true : chosen.length > 0 ? 'indeterminate' : false}
          onCheckedChange={(on) => setSelected(on === true ? new Set(messages.map((m) => m.id)) : new Set())}
        />
        {chosen.length > 0 ? (
          <>
            <span className="px-1 text-sm">{t('list.selected', { count: chosen.length })}</span>
            <span className="flex-1" />
            <ToolbarButton label={t('actions.markRead')} onClick={() => actions.mark(chosen, { seen: true }, () => setSelected(new Set()))}>
              <MailOpen />
            </ToolbarButton>
            <ToolbarButton label={t('actions.markUnread')} onClick={() => actions.mark(chosen, { seen: false }, () => setSelected(new Set()))}>
              <Mail />
            </ToolbarButton>
            {moves.length ? <PickerButton mode="move" rows={chosen} folder={folder} onMoved={() => afterPick(chosen)} /> : null}
            <PickerButton mode="label" rows={chosen} folder={folder} onMoved={() => afterPick(chosen)} />
            {moves.map((target) => (
              <ToolbarButton key={target} label={moveLabel(target)} onClick={() => move(chosen, target)}>
                {MOVE_ICON[target]}
              </ToolbarButton>
            ))}
            {DELETES_FOREVER.has(folder) ? (
              <ToolbarButton label={t('actions.deleteForever')} onClick={() => deleteForever(chosen)}>
                <Trash2 className="text-destructive" />
              </ToolbarButton>
            ) : null}
          </>
        ) : (
          <>
            <h1 className="min-w-0 flex-1 truncate px-1 font-display text-base font-semibold">
              {q ? t('list.searchResults', { q }) : title}
            </h1>
            <ToolbarButton label={t('shortcuts.title')} onClick={() => setShortcuts(true)}>
              <Keyboard />
            </ToolbarButton>
          </>
        )}
      </div>
      {list.isPending || account.isPending ? (
        <div className="space-y-2 p-3">
          {[0, 1, 2, 3, 4].map((i) => (
            <Skeleton key={i} className="h-14 w-full" />
          ))}
        </div>
      ) : list.isError ? (
        <Alert variant="error" className="m-3">
          {apiErrorMessage(list.error, t('common.tryAgain'))}
        </Alert>
      ) : messages.length === 0 ? (
        <div className="p-3">
          <EmptyState
            title={q ? t('list.noMatches') : placeKind ? t(`empty.${placeKind}`) : t(`empty.${folder}`)}
            description={q ? t('list.noMatchesHint') : placeKind ? t(`emptyHint.${placeKind}`) : t(`emptyHint.${folder}`)}
          />
        </div>
      ) : (
        <ContextMenu
          onOpenChange={(open) => {
            if (!open) setMenuFor([])
          }}
        >
          <ContextMenuTrigger asChild>
            <ul className="min-h-0 flex-1 overflow-y-auto" aria-label={t('list.messages')}>
              {messages.map((message, index) => {
                const open = message.threadId === threadId
                const isChosen = selected.has(message.id)
                const inMenu = menuFor.some((m) => m.id === message.id)
                const person = avatarOf(message)
                return (
                  <li
                    key={message.id}
                    id={`mail-row-${message.id}`}
                    draggable={folder !== 'drafts'}
                    // A right click acts on the chosen rows when it lands on one of them, else on this row (Proton, Gmail).
                    onContextMenu={() => setMenuFor(isChosen ? chosen : [message])}
                    onDragStart={(e) => {
                      const rows = isChosen ? chosen : [message]
                      const data: Movable[] = rows.map(({ id, folder: from, direction, customFolder }) => ({ id, folder: from, direction, customFolder }))
                      e.dataTransfer.setData(MAIL_DRAG_TYPE, JSON.stringify(data))
                      e.dataTransfer.setData('text/plain', t('list.dragging', { count: rows.length }))
                      e.dataTransfer.effectAllowed = 'move'
                    }}
                    className={cn(
                      'group border-b border-border/60',
                      open ? 'bg-accent' : isChosen || inMenu ? 'bg-primary/10' : !message.seen && 'bg-primary/5',
                      here === index && 'shadow-[inset_3px_0_0_var(--primary)]',
                    )}
                  >
                    <div className="flex items-start gap-2 px-2 py-2">
                      {/* The avatar turns into the checkbox on hover, or once anything is chosen (Proton's list). */}
                      <span className="relative m-1 flex size-8 shrink-0 items-center justify-center">
                        <span className={cn('transition-opacity', chosen.length > 0 ? 'opacity-0' : 'group-hover:opacity-0')}>
                          <PersonAvatar mailbox={person} contact={contacts.find(person?.address)} size={32} />
                        </span>
                        <Checkbox
                          className={cn('absolute', chosen.length > 0 ? 'opacity-100' : 'opacity-0 group-hover:opacity-100 focus-visible:opacity-100')}
                          checked={isChosen}
                          onClick={(e) => {
                            // Shift-click chooses everything from the last one chosen.
                            if (e.shiftKey && anchor.current !== null) {
                              e.preventDefault()
                              selectRange(anchor.current, index)
                              setCursor(index)
                            }
                          }}
                          onCheckedChange={() => toggle(index)}
                          aria-label={t('list.select', { subject: message.subject || t('list.noSubject') })}
                        />
                      </span>
                      <Link
                        to={`${base}/${message.threadId}${search}`}
                        onClick={(e) => onRowClick(e, index)}
                        draggable={false}
                        className="min-w-0 flex-1 py-1"
                        aria-current={open ? 'true' : undefined}
                      >
                        <span className="flex items-center gap-2">
                          <span className={cn('min-w-0 flex-1 truncate text-sm', !message.seen ? 'font-semibold' : 'text-muted-foreground')}>
                            {correspondent(message, t, contacts)}
                          </span>
                          {message.attachmentCount > 0 ? <Paperclip className="size-3.5 text-muted-foreground" aria-label={t('list.hasAttachments')} /> : null}
                          <span className="shrink-0 text-xs text-muted-foreground" title={formatInstant(message.receivedAt, i18n.language) ?? undefined}>
                            {formatFileDate(message.receivedAt, i18n.language)}
                          </span>
                        </span>
                        <span className="mt-0.5 flex items-center gap-2">
                          <Padlock message={message} className="[&_svg]:size-3.5" />
                          <span className={cn('min-w-0 flex-1 truncate text-sm', !message.seen && 'font-medium')}>
                            {message.subject || t('list.noSubject')}
                          </span>
                          {placeKind !== 'folder' && (folder === 'all' || folder === 'starred') ? (
                            <span className="shrink-0 rounded bg-muted px-1.5 text-[11px] text-muted-foreground">
                              {message.folder === 'custom' ? (places.data?.folders.get(message.customFolder ?? '')?.name ?? '…') : t(`folders.${message.folder}`)}
                            </span>
                          ) : null}
                          <LabelChips ids={message.labels} places={places.data} />
                        </span>
                      </Link>
                      <button
                        type="button"
                        className={cn('m-1 rounded p-1 hover:bg-muted', !message.starred && 'opacity-0 group-hover:opacity-100 focus-visible:opacity-100')}
                        aria-label={message.starred ? t('actions.unstar') : t('actions.star')}
                        aria-pressed={message.starred}
                        onClick={() => actions.mark([message], { starred: !message.starred })}
                      >
                        <Star className={cn('size-4', message.starred ? 'fill-status-warn text-status-warn' : 'text-muted-foreground')} />
                      </button>
                    </div>
                  </li>
                )
              })}
              {list.hasNextPage ? (
                <li className="p-3 text-center">
                  <Button variant="outline" size="sm" onClick={() => void list.fetchNextPage()} disabled={list.isFetchingNextPage}>
                    {t('list.more')}
                  </Button>
                </li>
              ) : null}
            </ul>
          </ContextMenuTrigger>
          {menuFor.length ? menu : null}
        </ContextMenu>
      )}
    </section>
  )

  return (
    <div className="flex h-full min-h-0">
      {listPane}
      <div className={cn('min-h-0 min-w-0 flex-1 overflow-hidden', !threadId && 'hidden md:block')}>
        {threadId && account.data ? (
          <ThreadView account={account.data} folder={folder} base={base} threadId={threadId} onClose={() => void navigate(`${base}${search}`)} />
        ) : (
          <div className="flex h-full flex-col items-center justify-center gap-3 p-6 text-center text-muted-foreground">
            <Mail className="size-10" aria-hidden />
            <p className="text-sm">{t('read.pick')}</p>
            <p className="text-xs">{t('shortcuts.hint')}</p>
          </div>
        )}
      </div>
      <ConfirmDestructive
        open={deleting !== null}
        onOpenChange={(open) => !open && setDeleting(null)}
        title={t('actions.deleteForeverTitle', { count: deleting?.length ?? 0 })}
        description={t('actions.deleteForeverDescription', { count: deleting?.length ?? 0 })}
        submit={t('actions.deleteForever')}
        pending={remove.isPending}
        error={remove.error}
        errorFallback={t('common.tryAgain')}
        onConfirm={() => {
          const ids = deleting ?? []
          remove.mutate(ids, {
            onSuccess: () => {
              toast.success(t('toasts.deleted', { count: ids.length }))
              setSelected(new Set())
              setDeleting(null)
              if (threadId && messages.some((m) => ids.includes(m.id) && m.threadId === threadId)) void navigate(`${base}${search}`)
            },
          })
        }}
      />
      <ShortcutsDialog open={shortcuts} onOpenChange={setShortcuts} />
      {picker ? <PickerDialog mode={picker.mode} rows={picker.rows} folder={folder} onClose={() => setPicker(null)} onMoved={() => afterPick(picker.rows)} /> : null}
    </div>
  )
}
