import { AlarmClock, Archive, Ban, Check, Clock, Copy, Folder as FolderIcon, FolderInput, FolderPlus, Hourglass, Inbox as InboxIcon, Plus, Tag, Keyboard, Mail, MailOpen, OctagonAlert, Paperclip, Search, Star, StarOff, Trash2, UserPlus, UserRound } from 'lucide-react'
import { useEffect, useMemo, useRef, useState, type CSSProperties, type MouseEvent, type ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import { Link, Navigate, useLocation, useNavigate, useParams, useSearchParams } from 'react-router-dom'
import { toast } from 'sonner'
import { useContactLookup } from '@kutup/contacts-core/api'
import { DEFAULT_PAGE_SIZE, FOLDERS, membersOf, useBatchMessages, NoAddressKey, rowSeen, rowStarred, useDeleteMessages, useEmptyFolder, useFolder, useMailAccount, useMailSettings, useUpdateMailSettings, type FolderId, type ListFilter, type ListSort, type MailMessage, type PlaceKey } from '@kutup/mail-core/api'
import { oneTimeCode } from '@kutup/mail-core/oneTimeCode'
import { flattenFolders, usePlaces } from '@kutup/mail-core/places'
import { isSearching, listCriteria, searchFromParams } from '@kutup/mail-core/search'
import { useContentSearch, useContentSearchList, useContentSearchState } from '@kutup/mail-core/contentSearch'
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
import { openBlockSender } from './blockState'
import { openComposer } from './composerState'
import { replyCommand } from './messageCommands'
import { useMailboxScope } from './mailboxScope'
import { MAIL_DRAG_TYPE, movesFor, useMailActions, type Movable, type MoveTarget } from './mailActions'
import { LabelChips } from './LabelChips'
import { ListFilters } from './ListFilters'
import { Padlock } from './Padlock'
import { PaneSplitter } from './PaneSplitter'
import { usePaneSize } from './paneSize'
import { PersonAvatar } from './Person'
import { nameFor } from './personName'
import { useSaveContact } from './saveContactState'
import { PickerButton, PickerDialog, type PickerMode } from './PlacePicker'
import { openPlacesDialog } from './placesState'
import { ShortcutsDialog } from './ShortcutsDialog'
import { ThreadView } from './ThreadView'
import { ListPagination, PagingControls } from './Paging'
import { pageCount, pageFromParams } from './paging'
import { SelectionPane } from './SelectionPane'
import { OneTimeCodeButton } from './OneTimeCode'
import { AttachmentChips } from './AttachmentChips'
import { SnoozeButton, UnsnoozeButton } from './Snooze'
import { chipsShown } from './attachments'
import { SelectAllBanner, SelectAllConfirm } from './SelectAll'
import { canSelectAll, type AllAction } from './selectAll'

const KNOWN = new Set<string>([...FOLDERS, 'all'])
const FILTERS: ListFilter[] = ['unread', 'read', 'attachments']
const SORTS: ListSort[] = ['newest', 'oldest', 'largest', 'smallest']

type Lookup = ReturnType<typeof useContactLookup>

/** Who a row names: the sender for received mail, the recipients for sent mail and drafts; by their contact names. */
function correspondent(message: MailMessage, t: (key: string) => string, contacts: Lookup, own: string): string {
  // A conversation names everyone who wrote in it, you as "me" (Proton's senders), unless only you did.
  const senders = message.conversation?.senders ?? []
  if (senders.some((m) => m.address.toLowerCase() !== own)) {
    return senders.map((m) => (m.address.toLowerCase() === own ? t('list.me') : nameFor(m, contacts.find(m.address)))).join(', ')
  }
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
  const [params, setParams] = useSearchParams()
  const q = params.get('q') ?? ''
  // Proton's advanced search, in the address bar beside the keyword.
  const searching = searchFromParams(params)
  const criteriaKey = JSON.stringify(listCriteria(searching))
  const criteria = useMemo(() => JSON.parse(criteriaKey) as ReturnType<typeof listCriteria>, [criteriaKey])
  const advanced = isSearching({ ...searching, q: '' })
  // Proton's filter and sort, kept in the address bar.
  const filter = FILTERS.find((f) => f === params.get('filter')) ?? null
  const sort = SORTS.find((s) => s === params.get('sort')) ?? 'newest'
  // Proton's paging: the page (from 1) in the address bar, gone on page 1.
  const page = pageFromParams(params)
  const setPage = (to: number) => {
    const next = new URLSearchParams(params)
    if (to > 1) next.set('page', String(to))
    else next.delete('page')
    setParams(next)
  }
  // A new filter or sort starts from the first page, as Proton's.
  const setView = (change: { filter?: ListFilter | null; sort?: ListSort }) => {
    const next = new URLSearchParams(params)
    next.delete('page')
    if ('filter' in change) {
      if (change.filter) next.set('filter', change.filter)
      else next.delete('filter')
    }
    if ('sort' in change) {
      if (change.sort && change.sort !== 'newest') next.set('sort', change.sort)
      else next.delete('sort')
    }
    setParams(next, { replace: true })
  }
  const navigate = useNavigate()
  const account = useMailAccount()
  const contacts = useContactLookup()
  const saveContact = useSaveContact()
  const scope = useMailboxScope()
  const { group } = scope
  // A shared mailbox has no drafts (they are each member's own); your own
  // folders and labels are in your own mailbox only.
  const fixed = (KNOWN.has(folderParam) && !(group && folderParam === 'drafts') ? folderParam : 'inbox') as FolderId
  const place: PlaceKey = placeKind && placeId ? `${placeKind}:${placeId}` : fixed
  // Where the list lives in the address bar.
  const base = placeKind && placeId ? `/${placeKind === 'folder' ? 'f' : 'l'}/${placeId}` : `${scope.base}/${fixed}`
  // Own folders and labels act as All mail does: every move is offered.
  const folder: FolderId = placeKind ? 'all' : fixed
  const placeName = placeKind === 'folder' ? places.data?.folders.get(placeId ?? '')?.name : placeKind === 'label' ? places.data?.labelsById.get(placeId ?? '')?.name : undefined
  const title = placeKind ? (placeName ?? '') : t(`folders.${fixed}`)
  const actions = useMailActions(group)
  const remove = useDeleteMessages()
  const emptyFolder = useEmptyFolder()
  const settings = useMailSettings()
  const updateSettings = useUpdateMailSettings()
  // Appearance (Proton's Layouts): the reading pane beside or below the list, and how tight its rows are.
  const layout = settings.data?.viewLayout ?? 'column'
  const compact = settings.data?.density === 'compact'
  // The row layout has room for one line per message, as Proton's.
  const oneLine = layout === 'row'
  const [paneSize, setPaneSize] = usePaneSize(layout)
  // Conversation grouping (Proton's View mode, on by default); the list waits for the setting.
  const conversations = (settings.data?.viewMode ?? 'conversation') === 'conversation'
  const pageSize = settings.data?.pageSize ?? DEFAULT_PAGE_SIZE
  // Body search, when on and built: a keyword in your own mailbox is answered
  // from this browser's index, found, filtered and paged here.
  const contentSearch = useContentSearch()
  const contentState = useContentSearchState(contentSearch)
  const byContent = !!q.trim() && !group && contentState.searchable
  const serverList = useFolder(place, { q, criteria, group, conversations, filter, sort, page: page - 1, pageSize }, !settings.isPending && !byContent)
  const contentList = useContentSearchList(contentSearch, place, { q, criteria, conversations, filter, sort, page: page - 1, pageSize }, byContent)
  const list = byContent ? contentList : serverList
  const total = list.data?.pages[0]?.total ?? null
  const pages = pageCount(total ?? 0, pageSize)
  const own = account.data?.address.toLowerCase() ?? ''
  const [emptying, setEmptying] = useState(false)
  // Trash and Spam can be emptied, and auto-delete applies to them (Proton).
  const unwanted = !placeKind && (fixed === 'trash' || fixed === 'spam') ? fixed : null
  const [selected, setSelected] = useState<Set<string>>(new Set())
  // Where Shift extends a selection from, and the row the keyboard is on.
  const anchor = useRef<number | null>(null)
  const [cursor, setCursor] = useState<number | null>(null)
  const [deleting, setDeleting] = useState<string[] | null>(null)
  // Proton's select all: actions go to every message of the place, past this page.
  const [allOfPlace, setAllOfPlace] = useState(false)
  const [pendingAll, setPendingAll] = useState<AllAction | null>(null)
  const batch = useBatchMessages()
  const [shortcuts, setShortcuts] = useState(false)
  // Move to / Label as opened from the keyboard, with the rows it acts on.
  const [picker, setPicker] = useState<{ mode: PickerMode; rows: MailMessage[] } | null>(null)
  // The rows a right-click menu acts on.
  const [menuFor, setMenuFor] = useState<MailMessage[]>([])
  const messages = useMemo(() => list.data?.pages.flatMap((page) => page.messages) ?? [], [list.data])
  const chosen = messages.filter((m) => selected.has(m.id))
  // The list's search, filter and sort go along to an opened conversation and back.
  const search = params.toString() ? `?${params.toString()}` : ''
  const openIndex = messages.findIndex((m) => m.threadId === threadId)
  const here = cursor ?? (openIndex >= 0 ? openIndex : null)

  useEffect(() => {
    setSelected(new Set())
    anchor.current = null
    setCursor(null)
  }, [place, q, page])
  // Select all ends with the place, page, search, filter or sort, and once a row is unchecked.
  useEffect(() => setAllOfPlace(false), [place, q, page, filter, sort])
  const showSelectAll = allOfPlace || (total !== null && total > 0 && canSelectAll({ checked: chosen.length, pageSize, folder, own: placeKind !== null, q, filtered: filter !== null || advanced }))
  useEffect(() => {
    if (allOfPlace && (chosen.length < messages.length || messages.length === 0)) setAllOfPlace(false)
  }, [allOfPlace, chosen.length, messages.length])
  // Past the last page (mail moved away): the last one.
  const pastEnd = total !== null && !list.isPlaceholderData && page > pages
  useEffect(() => {
    if (pastEnd) setPage(pages)
    // eslint-disable-next-line react-hooks/exhaustive-deps -- only when the list says so
  }, [pastEnd, pages])
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

  /** Select all's action on the whole place, once confirmed (Proton's select-all modals). */
  function runAll(action: AllAction) {
    const notice = toast.loading(t(conversations ? 'selectAll.applying.conversations' : 'selectAll.applying.messages'))
    const scoped = { place, ...(group ? { group } : {}) }
    const done = () => {
      toast.dismiss(notice)
      setPendingAll(null)
      setAllOfPlace(false)
      setSelected(new Set())
    }
    const requests =
      action.kind === 'mark'
        ? [{ ...scoped, seen: action.seen }]
        : action.kind === 'label'
          ? [{ ...scoped, addLabels: action.add, removeLabels: action.remove }]
          : typeof action.destination === 'object'
            ? [{ ...scoped, folder: 'custom' as const, customFolder: action.destination.folder }]
            : // Home is the Inbox for received mail and Sent for your own.
              action.destination === 'inbox'
              ? [
                  { ...scoped, folder: 'inbox' as const },
                  { ...scoped, folder: 'sent' as const },
                ]
              : [{ ...scoped, folder: action.destination }]
    requests
      .reduce<Promise<unknown>>((before, change) => before.then(() => batch.mutateAsync(change)), Promise.resolve())
      .then(
        () => {
          done()
          if (action.kind === 'move' && threadId) void navigate(`${base}${search}`)
        },
        (error: unknown) => {
          toast.dismiss(notice)
          setPendingAll(null)
          toast.error(apiErrorMessage(error, t('common.tryAgain')))
        },
      )
  }

  function markChosen(rows: MailMessage[], seen: boolean, after?: () => void) {
    if (allOfPlace) setPendingAll({ kind: 'mark', seen })
    else actions.mark(rows, { seen }, after)
  }

  function move(rows: MailMessage[], target: MoveTarget) {
    if (allOfPlace) {
      setPendingAll({ kind: 'move', destination: target })
      return
    }
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
    if (rows.length) setDeleting(membersOf(rows).map((m) => m.id))
  }

  // Proton's list shortcuts (`packages/shared/lib/shortcuts/mail.ts`), kept
  // in a ref so the one listener always sees this render's list.
  const keys = useRef<(event: KeyboardEvent) => void>(() => undefined)
  keys.current = (event: KeyboardEvent) => {
    const target = event.target as HTMLElement | null
    // Handled already: a dialog's Escape closes it, and React may have
    // removed the dialog before this listener runs.
    if (event.altKey || event.defaultPrevented) return
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
        openComposer({ kind: 'new', fromGroup: group })
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
        actions.mark(rows, { starred: !rows.every(rowStarred) })
        break
      }
      case 'u':
        markChosen(targets(), false, () => {
          if (threadId) void navigate(`${base}${search}`)
        })
        break
      case 'r':
        // With a conversation open (and nothing chosen), R replies, as Proton's message keys.
        if (threadId && chosen.length === 0) replyCommand('reply')
        else markChosen(targets(), true)
        break
      case 'R':
        if (threadId) replyCommand('replyAll')
        break
      case 'F':
        if (threadId) replyCommand('forward')
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
        if (rows.length && !allOfPlace && (key === 'l' ? !group : movesFor(folder).length)) {
          event.preventDefault()
          setPicker({ mode: key === 'm' ? 'move' : 'label', rows })
        }
        break
      }
      case 'Delete':
        if (allOfPlace && unwanted) setEmptying(true)
        else if (allOfPlace && folder === 'drafts') break
        else if (DELETES_FOREVER.has(folder)) deleteForever(targets())
        else move(targets(), 'trash')
        break
    }
  }
  useEffect(() => {
    const onKey = (event: KeyboardEvent) => keys.current(event)
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [])

  if (!placeKind && (!KNOWN.has(folderParam) || (group && folderParam === 'drafts'))) return <Navigate to={`${scope.base}/inbox`} replace />

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
      {menuFor.some((m) => !rowSeen(m)) ? (
        <ContextMenuItem onSelect={() => actions.mark(menuFor, { seen: true })}>
          <MailOpen />
          {t('actions.markRead')}
          <Kbd>R</Kbd>
        </ContextMenuItem>
      ) : null}
      {menuFor.some(rowSeen) ? (
        <ContextMenuItem onSelect={() => actions.mark(menuFor, { seen: false })}>
          <Mail />
          {t('actions.markUnread')}
          <Kbd>U</Kbd>
        </ContextMenuItem>
      ) : null}
      {menuFor.every(rowStarred) ? (
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
      {moves.length && !group ? (
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
      {group ? null : (
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
      )}
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
              {single.direction === 'inbound' && singlePerson.address.toLowerCase() !== account.data?.address.toLowerCase() ? (
                <ContextMenuItem onSelect={() => openBlockSender([singlePerson.address.toLowerCase()])}>
                  <Ban />
                  {t('person.block')}
                </ContextMenuItem>
              ) : null}
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
      style={{ '--pane': `${paneSize}px` } as CSSProperties}
      className={cn('flex min-h-0 flex-1 flex-col md:flex-none md:shrink-0', layout === 'column' ? 'md:w-[var(--pane)]' : 'md:h-[var(--pane)]', threadId && 'hidden md:flex')}
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
            <ToolbarButton label={t('actions.markRead')} onClick={() => markChosen(chosen, true, () => setSelected(new Set()))}>
              <MailOpen />
            </ToolbarButton>
            <ToolbarButton label={t('actions.markUnread')} onClick={() => markChosen(chosen, false, () => setSelected(new Set()))}>
              <Mail />
            </ToolbarButton>
            {!allOfPlace && folder === 'inbox' ? <SnoozeButton rows={chosen} group={group} onDone={() => afterPick(chosen)} /> : null}
            {!allOfPlace && folder === 'snoozed' ? <UnsnoozeButton rows={chosen} group={group} onDone={() => afterPick(chosen)} /> : null}
            {moves.length ? <PickerButton mode="move" rows={chosen} folder={folder} onMoved={() => afterPick(chosen)} onAll={allOfPlace ? setPendingAll : undefined} /> : null}
            <PickerButton
              mode="label"
              rows={chosen}
              folder={folder}
              onMoved={() => afterPick(chosen)}
              onAll={allOfPlace ? setPendingAll : undefined}
              currentLabel={placeKind === 'label' ? placeId : undefined}
            />
            {moves.map((target) => (
              <ToolbarButton key={target} label={moveLabel(target)} onClick={() => move(chosen, target)}>
                {MOVE_ICON[target]}
              </ToolbarButton>
            ))}
            {DELETES_FOREVER.has(folder) && !(allOfPlace && folder === 'drafts') ? (
              <ToolbarButton label={t('actions.deleteForever')} onClick={() => (allOfPlace ? setEmptying(true) : deleteForever(chosen))}>
                <Trash2 className="text-destructive" />
              </ToolbarButton>
            ) : null}
          </>
        ) : (
          <>
            <h1 className="min-w-0 flex-1 truncate px-1 font-display text-base font-semibold">
              {q ? t('list.searchResults', { q }) : advanced ? t('list.advancedResults', { place: title }) : title}
            </h1>
            {unwanted && messages.length > 0 ? (
              <Button variant="ghost" size="sm" className="text-destructive" onClick={() => setEmptying(true)}>
                <Trash2 />
                {t('emptyFolder.action')}
              </Button>
            ) : null}
            <ToolbarButton label={t('shortcuts.title')} onClick={() => setShortcuts(true)}>
              <Keyboard />
            </ToolbarButton>
          </>
        )}
      </div>
      {showSelectAll && total !== null ? (
        <SelectAllBanner
          on={allOfPlace}
          conversations={conversations}
          page={chosen.length}
          total={total}
          location={title}
          onToggle={() => {
            if (allOfPlace) setSelected(new Set())
            setAllOfPlace(!allOfPlace)
          }}
        />
      ) : null}
      <ListFilters filter={filter} sort={sort} onChange={setView} filtersHidden={chosen.length > 0}>
        <PagingControls page={page} pages={pages} onPage={setPage} disabled={total === null || list.isPlaceholderData} />
      </ListFilters>
      {byContent ? <p className="border-b border-border px-3 py-1.5 text-xs text-muted-foreground">{t('contentSearch.results')}</p> : null}
      {unwanted && !group && settings.data ? (
        <div className="flex flex-wrap items-center gap-2 border-b border-border bg-muted/40 px-3 py-2 text-xs text-muted-foreground">
          <span className="min-w-0 flex-1">{settings.data.autoDeleteDays ? t('emptyFolder.autoDeleteOn') : t('emptyFolder.autoDeleteOffer')}</span>
          {settings.data.autoDeleteDays ? null : (
            <Button
              variant="outline"
              size="sm"
              className="h-7"
              disabled={updateSettings.isPending}
              onClick={() =>
                updateSettings.mutate(
                  { autoDeleteDays: 30 },
                  { onSuccess: () => toast.success(t('emptyFolder.autoDeleteEnabled')), onError: (e) => toast.error(apiErrorMessage(e, t('common.tryAgain'))) },
                )
              }
            >
              {t('emptyFolder.enable')}
            </Button>
          )}
        </div>
      ) : null}
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
            title={q || advanced ? t('list.noMatches') : filter ? t('listFilter.empty') : placeKind ? t(`empty.${placeKind}`) : t(`empty.${folder}`)}
            description={q || advanced ? t('list.noMatchesHint') : filter ? '' : placeKind ? t(`emptyHint.${placeKind}`) : t(`emptyHint.${folder}`)}
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
                const seen = rowSeen(message)
                const starred = rowStarred(message)
                const attachments = message.conversation?.attachmentCount ?? message.attachmentCount
                const count = message.conversation?.members.length ?? 1
                // Proton's one-time code in the list, from the subject alone (rows carry no body).
                const code = message.direction === 'inbound' && !['spam', 'trash'].includes(message.folder) ? oneTimeCode({ subject: message.subject, at: Date.parse(message.receivedAt) }) : null
                const sender = (size: string) => (
                  <span className={cn(size, 'truncate text-sm', !seen ? 'font-semibold' : 'text-muted-foreground')}>{correspondent(message, t, contacts, own)}</span>
                )
                const meta = (
                  <>
                    {message.expiresAt ? (
                      <Hourglass className="size-3.5 text-muted-foreground" aria-label={t('expiry.row', { date: formatInstant(message.expiresAt, i18n.language) ?? '' })} />
                    ) : null}
                    {attachments > 0 ? <Paperclip className="size-3.5 text-muted-foreground" aria-label={t('list.hasAttachments')} /> : null}
                    {message.snoozedUntil ? (
                      // Snoozed: when it comes back.
                      <span className="flex shrink-0 items-center gap-1 text-xs text-primary" title={formatInstant(message.snoozedUntil, i18n.language) ?? undefined}>
                        <AlarmClock className="size-3.5" aria-hidden />
                        {t('snooze.rowUntil', { date: formatFileDate(message.snoozedUntil, i18n.language) })}
                      </span>
                    ) : message.scheduledAt ? (
                      // Scheduled: when it goes, not when it was written.
                      <span className="flex shrink-0 items-center gap-1 text-xs text-primary" title={formatInstant(message.scheduledAt, i18n.language) ?? undefined}>
                        <Clock className="size-3.5" aria-hidden />
                        {t('schedule.rowAt', { date: formatFileDate(message.scheduledAt, i18n.language) })}
                      </span>
                    ) : (
                      <span className="shrink-0 text-xs text-muted-foreground" title={formatInstant(message.receivedAt, i18n.language) ?? undefined}>
                        {formatFileDate(message.receivedAt, i18n.language)}
                      </span>
                    )}
                  </>
                )
                const subjectLine = (
                  <>
                    <Padlock message={message} className="[&_svg]:size-3.5" />
                    <span className={cn('min-w-0 flex-1 truncate text-sm', !seen && 'font-medium')}>{message.subject || t('list.noSubject')}</span>
                    {count > 1 ? (
                      <span className="shrink-0 rounded border border-border px-1 text-[11px] tabular-nums text-muted-foreground" aria-label={t('list.inConversation', { count })}>
                        {count}
                      </span>
                    ) : null}
                    {message.groupAddress && !group ? (
                      <span className="shrink-0 truncate rounded bg-muted px-1.5 text-[11px] text-muted-foreground" title={t('list.viaGroup', { address: message.groupAddress })}>
                        {message.groupAddress.split('@')[0]}
                      </span>
                    ) : null}
                    {message.sentBy ? <span className="shrink-0 rounded bg-muted px-1.5 text-[11px] text-muted-foreground">{t('list.sentBy', { name: message.sentBy })}</span> : null}
                    {placeKind !== 'folder' && (folder === 'all' || folder === 'starred') ? (
                      <span className="shrink-0 rounded bg-muted px-1.5 text-[11px] text-muted-foreground">
                        {message.folder === 'custom' ? (places.data?.folders.get(message.customFolder ?? '')?.name ?? '…') : t(`folders.${message.folder}`)}
                      </span>
                    ) : null}
                    <LabelChips ids={message.labels} places={places.data} />
                  </>
                )
                return (
                  <li
                    key={message.id}
                    id={`mail-row-${message.id}`}
                    draggable={folder !== 'drafts'}
                    // A right click acts on the chosen rows when it lands on one of them, else on this row (Proton, Gmail).
                    onContextMenu={() => setMenuFor(isChosen ? chosen : [message])}
                    onDragStart={(e) => {
                      const rows = isChosen ? chosen : [message]
                      // Each member with its thread: a drop on Spam may unsubscribe from its list.
                      const data: Movable[] = rows.flatMap((row) => membersOf([row]).map((member) => ({ ...member, threadId: row.threadId, unsubscribable: member.unsubscribable ?? row.unsubscribable })))
                      e.dataTransfer.setData(MAIL_DRAG_TYPE, JSON.stringify(data))
                      e.dataTransfer.setData('text/plain', t('list.dragging', { count: rows.length }))
                      e.dataTransfer.effectAllowed = 'move'
                    }}
                    className={cn(
                      'group border-b border-border/60',
                      open ? 'bg-accent' : isChosen || inMenu ? 'bg-primary/10' : !seen && 'bg-primary/5',
                      here === index && 'shadow-[inset_3px_0_0_var(--primary)]',
                    )}
                  >
                    <div className={cn('flex gap-2 px-2', compact ? 'py-0.5' : 'py-2', oneLine ? 'items-center' : 'items-start')}>
                      {/* The avatar turns into the checkbox on hover, or once anything is chosen (Proton's list). */}
                      <span className={cn('relative m-1 flex shrink-0 items-center justify-center', compact ? 'size-6' : 'size-8')}>
                        <span className={cn('transition-opacity', chosen.length > 0 ? 'opacity-0' : 'group-hover:opacity-0')}>
                          <PersonAvatar mailbox={person} contact={contacts.find(person?.address)} size={compact ? 24 : 32} />
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
                      <div className="min-w-0 flex-1 py-1">
                        <Link
                          to={`${base}/${message.threadId}${search}`}
                          onClick={(e) => onRowClick(e, index)}
                          draggable={false}
                          className="block"
                          aria-current={open ? 'true' : undefined}
                        >
                          {oneLine ? (
                            <span className="flex items-center gap-3">
                              {sender('w-48 shrink-0')}
                              <span className="flex min-w-0 flex-1 items-center gap-2">{subjectLine}</span>
                              {meta}
                            </span>
                          ) : (
                            <>
                              <span className="flex items-center gap-2">
                                {sender('min-w-0 flex-1')}
                                {meta}
                              </span>
                              <span className="mt-0.5 flex items-center gap-2">{subjectLine}</span>
                            </>
                          )}
                        </Link>
                        {/* Proton's attachment thumbnails: not in compact rows, never in Spam. */}
                        {!compact && message.folder !== 'spam' ? <AttachmentChips row={message} max={chipsShown(layout)} /> : null}
                      </div>
                      {code ? <OneTimeCodeButton code={code} className="my-1 ml-1 shrink-0" onCopied={() => move([message], 'trash')} /> : null}
                      <button
                        type="button"
                        className={cn('m-1 rounded p-1 hover:bg-muted', !starred && 'opacity-0 group-hover:opacity-100 focus-visible:opacity-100')}
                        aria-label={starred ? t('actions.unstar') : t('actions.star')}
                        aria-pressed={starred}
                        onClick={() => actions.mark([message], { starred: !starred })}
                      >
                        <Star className={cn('size-4', starred ? 'fill-status-warn text-status-warn' : 'text-muted-foreground')} />
                      </button>
                    </div>
                  </li>
                )
              })}
              {pages > 1 ? (
                <li>
                  <ListPagination page={page} pages={pages} onPage={setPage} disabled={list.isPlaceholderData} />
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
    <div className={cn('flex h-full min-h-0', layout === 'row' && 'md:flex-col')}>
      {listPane}
      <PaneSplitter layout={layout} size={paneSize} onResize={setPaneSize} />
      <div className={cn('min-h-0 min-w-0 flex-1 overflow-hidden', !threadId && 'hidden md:block')}>
        {/* Proton: rows checked beside the list show the selection pane, over an open conversation too. */}
        {threadId && account.data && !(layout === 'column' && chosen.length > 0) ? (
          <ThreadView account={account.data} folder={folder} base={base} threadId={threadId} onClose={() => void navigate(`${base}${search}`)} />
        ) : (
          <SelectionPane
            name={title}
            label={placeKind === 'label'}
            conversations={conversations}
            checked={allOfPlace ? (total ?? chosen.length) : chosen.length}
            allOfPlace={allOfPlace}
            total={total}
            q={q}
            onClear={() => {
              setAllOfPlace(false)
              setSelected(new Set())
            }}
          />
        )}
      </div>
      <SelectAllConfirm
        action={pendingAll}
        count={total ?? 0}
        conversations={conversations}
        destination={
          pendingAll?.kind === 'move' ? (typeof pendingAll.destination === 'object' ? pendingAll.destination.name : t(`folders.${pendingAll.destination === 'inbox' && folder === 'sent' ? 'sent' : pendingAll.destination}`)) : ''
        }
        labelName={(id) => places.data?.labelsById.get(id)?.name ?? ''}
        pending={batch.isPending}
        onCancel={() => setPendingAll(null)}
        onConfirm={() => pendingAll && runAll(pendingAll)}
      />
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
          remove.mutate({ ids, group }, {
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
      <ConfirmDestructive
        open={emptying}
        onOpenChange={setEmptying}
        title={t(unwanted === 'spam' ? 'emptyFolder.spamTitle' : 'emptyFolder.trashTitle')}
        description={t('emptyFolder.description')}
        submit={t('emptyFolder.action')}
        pending={emptyFolder.isPending}
        error={emptyFolder.error}
        errorFallback={t('common.tryAgain')}
        onConfirm={() => {
          if (!unwanted) return
          emptyFolder.mutate(
            { folder: unwanted, group },
            {
              onSuccess: (count) => {
                toast.success(t('toasts.deleted', { count }))
                setEmptying(false)
                setSelected(new Set())
                if (threadId) void navigate(`${base}${search}`)
              },
            },
          )
        }}
      />
      {picker ? <PickerDialog mode={picker.mode} rows={picker.rows} folder={folder} onClose={() => setPicker(null)} onMoved={() => afterPick(picker.rows)} /> : null}
    </div>
  )
}
