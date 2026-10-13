import { FeedbackButton } from '@kutup/ui/components/feedback'
import { feedbackServices } from '@kutup/session/feedback'
import {
  Archive,
  BookUser,
  AlarmClock,
  Clock,
  FilePen,
  FileType,
  HardDrive,
  Images,
  Inbox,
  KeyRound,
  Mail as MailIcon,
  Mails,
  Map as MapIcon,
  MessagesSquare,
  OctagonAlert,
  PenSquare,
  Search,
  Send,
  Settings,
  SlidersHorizontal,
  Star,
  Trash2,
  UserRound,
  Users,
} from 'lucide-react'
import { lazy, Suspense, useEffect, useState, type ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import { Link, Outlet, useNavigate, useParams, useSearchParams } from 'react-router-dom'
import { StorageMeter } from '@kutup/drive-ui/StorageMeter'
import { useCounts, type FolderId } from '@kutup/mail-core/api'
import { useMyGroups, type MailGroup } from '@kutup/mail-core/groups'
import { appUrl } from '@kutup/session/apps'
import { signOut } from '@kutup/session/signOut'
import { useRequiredSession } from '@kutup/session/store'
import { useAccountUiPreferences } from '@kutup/session/uiPreferences'
import { AppShell, SidebarNavLink } from '@kutup/ui/components/app-shell'
import { AppSwitcher } from '@kutup/ui/components/app-switcher'
import { Button } from '@kutup/ui/components/button'
import { Input } from '@kutup/ui/components/input'
import { Popover, PopoverContent, PopoverTrigger } from '@kutup/ui/components/popover'
import { Tooltip } from '@kutup/ui/components/tooltip'
import { UserMenu } from '@kutup/ui/components/user-menu'
import { AdvancedSearch } from '../features/AdvancedSearch'
import { NotificationBanner } from '../features/NotificationBanner'
import { useNewMailNotifications } from '../features/useNewMailNotifications'
import { openComposer, useComposer } from '../features/composerState'
import { MAILTO_HASH, parseMailto } from '../features/mailto'
import { MAIL_DRAG_TYPE, useMailActions, type Movable, type MoveTarget } from '../features/mailActions'
import { BlockSenderHost } from '../features/BlockSenderHost'
import { SpamUnsubscribeDialog } from '../features/SpamUnsubscribeDialog'
import { PlacesHost } from '../features/PlacesHost'
import { PlacesNav } from '../features/PlacesNav'
import { SaveContactHost } from '../features/SaveContactHost'

// The composer and its editor load the first time someone writes.
const Composer = lazy(() => import('../features/Composer').then((m) => ({ default: m.Composer })))

const NAV: { id: FolderId; icon: ReactNode }[] = [
  { id: 'inbox', icon: <Inbox /> },
  { id: 'drafts', icon: <FilePen /> },
  { id: 'scheduled', icon: <Clock /> },
  { id: 'snoozed', icon: <AlarmClock /> },
  { id: 'sent', icon: <Send /> },
  { id: 'starred', icon: <Star /> },
  { id: 'archive', icon: <Archive /> },
  { id: 'spam', icon: <OctagonAlert /> },
  { id: 'trash', icon: <Trash2 /> },
  { id: 'all', icon: <Mails /> },
]

/** Folders mail can be dragged onto. */
const DROPS = new Set<FolderId>(['inbox', 'starred', 'archive', 'spam', 'trash'])

function Count({ value }: { value: number }) {
  return <span className="text-xs font-semibold tabular-nums text-chrome-foreground">{value}</span>
}

/** A shared mailbox's folders (no drafts: those are each member's own). */
const SHARED_NAV: { id: FolderId; icon: ReactNode }[] = [
  { id: 'inbox', icon: <Inbox /> },
  { id: 'sent', icon: <Send /> },
  { id: 'archive', icon: <Archive /> },
  { id: 'spam', icon: <OctagonAlert /> },
  { id: 'trash', icon: <Trash2 /> },
]

/** One shared mailbox in the sidebar, with its unread count; its folders while it is open. */
function SharedMailbox({ group, open }: { group: MailGroup; open: boolean }) {
  const { t } = useTranslation()
  const counts = useCounts(group.id)
  const unread = (folder: FolderId) => counts.data?.find((c) => c.folder === folder)?.unread ?? 0
  return (
    <>
      <SidebarNavLink
        to={`/g/${group.id}/inbox`}
        icon={<Users />}
        label={group.displayName || group.address}
        trailing={unread('inbox') > 0 ? <Count value={unread('inbox')} /> : undefined}
      />
      {open ? (
        <li>
          <ul className="space-y-0.5 pl-4" aria-label={t('mailGroups.foldersOf', { name: group.displayName || group.address })}>
            {SHARED_NAV.filter(({ id }) => id !== 'inbox').map(({ id, icon }) => (
              <SidebarNavLink
                key={id}
                to={`/g/${group.id}/${id}`}
                icon={icon}
                label={t(`folders.${id}`)}
                trailing={id === 'spam' && unread(id) > 0 ? <Count value={unread(id)} /> : undefined}
              />
            ))}
          </ul>
        </li>
      ) : null}
    </>
  )
}

/** Searches subjects and addresses in all mail, as Proton's search box does; its options open advanced search. */
function SearchBox() {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const { folder } = useParams()
  const [params] = useSearchParams()
  const [value, setValue] = useState(params.get('q') ?? '')
  const [advanced, setAdvanced] = useState(false)
  useEffect(() => setValue(params.get('q') ?? ''), [params])
  return (
    <form
      role="search"
      className="relative w-full max-w-md"
      onSubmit={(e) => {
        e.preventDefault()
        const q = value.trim()
        void navigate(q ? `/all?q=${encodeURIComponent(q)}` : `/${folder === 'all' ? 'inbox' : (folder ?? 'inbox')}`)
      }}
    >
      <Search className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" aria-hidden />
      <Input
        type="search"
        data-mail-search
        value={value}
        onChange={(e) => setValue(e.target.value)}
        placeholder={t('search.placeholder')}
        aria-label={t('search.label')}
        className="pl-9 pr-10"
      />
      <Popover open={advanced} onOpenChange={setAdvanced}>
        <PopoverTrigger asChild>
          <Button type="button" variant="ghost" size="icon" className="absolute right-1 top-1/2 size-8 -translate-y-1/2" aria-label={t('search.advanced')} title={t('search.advanced')}>
            <SlidersHorizontal className="size-4" />
          </Button>
        </PopoverTrigger>
        <PopoverContent align="end" className="w-[min(26rem,calc(100vw-2rem))]">
          <AdvancedSearch onDone={() => setAdvanced(false)} />
        </PopoverContent>
      </Popover>
    </form>
  )
}

/** Mail's frame: Compose, the folders with their unread counts, and the shared storage. */
export function MailShell() {
  const { t } = useTranslation()
  const session = useRequiredSession()
  useAccountUiPreferences()
  const counts = useCounts()
  useNewMailNotifications()
  const actions = useMailActions()
  const groups = useMyGroups()
  const shared = (groups.data ?? []).filter((group) => group.kind === 'shared')
  const { groupId, folder: openFolder } = useParams()
  const composing = useComposer().target !== null
  const unread = (folder: FolderId) => counts.data?.find((c) => c.folder === folder)?.unread ?? 0
  const total = (folder: FolderId) => counts.data?.find((c) => c.folder === folder)?.total ?? 0
  const [params, setParams] = useSearchParams()
  const composeTo = params.get('to')

  // A mailto link, with Kutup Mail as the browser's mail app (`#mailto=mailto:…`).
  // Read while rendering: the route's redirect to the Inbox drops the hash before effects run.
  const [startHash] = useState(() => window.location.hash)
  useEffect(() => {
    const hash = startHash
    if (!hash.startsWith(MAILTO_HASH)) return
    const link = parseMailto(hash.slice(MAILTO_HASH.length))
    window.history.replaceState(null, '', window.location.pathname + window.location.search)
    if (link) openComposer({ kind: 'new', mailto: link })
  }, [startHash])

  // "Write to" from another app: open the composer with that address.
  useEffect(() => {
    if (!composeTo) return
    openComposer({ kind: 'new', to: composeTo })
    setParams(
      (now) => {
        const next = new URLSearchParams(now)
        next.delete('to')
        return next
      },
      { replace: true },
    )
  }, [composeTo, setParams])

  useEffect(() => {
    const inbox = unread('inbox')
    document.title = inbox > 0 ? `(${inbox}) ${t('apps.mail')} · Kutup` : `${t('apps.mail')} · Kutup`
  })

  return (
    <AppShell
      appName={t('apps.mail')}
      switcher={
        <AppSwitcher
          currentId="mail"
          apps={[
            { id: 'drive', name: t('apps.drive'), href: appUrl('drive'), icon: <HardDrive /> },
            { id: 'office', name: t('apps.office'), href: appUrl('office'), icon: <FileType /> },
            { id: 'chat', name: t('apps.chat'), href: appUrl('chat'), icon: <MessagesSquare /> },
            { id: 'mail', name: t('apps.mail'), href: appUrl('mail'), icon: <MailIcon /> },
            { id: 'pass', name: t('apps.pass'), href: appUrl('pass'), icon: <KeyRound /> },
            { id: 'contacts', name: t('apps.contacts'), href: appUrl('contacts'), icon: <BookUser /> },
            { id: 'photos', name: t('apps.photos'), href: appUrl('photos'), icon: <Images /> },
            { id: 'maps', name: t('apps.maps'), href: appUrl('maps'), icon: <MapIcon /> },
            { id: 'account', name: t('apps.account'), href: appUrl('account'), icon: <UserRound /> },
          ]}
        />
      }
      flush
      primaryAction={
        <Button className="w-full" onClick={() => openComposer({ kind: 'new', fromGroup: groupId })}>
          <PenSquare />
          {t('compose.new')}
        </Button>
      }
      nav={<>{NAV.filter(({ id }) => id !== 'scheduled' || total('scheduled') > 0 || openFolder === 'scheduled').map(({ id, icon }) => (
        <SidebarNavLink
          key={id}
          to={`/${id}`}
          icon={icon}
          label={t(`folders.${id}`)}
          drop={
            DROPS.has(id)
              ? {
                  // Your own folders take your own mail, not a shared mailbox's.
                  accepts: (types) => !groupId && types.includes(MAIL_DRAG_TYPE),
                  onDrop: (data) => {
                    // Mail dragged from the list: filed here, or starred on Starred.
                    let rows: Movable[]
                    try {
                      rows = JSON.parse(data.getData(MAIL_DRAG_TYPE)) as Movable[]
                    } catch {
                      return
                    }
                    if (id === 'starred') actions.mark(rows, { starred: true })
                    else actions.move(rows, id as MoveTarget)
                  },
                }
              : undefined
          }
          trailing={
            (id === 'drafts' || id === 'scheduled') && total(id) > 0 ? (
              <Count value={total(id)} />
            ) : id !== 'sent' && id !== 'trash' && unread(id) > 0 ? (
              <Count value={unread(id)} />
            ) : undefined
          }
        />
      ))}
          {shared.length > 0 ? (
            <li className="px-3 pb-1 pt-4 text-xs font-medium uppercase tracking-wide text-chrome-muted">{t('mailGroups.sharedMailboxes')}</li>
          ) : null}
          {shared.map((group) => (
            <SharedMailbox key={group.id} group={group} open={groupId === group.id} />
          ))}
          <SidebarNavLink to="/groups" icon={<Users />} label={t('mailGroups.title')} />
      <PlacesNav counts={counts.data} />
      </>}
      sidebarFooter={
        <div className="space-y-2">
          <FeedbackButton app="mail" services={feedbackServices} />
          <StorageMeter />
        </div>
      }
      headerStart={<SearchBox />}
      headerEnd={
        <>
        <Tooltip label={t('settings.title')}>
          <Button variant="ghost" size="icon" asChild aria-label={t('settings.title')}>
            <Link to="/settings">
              <Settings />
            </Link>
          </Button>
        </Tooltip>
        <UserMenu
          name={session.username ?? session.address}
          email={session.address}
          settingsHref={appUrl('account', '/settings/profile')}
          onSignOut={() => {
            void signOut().then(() => window.location.assign(appUrl('account', '/login')))
          }}
        />
        </>
      }
    >
      <Outlet />
      <NotificationBanner />
      <SaveContactHost />
      <PlacesHost />
      <BlockSenderHost />
      <SpamUnsubscribeDialog />
      {composing ? (
        <Suspense fallback={null}>
          <Composer />
        </Suspense>
      ) : null}
    </AppShell>
  )
}
