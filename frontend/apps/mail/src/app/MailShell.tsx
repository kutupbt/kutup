import {
  Archive,
  BookUser,
  FilePen,
  FileType,
  HardDrive,
  Images,
  Inbox,
  Mail as MailIcon,
  Map as MapIcon,
  MessagesSquare,
  OctagonAlert,
  PenSquare,
  Search,
  Send,
  Star,
  Settings,
  Trash2,
  UserRound,
} from 'lucide-react'
import { lazy, Suspense, useEffect, useState, type ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import { Link, Outlet, useNavigate, useParams, useSearchParams } from 'react-router-dom'
import { StorageMeter } from '@kutup/drive-ui/StorageMeter'
import { useCounts, type FolderId } from '@kutup/mail-core/api'
import { appUrl } from '@kutup/session/apps'
import { signOut } from '@kutup/session/signOut'
import { useRequiredSession } from '@kutup/session/store'
import { useAccountUiPreferences } from '@kutup/session/uiPreferences'
import { AppShell, SidebarNavLink } from '@kutup/ui/components/app-shell'
import { AppSwitcher } from '@kutup/ui/components/app-switcher'
import { Button } from '@kutup/ui/components/button'
import { Input } from '@kutup/ui/components/input'
import { Tooltip } from '@kutup/ui/components/tooltip'
import { UserMenu } from '@kutup/ui/components/user-menu'
import { openComposer, useComposer } from '../features/composerState'
import { MAIL_DRAG_TYPE, useMailActions, type Movable, type MoveTarget } from '../features/mailActions'
import { PlacesHost } from '../features/PlacesHost'
import { PlacesNav } from '../features/PlacesNav'
import { SaveContactHost } from '../features/SaveContactHost'

// The composer and its editor load the first time someone writes.
const Composer = lazy(() => import('../features/Composer').then((m) => ({ default: m.Composer })))

const NAV: { id: FolderId; icon: ReactNode }[] = [
  { id: 'inbox', icon: <Inbox /> },
  { id: 'drafts', icon: <FilePen /> },
  { id: 'sent', icon: <Send /> },
  { id: 'starred', icon: <Star /> },
  { id: 'archive', icon: <Archive /> },
  { id: 'spam', icon: <OctagonAlert /> },
  { id: 'trash', icon: <Trash2 /> },
]

/** Folders mail can be dragged onto. */
const DROPS = new Set<FolderId>(['inbox', 'starred', 'archive', 'spam', 'trash'])

function Count({ value }: { value: number }) {
  return <span className="text-xs font-semibold tabular-nums text-chrome-foreground">{value}</span>
}

/** Searches subjects and addresses in all mail, as Proton's search box does. */
function SearchBox() {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const { folder } = useParams()
  const [params] = useSearchParams()
  const [value, setValue] = useState(params.get('q') ?? '')
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
        className="pl-9"
      />
    </form>
  )
}

/** Mail's frame: Compose, the folders with their unread counts, and the shared storage. */
export function MailShell() {
  const { t } = useTranslation()
  const session = useRequiredSession()
  useAccountUiPreferences()
  const counts = useCounts()
  const actions = useMailActions()
  const composing = useComposer().target !== null
  const unread = (folder: FolderId) => counts.data?.find((c) => c.folder === folder)?.unread ?? 0
  const total = (folder: FolderId) => counts.data?.find((c) => c.folder === folder)?.total ?? 0
  const [params, setParams] = useSearchParams()
  const composeTo = params.get('to')

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
            { id: 'contacts', name: t('apps.contacts'), href: appUrl('contacts'), icon: <BookUser /> },
            { id: 'photos', name: t('apps.photos'), href: appUrl('photos'), icon: <Images /> },
            { id: 'maps', name: t('apps.maps'), href: appUrl('maps'), icon: <MapIcon /> },
            { id: 'account', name: t('apps.account'), href: appUrl('account'), icon: <UserRound /> },
          ]}
        />
      }
      flush
      primaryAction={
        <Button className="w-full" onClick={() => openComposer({ kind: 'new' })}>
          <PenSquare />
          {t('compose.new')}
        </Button>
      }
      nav={<>{NAV.map(({ id, icon }) => (
        <SidebarNavLink
          key={id}
          to={`/${id}`}
          icon={icon}
          label={t(`folders.${id}`)}
          drop={
            DROPS.has(id)
              ? {
                  accepts: (types) => types.includes(MAIL_DRAG_TYPE),
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
            id === 'drafts' && total(id) > 0 ? (
              <Count value={total(id)} />
            ) : id !== 'sent' && id !== 'trash' && unread(id) > 0 ? (
              <Count value={unread(id)} />
            ) : undefined
          }
        />
      ))}
      <PlacesNav counts={counts.data} />
      </>}
      sidebarFooter={<StorageMeter />}
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
          name={session.username ?? session.email}
          email={session.email}
          settingsHref={appUrl('account', '/settings/profile')}
          onSignOut={() => {
            void signOut().then(() => window.location.assign(appUrl('account', '/login')))
          }}
        />
        </>
      }
    >
      <Outlet />
      <SaveContactHost />
      <PlacesHost />
      {composing ? (
        <Suspense fallback={null}>
          <Composer />
        </Suspense>
      ) : null}
    </AppShell>
  )
}
