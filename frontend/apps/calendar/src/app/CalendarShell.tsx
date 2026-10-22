import { FeedbackButton } from '@kutup/ui/components/feedback'
import { feedbackServices } from '@kutup/session/feedback'
import { BookUser, CalendarDays, FileType, HardDrive, Images, KeyRound, Mail as MailIcon, Map as MapIcon, MessagesSquare, Pencil, Plus, Settings2, UserRound } from 'lucide-react'
import { useEffect, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Outlet } from 'react-router-dom'
import { toast } from 'sonner'
import { CALENDAR_COLORS, createCalendar, updateCalendar, useCalendarMutation, useCalendars, type Calendar } from '@kutup/calendar-core/api'
import { StorageMeter } from '@kutup/drive-ui/StorageMeter'
import { useMailAccount } from '@kutup/mail-core/api'
import { appUrl } from '@kutup/session/apps'
import { signOut } from '@kutup/session/signOut'
import { useRequiredSession } from '@kutup/session/store'
import { useAccountUiPreferences } from '@kutup/session/uiPreferences'
import { useAccountHeadState } from '@kutup/session/useAccountHeadState'
import { Alert } from '@kutup/ui/components/alert'
import { AppShell } from '@kutup/ui/components/app-shell'
import { AppSwitcher } from '@kutup/ui/components/app-switcher'
import { Button } from '@kutup/ui/components/button'
import { Checkbox } from '@kutup/ui/components/checkbox'
import { HeadStateBanner } from '@kutup/ui/components/head-state-banner'
import { UserMenu } from '@kutup/ui/components/user-menu'
import { apiErrorMessage } from '@kutup/ui/lib/apiError'
import { CalendarDialog } from '../features/CalendarDialog'
import { EventDialog } from '../features/EventDialog'
import { openEditor } from '../features/editorState'
import { useCalendarPrefs } from '../features/prefs'
import { SettingsDialog } from '../features/SettingsDialog'
import { useToday } from '../features/today'

/**
 * The first open makes the account a calendar of its own, as Proton's does:
 * once, when the list holds none (and none that couldn't be opened).
 */
function useFirstCalendar() {
  const { t } = useTranslation()
  const session = useRequiredSession()
  const account = useMailAccount()
  const calendars = useCalendars()
  const tried = useRef(false)
  const make = useCalendarMutation(() => createCalendar(session, account.data!, t('calendars.defaultName'), CALENDAR_COLORS[0]))
  useEffect(() => {
    if (tried.current || !account.data || !calendars.data) return
    if (calendars.data.calendars.length > 0 || calendars.data.unreadable > 0) return
    tried.current = true
    make.mutate(undefined)
  }, [account.data, calendars.data, make])
  return make
}

function CalendarRow({ calendar, onEdit }: { calendar: Calendar; onEdit: () => void }) {
  const { t } = useTranslation()
  const session = useRequiredSession()
  const account = useMailAccount()
  const toggle = useCalendarMutation((display: boolean) => updateCalendar(session, account.data!, calendar, { display }))
  return (
    <li className="group flex items-center gap-2 rounded-md px-3 py-1.5 text-sm hover:bg-chrome-accent/60">
      <Checkbox
        id={`calendar-${calendar.id}`}
        checked={calendar.display}
        disabled={toggle.isPending}
        onCheckedChange={(v) => toggle.mutate(v === true, { onError: () => toast.error(t('calendars.saveFailed')) })}
        style={{ borderColor: calendar.color, background: calendar.display ? calendar.color : undefined }}
        aria-label={t('calendars.show', { name: calendar.name })}
      />
      <label htmlFor={`calendar-${calendar.id}`} className="min-w-0 flex-1 truncate" data-testid="calendar-list-item">
        {calendar.name}
      </label>
      <button
        type="button"
        onClick={onEdit}
        aria-label={t('calendars.edit', { name: calendar.name })}
        className="text-chrome-muted opacity-0 hover:text-chrome-foreground focus-visible:opacity-100 group-hover:opacity-100"
      >
        <Pencil className="size-3.5" aria-hidden />
      </button>
    </li>
  )
}

/** Calendar's frame: new event, the calendars, settings and the shared storage. */
export function CalendarShell() {
  const { t } = useTranslation()
  const session = useRequiredSession()
  const accountHeadState = useAccountHeadState()
  useAccountUiPreferences()
  const prefs = useCalendarPrefs()
  const today = useToday(prefs.zone)
  const account = useMailAccount()
  const calendars = useCalendars()
  const first = useFirstCalendar()
  const [editing, setEditing] = useState<Calendar | 'new' | null>(null)
  const [settings, setSettings] = useState(false)

  return (
    <AppShell
      banner={<HeadStateBanner {...accountHeadState} />}
      appName={t('apps.calendar')}
      switcher={
        <AppSwitcher
          currentId="calendar"
          apps={[
            { id: 'drive', name: t('apps.drive'), href: appUrl('drive'), icon: <HardDrive /> },
            { id: 'office', name: t('apps.office'), href: appUrl('office'), icon: <FileType /> },
            { id: 'chat', name: t('apps.chat'), href: appUrl('chat'), icon: <MessagesSquare /> },
            { id: 'mail', name: t('apps.mail'), href: appUrl('mail'), icon: <MailIcon /> },
            { id: 'calendar', name: t('apps.calendar'), href: appUrl('calendar'), icon: <CalendarDays /> },
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
        <Button
          className="w-full"
          disabled={!today || !calendars.data?.calendars.length}
          onClick={() => today && openEditor({ kind: 'new', date: today })}
          data-testid="event-new"
        >
          <Plus />
          {t('events.new')}
        </Button>
      }
      nav={
        <>
          <li className="px-3 pb-1 pt-2 text-[11px] font-medium uppercase tracking-wider text-chrome-muted">{t('nav.calendars')}</li>
          {account.isError ? (
            <li className="px-3 text-xs">
              <Alert variant="error">{t('calendars.noMailKeys')}</Alert>
            </li>
          ) : null}
          {first.isError ? (
            <li className="px-3 text-xs">
              <Alert variant="error">{apiErrorMessage(first.error, t('calendars.saveFailed'))}</Alert>
            </li>
          ) : null}
          {(calendars.data?.calendars ?? []).map((calendar) => (
            <CalendarRow key={calendar.id} calendar={calendar} onEdit={() => setEditing(calendar)} />
          ))}
          <li>
            <button
              type="button"
              onClick={() => setEditing('new')}
              className="flex w-full items-center gap-3 rounded-md px-3 py-2 text-sm text-chrome-muted hover:bg-chrome-accent/60 hover:text-chrome-foreground"
              data-testid="calendar-new"
            >
              <Plus className="size-4" aria-hidden />
              {t('calendars.new')}
            </button>
          </li>
          <li>
            <button
              type="button"
              onClick={() => setSettings(true)}
              className="flex w-full items-center gap-3 rounded-md px-3 py-2 text-sm text-chrome-muted hover:bg-chrome-accent/60 hover:text-chrome-foreground"
            >
              <Settings2 className="size-4" aria-hidden />
              {t('settings.title')}
            </button>
          </li>
        </>
      }
      sidebarFooter={
        <div className="space-y-2">
          <FeedbackButton app="calendar" services={feedbackServices} />
          <StorageMeter />
        </div>
      }
      headerEnd={
        <UserMenu
          name={session.username ?? session.address}
          address={session.address}
          settingsHref={appUrl('account', '/settings/profile')}
          onSignOut={() => {
            void signOut().then(() => window.location.assign(appUrl('account', '/login')))
          }}
        />
      }
    >
      <Outlet />
      <EventDialog />
      <CalendarDialog
        open={editing !== null}
        onOpenChange={(open) => !open && setEditing(null)}
        calendar={editing === 'new' || editing === null ? undefined : editing}
      />
      <SettingsDialog open={settings} onOpenChange={setSettings} />
    </AppShell>
  )
}
