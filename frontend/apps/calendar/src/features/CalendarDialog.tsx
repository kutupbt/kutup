import { Check } from 'lucide-react'
import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import {
  CALENDAR_COLORS,
  PERMISSION,
  createCalendar,
  deleteCalendar,
  feedState,
  updateCalendar,
  useCalendarMutation,
  type Calendar,
  type DefaultReminders,
} from '@kutup/calendar-core/api'
import { useMailAccount } from '@kutup/mail-core/api'
import { useRequiredSession } from '@kutup/session/store'
import { Alert } from '@kutup/ui/components/alert'
import { Button } from '@kutup/ui/components/button'
import { Checkbox } from '@kutup/ui/components/checkbox'
import { ConfirmDestructive } from '@kutup/ui/components/confirm-destructive'
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle } from '@kutup/ui/components/dialog'
import { Input } from '@kutup/ui/components/input'
import { Label } from '@kutup/ui/components/label'
import { Textarea } from '@kutup/ui/components/textarea'
import { apiErrorMessage } from '@kutup/ui/lib/apiError'
import { cn } from '@kutup/ui/lib/cn'
import { ReminderList } from './reminders/ReminderList'
import { useQuery } from '@tanstack/react-query'
import { compactKeys, COMPACT_AT, keyGenerationCap, leaveCalendar } from './sharing/client'
import { hasRepeats } from './reminders/triggers'

/** Kutup-crypto's limits on a calendar's name and description. */
const MAX_NAME = 100
const MAX_DESCRIPTION = 255
/** Proton's default notifications per kind (`MAX_DEFAULT_NOTIFICATIONS`); the server holds its own (`calendarDefaultReminders`). */
const MAX_DEFAULT_REMINDERS = 5

/** Makes a calendar, or renames, recolours or deletes one. */
export function CalendarDialog({
  open,
  onOpenChange,
  calendar,
  onExport,
  fromUrl = false,
}: {
  open: boolean
  onOpenChange: (open: boolean) => void
  calendar?: Calendar
  /** A new calendar from a URL (Proton's "Add calendar from URL", E5a). */
  fromUrl?: boolean
  /** Proton's calendar export: every event in one `.ics` file. */
  onExport?: (calendar: Calendar) => void
}) {
  const { t } = useTranslation()
  const session = useRequiredSession()
  const account = useMailAccount()
  const [name, setName] = useState('')
  const [description, setDescription] = useState('')
  const [color, setColor] = useState<string>(CALENDAR_COLORS[0])
  const [url, setUrl] = useState('')
  const subscribing = !calendar && fromUrl
  const [confirming, setConfirming] = useState(false)
  // Proton's event defaults: this member's, for timed and all-day events.
  const [defaults, setDefaults] = useState<DefaultReminders>({ timed: [], allDay: [] })
  // Others may see when this member is busy from it (times only; E3e).
  const [shareBusy, setShareBusy] = useState(false)
  const owner = !calendar || (calendar.permissions & PERMISSION.owner) !== 0

  const save = useCalendarMutation(async () => {
    if (!account.data) throw new Error('no mail keys')
    if (!calendar) return createCalendar(session, account.data, name.trim(), color, subscribing ? url.trim() : undefined)
    await updateCalendar(session, account.data, calendar, {
      ...(owner && (name.trim() !== calendar.name || description !== calendar.description) ? { name: name.trim(), description } : {}),
      ...(color !== calendar.color ? { color } : {}),
      ...(JSON.stringify(defaults) !== JSON.stringify(calendar.defaultReminders) ? { defaultReminders: defaults } : {}),
      ...(calendar.owned && shareBusy !== calendar.shareBusy ? { shareBusy } : {}),
    })
    return calendar.id
  })
  const remove = useCalendarMutation(async () => {
    if (calendar) await deleteCalendar(session, calendar)
  })
  // A member leaves what someone else owns (docs/plans/calendar-e3.md §1).
  const leave = useCalendarMutation(async () => {
    if (calendar) await leaveCalendar(session, calendar)
  })
  const [leaving, setLeaving] = useState(false)
  // The owner tidies old key generations away (compaction): offered while
  // the calendar holds more than one, urged near the site's cap.
  const cap = useQuery({ queryKey: ['calendar', 'keyGenerationCap'], enabled: !!calendar?.owned, queryFn: keyGenerationCap, staleTime: 60_000 })
  const compact = useCalendarMutation(async () => {
    if (calendar) return compactKeys(calendar)
    return 0
  })
  const nearCap = !!calendar && !!cap.data && calendar.keyGenerations >= cap.data * COMPACT_AT

  useEffect(() => {
    if (!open) return
    setName(calendar?.name ?? '')
    setUrl('')
    setDescription(calendar?.description ?? '')
    setColor(calendar?.color ?? CALENDAR_COLORS[Math.floor(Math.random() * CALENDAR_COLORS.length)])
    setDefaults(calendar?.defaultReminders ?? { timed: [], allDay: [] })
    setShareBusy(calendar?.shareBusy ?? false)
    save.reset()
    // eslint-disable-next-line react-hooks/exhaustive-deps -- reset once per opening
  }, [open, calendar])

  return (
    <>
      <Dialog open={open} onOpenChange={onOpenChange}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{calendar ? t('calendars.editTitle') : subscribing ? t('feeds.newTitle') : t('calendars.newTitle')}</DialogTitle>
          </DialogHeader>
          <form
            className="mt-4 space-y-4"
            onSubmit={(e) => {
              e.preventDefault()
              if (!name.trim() || (subscribing && !url.trim())) return
              save.mutate(undefined, {
                onSuccess: () => {
                  toast.success(calendar ? t('calendars.saved') : subscribing ? t('feeds.created') : t('calendars.created'))
                  onOpenChange(false)
                },
              })
            }}
          >
            {subscribing ? (
              <div className="space-y-1.5">
                <Label htmlFor="calendar-feed-url">{t('feeds.url')}</Label>
                <Input
                  id="calendar-feed-url"
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                  inputMode="url"
                  autoComplete="off"
                  spellCheck={false}
                  placeholder="https://"
                  maxLength={8192}
                  autoFocus
                  required
                  data-testid="calendar-feed-url"
                />
                <p className="text-xs text-muted-foreground">{t('feeds.urlHint')}</p>
              </div>
            ) : null}
            {calendar?.feed ? <FeedDetails calendar={calendar} /> : null}
            <div className="space-y-1.5">
              <Label htmlFor="calendar-name">{t('calendars.name')}</Label>
              <Input
                id="calendar-name"
                value={name}
                onChange={(e) => setName(e.target.value)}
                maxLength={MAX_NAME}
                disabled={!owner}
                autoFocus={!subscribing}
                required
                data-testid="calendar-name"
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="calendar-description">{t('calendars.description')}</Label>
              <Textarea
                id="calendar-description"
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                maxLength={MAX_DESCRIPTION}
                disabled={!owner}
                rows={2}
              />
            </div>
            <fieldset className="space-y-2">
              <legend className="text-sm font-medium">{t('calendars.color')}</legend>
              <div className="flex flex-wrap gap-2">
                {CALENDAR_COLORS.map((option) => (
                  <button
                    key={option}
                    type="button"
                    onClick={() => setColor(option)}
                    aria-label={option}
                    aria-pressed={color === option}
                    className={cn('grid size-8 place-items-center rounded-full text-white ring-offset-2 ring-offset-background', color === option && 'ring-2 ring-ring')}
                    style={{ background: option }}
                  >
                    {color === option ? <Check className="size-4" aria-hidden /> : null}
                  </button>
                ))}
              </div>
            </fieldset>
            {calendar ? (
              <>
                <div className="space-y-1.5">
                  <Label>{t('reminders.defaults.timed')}</Label>
                  <ReminderList id="calendar-timed" allDay={false} reminders={defaults.timed} max={MAX_DEFAULT_REMINDERS} onChange={(timed) => setDefaults((d) => ({ ...d, timed }))} />
                </div>
                <div className="space-y-1.5">
                  <Label>{t('reminders.defaults.allDay')}</Label>
                  <ReminderList id="calendar-all-day" allDay reminders={defaults.allDay} max={MAX_DEFAULT_REMINDERS} onChange={(allDay) => setDefaults((d) => ({ ...d, allDay }))} />
                </div>
                {calendar?.owned && calendar.keyGenerations > 1 ? (
                  <div className="space-y-1.5" data-testid="calendar-key-generations">
                    <p className="text-xs text-muted-foreground">
                      {cap.data ? t('calendars.keys.count', { count: calendar.keyGenerations, cap: cap.data }) : t('calendars.keys.countBare', { count: calendar.keyGenerations })}
                    </p>
                    {nearCap ? <Alert variant="warn">{t('calendars.keys.nearCap')}</Alert> : null}
                    {compact.error ? <Alert variant="error">{apiErrorMessage(compact.error, t('calendars.keys.failed'))}</Alert> : null}
                    <Button
                      type="button"
                      size="sm"
                      variant="outline"
                      loading={compact.isPending}
                      onClick={() => compact.mutate(undefined, { onSuccess: (count) => toast.success(t('calendars.keys.done', { count })) })}
                      data-testid="calendar-compact"
                    >
                      {t('calendars.keys.compact')}
                    </Button>
                  </div>
                ) : null}
                {/* Busy times are answered from the calendars one owns: a member can't show the owner's. */}
                {calendar?.owned && !calendar.feed ? (
                  <div className="flex items-start gap-2">
                    <Checkbox id="calendar-share-busy" checked={shareBusy} onCheckedChange={(v) => setShareBusy(v === true)} className="mt-0.5" data-testid="calendar-share-busy" />
                    <div className="space-y-0.5">
                      <Label htmlFor="calendar-share-busy">{t('busy.share')}</Label>
                      <p className="text-xs text-muted-foreground">{t('busy.shareHint')}</p>
                    </div>
                  </div>
                ) : null}
                {hasRepeats(defaults.timed) || hasRepeats(defaults.allDay) ? (
                  <p className="text-xs text-destructive" role="alert">
                    {t('reminders.picker.repeats')}
                  </p>
                ) : null}
              </>
            ) : null}
            {calendar && onExport && (calendar.permissions & PERMISSION.read) !== 0 ? (
              <div className="space-y-1.5">
                <Label>{t('ics.export.section')}</Label>
                <p className="text-xs text-muted-foreground">{t('ics.export.sectionHint')}</p>
                <Button type="button" size="sm" variant="outline" onClick={() => onExport(calendar)} data-testid="calendar-export">
                  {t('ics.export.open')}
                </Button>
              </div>
            ) : null}
            <p className="text-xs text-muted-foreground">{t('calendars.encrypted')}</p>
            {calendar && !calendar.owned && calendar.owner ? (
              <p className="text-xs text-muted-foreground">{t('sharing.sharedBy', { address: calendar.owner.address })}</p>
            ) : null}
            {save.error ? <Alert variant="error">{feedError(save.error, t) ?? apiErrorMessage(save.error, t('calendars.saveFailed'))}</Alert> : null}
            <DialogFooter className="sm:justify-between">
              {calendar && (calendar.permissions & PERMISSION.superOwner) !== 0 ? (
                <Button type="button" variant="ghost" onClick={() => setConfirming(true)} data-testid="calendar-delete">
                  {t('calendars.delete')}
                </Button>
              ) : calendar && !calendar.owned ? (
                <Button type="button" variant="ghost" onClick={() => setLeaving(true)} data-testid="calendar-leave">
                  {t('sharing.leave')}
                </Button>
              ) : (
                <span />
              )}
              <div className="flex gap-2">
                <Button type="button" variant="ghost" onClick={() => onOpenChange(false)}>
                  {t('common.cancel')}
                </Button>
                <Button type="submit" loading={save.isPending} disabled={!name.trim() || (subscribing && !url.trim()) || hasRepeats(defaults.timed) || hasRepeats(defaults.allDay)} data-testid="calendar-save">
                  {t('common.save')}
                </Button>
              </div>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>
      {calendar && !calendar.owned ? (
        <ConfirmDestructive
          open={leaving}
          onOpenChange={setLeaving}
          title={t('sharing.leaveTitle', { name: calendar.name })}
          description={t('sharing.leaveDescription')}
          submit={t('sharing.leave')}
          pending={leave.isPending}
          error={leave.error}
          errorFallback={t('sharing.errors.saveFailed')}
          onConfirm={() =>
            leave.mutate(undefined, {
              onSuccess: () => {
                setLeaving(false)
                onOpenChange(false)
                toast.success(t('sharing.left', { name: calendar.name }))
              },
            })
          }
        />
      ) : null}
      {calendar ? (
        <ConfirmDestructive
          open={confirming}
          onOpenChange={setConfirming}
          title={t('calendars.deleteTitle', { name: calendar.name })}
          description={t('calendars.deleteDescription')}
          submit={t('calendars.delete')}
          pending={remove.isPending}
          error={remove.error}
          errorFallback={t('calendars.saveFailed')}
          onConfirm={() =>
            remove.mutate(undefined, {
              onSuccess: () => {
                setConfirming(false)
                onOpenChange(false)
                toast.success(t('calendars.deleted'))
              },
            })
          }
        />
      ) : null}
    </>
  )
}

/** The server's refusals of a feed, in words (E5a). */
function feedError(error: unknown, t: (key: string) => string): string | null {
  const code = (error as { response?: { data?: { code?: string } } })?.response?.data?.code
  if (code === 'feedUrlInvalid') return t('feeds.errors.url')
  if (code === 'feedLimit') return t('feeds.errors.limit')
  return null
}

/** A subscription's address (its owner's only) and how its last fetch went. */
function FeedDetails({ calendar }: { calendar: Calendar }) {
  const { t, i18n } = useTranslation()
  const feed = calendar.feed!
  const state = feedState(feed)
  const when = (at: string | null) => (at ? new Date(at).toLocaleString(i18n.language) : t('feeds.never'))
  return (
    <div className="space-y-1.5 rounded-md border p-3 text-sm" data-testid="calendar-feed-details">
      <p className="font-medium">{t('feeds.subscribed')}</p>
      {feed.url ? <p className="break-all text-xs text-muted-foreground" data-testid="calendar-feed-address">{feed.url}</p> : null}
      <p className={cn('text-xs', state === 'ok' || state === 'syncing' ? 'text-muted-foreground' : 'text-status-warn')} data-testid="calendar-feed-state">
        {t(`feeds.state.${state}`)}
      </p>
      <p className="text-xs text-muted-foreground">{t('feeds.lastSynced', { when: when(feed.syncedAt) })}</p>
      {feed.skipped > 0 ? <p className="text-xs text-muted-foreground">{t('feeds.skipped', { count: feed.skipped })}</p> : null}
      <p className="text-xs text-muted-foreground">{t('feeds.readOnly')}</p>
    </div>
  )
}
