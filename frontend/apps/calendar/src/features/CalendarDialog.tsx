import { Check } from 'lucide-react'
import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import {
  CALENDAR_COLORS,
  PERMISSION,
  createCalendar,
  deleteCalendar,
  updateCalendar,
  useCalendarMutation,
  type Calendar,
  type DefaultReminders,
} from '@kutup/calendar-core/api'
import { useMailAccount } from '@kutup/mail-core/api'
import { useRequiredSession } from '@kutup/session/store'
import { Alert } from '@kutup/ui/components/alert'
import { Button } from '@kutup/ui/components/button'
import { ConfirmDestructive } from '@kutup/ui/components/confirm-destructive'
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle } from '@kutup/ui/components/dialog'
import { Input } from '@kutup/ui/components/input'
import { Label } from '@kutup/ui/components/label'
import { Textarea } from '@kutup/ui/components/textarea'
import { apiErrorMessage } from '@kutup/ui/lib/apiError'
import { cn } from '@kutup/ui/lib/cn'
import { ReminderList } from './reminders/ReminderList'
import { hasRepeats } from './reminders/triggers'

/** Kutup-crypto's limits on a calendar's name and description. */
const MAX_NAME = 100
const MAX_DESCRIPTION = 255
/** Proton's default notifications per kind (`MAX_DEFAULT_NOTIFICATIONS`); the server holds its own (`calendarDefaultReminders`). */
const MAX_DEFAULT_REMINDERS = 5

/** Makes a calendar, or renames, recolours or deletes one. */
export function CalendarDialog({ open, onOpenChange, calendar }: { open: boolean; onOpenChange: (open: boolean) => void; calendar?: Calendar }) {
  const { t } = useTranslation()
  const session = useRequiredSession()
  const account = useMailAccount()
  const [name, setName] = useState('')
  const [description, setDescription] = useState('')
  const [color, setColor] = useState<string>(CALENDAR_COLORS[0])
  const [confirming, setConfirming] = useState(false)
  // Proton's event defaults: this member's, for timed and all-day events.
  const [defaults, setDefaults] = useState<DefaultReminders>({ timed: [], allDay: [] })
  const owner = !calendar || (calendar.permissions & PERMISSION.owner) !== 0

  const save = useCalendarMutation(async () => {
    if (!account.data) throw new Error('no mail keys')
    if (!calendar) return createCalendar(session, account.data, name.trim(), color)
    await updateCalendar(session, account.data, calendar, {
      ...(owner && (name.trim() !== calendar.name || description !== calendar.description) ? { name: name.trim(), description } : {}),
      ...(color !== calendar.color ? { color } : {}),
      ...(JSON.stringify(defaults) !== JSON.stringify(calendar.defaultReminders) ? { defaultReminders: defaults } : {}),
    })
    return calendar.id
  })
  const remove = useCalendarMutation(async () => {
    if (calendar) await deleteCalendar(session, calendar)
  })

  useEffect(() => {
    if (!open) return
    setName(calendar?.name ?? '')
    setDescription(calendar?.description ?? '')
    setColor(calendar?.color ?? CALENDAR_COLORS[Math.floor(Math.random() * CALENDAR_COLORS.length)])
    setDefaults(calendar?.defaultReminders ?? { timed: [], allDay: [] })
    save.reset()
    // eslint-disable-next-line react-hooks/exhaustive-deps -- reset once per opening
  }, [open, calendar])

  return (
    <>
      <Dialog open={open} onOpenChange={onOpenChange}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{calendar ? t('calendars.editTitle') : t('calendars.newTitle')}</DialogTitle>
          </DialogHeader>
          <form
            className="mt-4 space-y-4"
            onSubmit={(e) => {
              e.preventDefault()
              if (!name.trim()) return
              save.mutate(undefined, {
                onSuccess: () => {
                  toast.success(calendar ? t('calendars.saved') : t('calendars.created'))
                  onOpenChange(false)
                },
              })
            }}
          >
            <div className="space-y-1.5">
              <Label htmlFor="calendar-name">{t('calendars.name')}</Label>
              <Input
                id="calendar-name"
                value={name}
                onChange={(e) => setName(e.target.value)}
                maxLength={MAX_NAME}
                disabled={!owner}
                autoFocus
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
                {hasRepeats(defaults.timed) || hasRepeats(defaults.allDay) ? (
                  <p className="text-xs text-destructive" role="alert">
                    {t('reminders.picker.repeats')}
                  </p>
                ) : null}
              </>
            ) : null}
            <p className="text-xs text-muted-foreground">{t('calendars.encrypted')}</p>
            {save.error ? <Alert variant="error">{apiErrorMessage(save.error, t('calendars.saveFailed'))}</Alert> : null}
            <DialogFooter className="sm:justify-between">
              {calendar && (calendar.permissions & PERMISSION.superOwner) !== 0 ? (
                <Button type="button" variant="ghost" onClick={() => setConfirming(true)} data-testid="calendar-delete">
                  {t('calendars.delete')}
                </Button>
              ) : (
                <span />
              )}
              <div className="flex gap-2">
                <Button type="button" variant="ghost" onClick={() => onOpenChange(false)}>
                  {t('common.cancel')}
                </Button>
                <Button type="submit" loading={save.isPending} disabled={!name.trim() || hasRepeats(defaults.timed) || hasRepeats(defaults.allDay)} data-testid="calendar-save">
                  {t('common.save')}
                </Button>
              </div>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>
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
