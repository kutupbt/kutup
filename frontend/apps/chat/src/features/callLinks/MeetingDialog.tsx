import { Loader2 } from 'lucide-react'
import { useEffect, useState, type FormEvent } from 'react'
import { useTranslation } from 'react-i18next'
import { Alert } from '@kutup/ui/components/alert'
import { Button } from '@kutup/ui/components/button'
import { Checkbox } from '@kutup/ui/components/checkbox'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@kutup/ui/components/dialog'
import { Field } from '@kutup/ui/components/field'
import { Input } from '@kutup/ui/components/input'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@kutup/ui/components/select'
import type { MeetingDraft } from './useMeetings'
import { defaultStart, fromLocalDateTime, localDateTime, MEETING_LENGTHS } from './meetingTime'

/** A meeting title in the form: the sealed info holds 200 bytes of UTF-8. */
const MAX_TITLE_LENGTH = 60

/**
 * A meeting's title and, if it is scheduled, its day, time and length:
 * for a new meeting or to change one. The time is in this browser's time
 * zone; everyone else sees it in theirs.
 */
export function MeetingDialog({
  open,
  onOpenChange,
  initial,
  scheduled,
  submitLabel,
  heading,
  onSubmit,
}: {
  open: boolean
  onOpenChange: (open: boolean) => void
  /** The meeting being changed; absent for a new one. */
  initial?: MeetingDraft
  /** For a new meeting: start with a time filled in. */
  scheduled: boolean
  heading: string
  submitLabel: string
  onSubmit: (draft: MeetingDraft) => Promise<void>
}) {
  const { t } = useTranslation()
  const [title, setTitle] = useState('')
  const [timed, setTimed] = useState(false)
  const [date, setDate] = useState('')
  const [time, setTime] = useState('')
  const [length, setLength] = useState(60)
  const [waitingRoom, setWaitingRoom] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  // Each opening starts from the meeting as it is (or from a fresh default).
  useEffect(() => {
    if (!open) return
    const start = initial?.info.startsAtMs ?? (scheduled ? defaultStart(Date.now()) : undefined)
    const local = localDateTime(start ?? defaultStart(Date.now()))
    setTitle(initial?.info.title ?? '')
    setTimed(start !== undefined)
    setDate(local.date)
    setTime(local.time)
    setLength(initial?.info.durationMinutes ?? 60)
    setWaitingRoom(initial?.waitingRoom ?? false)
    setError(null)
    setBusy(false)
  }, [open, initial, scheduled])

  const trimmed = title.trim()
  const startsAtMs = timed ? fromLocalDateTime(date, time) : undefined

  async function submit(event: FormEvent) {
    event.preventDefault()
    if (!trimmed || busy || startsAtMs === null) return
    setBusy(true)
    setError(null)
    try {
      await onSubmit({
        info: startsAtMs === undefined ? { title: trimmed } : { title: trimmed, startsAtMs, durationMinutes: length },
        waitingRoom,
      })
      onOpenChange(false)
    } catch {
      setError(t('chat.meetings.saveFailed'))
    } finally {
      setBusy(false)
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-md" data-testid="chat-meeting-dialog">
        <form onSubmit={(event) => void submit(event)} className="space-y-4">
          <DialogHeader>
            <DialogTitle>{heading}</DialogTitle>
            <DialogDescription>{t('chat.meetings.dialogDescription')}</DialogDescription>
          </DialogHeader>
          <Field label={t('chat.meetings.titleField')} required>
            {(props) => (
              <Input
                {...props}
                autoFocus
                autoComplete="off"
                maxLength={MAX_TITLE_LENGTH}
                value={title}
                onChange={(event) => setTitle(event.target.value)}
                data-testid="chat-meeting-title"
              />
            )}
          </Field>
          <label className="flex items-center gap-2 text-sm">
            <Checkbox checked={timed} onCheckedChange={(checked) => setTimed(checked === true)} data-testid="chat-meeting-timed" />
            {t('chat.meetings.setTime')}
          </label>
          {timed ? (
            <div className="grid grid-cols-2 gap-3">
              <Field label={t('chat.meetings.date')} required>
                {(props) => <Input {...props} type="date" value={date} onChange={(event) => setDate(event.target.value)} data-testid="chat-meeting-date" />}
              </Field>
              <Field label={t('chat.meetings.time')} required>
                {(props) => <Input {...props} type="time" value={time} onChange={(event) => setTime(event.target.value)} data-testid="chat-meeting-time" />}
              </Field>
              <Field label={t('chat.meetings.length')} className="col-span-2">
                {(props) => (
                  <Select value={String(length)} onValueChange={(value) => setLength(Number(value))}>
                    <SelectTrigger {...props} data-testid="chat-meeting-length">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      {MEETING_LENGTHS.map((minutes) => (
                        <SelectItem key={minutes} value={String(minutes)}>
                          {t('chat.meetings.minutes', { count: minutes })}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                )}
              </Field>
            </div>
          ) : null}
          <div className="space-y-1">
            <label className="flex items-center gap-2 text-sm">
              <Checkbox checked={waitingRoom} onCheckedChange={(checked) => setWaitingRoom(checked === true)} data-testid="chat-meeting-waiting-room" />
              {t('chat.meetings.waitingRoom')}
            </label>
            <p className="pl-6 text-xs text-muted-foreground">{t('chat.meetings.waitingRoomHint')}</p>
          </div>
          {error ? <Alert variant="error">{error}</Alert> : null}
          <DialogFooter>
            <Button type="button" variant="ghost" onClick={() => onOpenChange(false)}>
              {t('common.cancel')}
            </Button>
            <Button type="submit" disabled={!trimmed || busy || startsAtMs === null} data-testid="chat-meeting-save">
              {busy ? <Loader2 className="animate-spin" /> : null}
              {submitLabel}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
