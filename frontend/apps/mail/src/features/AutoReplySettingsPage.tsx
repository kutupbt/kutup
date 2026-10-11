import { useMemo, useState, type ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { useAutoReply, useSaveAutoReply, type AutoReply, type AutoReplySettings } from '@kutup/mail-core/api'
import { sanitizeSignature } from '@kutup/mail-core/sanitize'
import { Alert } from '@kutup/ui/components/alert'
import { Button } from '@kutup/ui/components/button'
import { Checkbox } from '@kutup/ui/components/checkbox'
import { Input } from '@kutup/ui/components/input'
import { Label } from '@kutup/ui/components/label'
import { PageBody, PageHeader } from '@kutup/ui/components/page'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@kutup/ui/components/select'
import { LoadingPanel } from '@kutup/ui/components/states'
import { apiErrorMessage } from '@kutup/ui/lib/apiError'
import { SimpleEditor } from './SimpleEditor'

type Repeat = AutoReplySettings['repeat']
const REPEATS: Repeat[] = ['fixed', 'daily', 'weekly', 'monthly', 'permanent']
const MAX_BYTES = 10_000

const pad = (n: number) => String(n).padStart(2, '0')
const localDate = (d: Date) => `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`
const localTime = (d: Date) => `${pad(d.getHours())}:${pad(d.getMinutes())}`
const toMinutes = (time: string) => {
  const [h, m] = time.split(':').map(Number)
  return (h ?? 0) * 60 + (m ?? 0)
}
const fromMinutes = (minutes: number | null | undefined) => `${pad(Math.floor((minutes ?? 0) / 60))}:${pad((minutes ?? 0) % 60)}`

function browserZone(): string {
  try {
    return Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC'
  } catch {
    return 'UTC'
  }
}

function allZones(current: string): string[] {
  let zones: string[] = []
  try {
    zones = Intl.supportedValuesOf('timeZone')
  } catch {
    zones = []
  }
  return zones.includes(current) ? zones : [current, ...zones]
}

/** The form's state: dates and times as the inputs hold them. */
interface Model {
  repeat: Repeat
  zone: string
  startDate: string
  startTime: string
  endDate: string
  endTime: string
  days: number[]
  startDay: number
  endDay: number
  html: string
  text: string
}

/** Proton's defaults: a fixed week from now, the browser's zone, a short message. */
function modelOf(saved: AutoReplySettings | null, defaultText: string): Model {
  const now = new Date()
  const later = new Date(now.getTime() + (7 * 24 + 2) * 3600_000)
  const [startDate, startTime] = saved?.start?.split('T') ?? [localDate(now), localTime(now)]
  const [endDate, endTime] = saved?.end?.split('T') ?? [localDate(later), localTime(later)]
  const timed = saved && saved.repeat !== 'fixed' && saved.repeat !== 'permanent'
  return {
    repeat: saved?.repeat ?? 'fixed',
    zone: saved?.zone ?? browserZone(),
    startDate: startDate ?? localDate(now),
    startTime: timed ? fromMinutes(saved.startMinute) : (startTime ?? localTime(now)),
    endDate: endDate ?? localDate(later),
    endTime: timed ? fromMinutes(saved.endMinute) : (endTime ?? localTime(later)),
    days: saved?.days.length ? saved.days : [1, 2, 3, 4, 5],
    startDay: saved?.startDay ?? 1,
    endDay: saved?.endDay ?? (saved?.repeat === 'monthly' ? 1 : 5),
    html: saved?.messageHtml ?? `<p>${defaultText}</p>`,
    text: saved?.messageText ?? defaultText,
  }
}

function settingsOf(model: Model, enabled: boolean): AutoReplySettings {
  const base = { enabled, repeat: model.repeat, zone: model.zone, days: [] as number[], messageHtml: model.html, messageText: model.text }
  switch (model.repeat) {
    case 'fixed':
      return { ...base, start: `${model.startDate}T${model.startTime}`, end: `${model.endDate}T${model.endTime}` }
    case 'daily':
      return { ...base, days: [...model.days].sort(), startMinute: toMinutes(model.startTime), endMinute: toMinutes(model.endTime) }
    case 'weekly':
    case 'monthly':
      return { ...base, startDay: model.startDay, endDay: model.endDay, startMinute: toMinutes(model.startTime), endMinute: toMinutes(model.endTime) }
    case 'permanent':
      return base
  }
}

function Row({ label, htmlFor, children }: { label: string; htmlFor?: string; children: ReactNode }) {
  return (
    <div className="grid gap-1.5 sm:grid-cols-[12rem_1fr] sm:items-center sm:gap-4">
      <Label htmlFor={htmlFor}>{label}</Label>
      <div>{children}</div>
    </div>
  )
}

function Choice({ id, label, value, options, onChange }: { id: string; label: string; value: string; options: { value: string; label: string }[]; onChange: (value: string) => void }) {
  return (
    <Select value={value} onValueChange={onChange}>
      <SelectTrigger id={id} aria-label={label} className="max-w-xs">
        <SelectValue placeholder={label} />
      </SelectTrigger>
      <SelectContent>
        {options.map((o) => (
          <SelectItem key={o.value} value={o.value}>
            {o.label}
          </SelectItem>
        ))}
      </SelectContent>
    </Select>
  )
}

/** Settings → Auto-reply (Proton's Auto-reply section). */
export function AutoReplySettingsPage() {
  const { t } = useTranslation()
  const autoReply = useAutoReply()
  if (autoReply.isPending) return <LoadingPanel label={t('common.loading')} />
  if (autoReply.isError) return <Alert variant="error">{apiErrorMessage(autoReply.error, t('common.tryAgain'))}</Alert>
  return <AutoReplyEditor data={autoReply.data} />
}

function AutoReplyEditor({ data }: { data: AutoReply }) {
  const { t, i18n } = useTranslation()
  const save = useSaveAutoReply()
  const saved = data.settings
  // The form starts from what the server had when the page opened.
  const [enabled, setEnabled] = useState(saved?.enabled ?? false)
  const [model, setModel] = useState<Model>(() => modelOf(saved, t('autoReply.defaultMessage')))

  const weekdays = useMemo(() => {
    const format = new Intl.DateTimeFormat(i18n.language, { weekday: 'long' })
    // 2026-10-11 is a Sunday.
    return Array.from({ length: 7 }, (_, day) => ({ value: String(day), label: format.format(new Date(2026, 9, 11 + day)) }))
  }, [i18n.language])
  const monthDays = useMemo(() => Array.from({ length: 31 }, (_, i) => ({ value: String(i + 1), label: t('autoReply.dayOfMonth', { day: i + 1 }) })), [t])
  const zones = useMemo(() => allZones(model.zone).map((zone) => ({ value: zone, label: zone.replace(/_/g, ' ') })), [model.zone])

  const update = (change: Partial<Model>) => setModel({ ...model, ...change })
  const tooLong = new TextEncoder().encode(model.html).length > MAX_BYTES

  async function store(next: AutoReplySettings, done: string) {
    try {
      await save.mutateAsync(next)
      toast.success(done)
    } catch (error) {
      toast.error(apiErrorMessage(error, t('common.tryAgain')))
    }
  }

  async function toggle(on: boolean) {
    setEnabled(on)
    // Turning it off takes effect at once, as Proton's; turning it on waits for Save.
    if (!on && saved?.enabled) await store({ ...saved, enabled: false }, t('autoReply.disabled'))
  }

  function submit() {
    if (!model.text.trim()) {
      toast.error(t('autoReply.messageRequired'))
      return
    }
    if (model.repeat === 'daily' && model.days.length === 0) {
      toast.error(t('autoReply.daysRequired'))
      return
    }
    const html = sanitizeSignature(model.html)
    void store(settingsOf({ ...model, html }, true), t('autoReply.saved'))
  }

  const timeRow = (which: 'start' | 'end') => (
    <Row label={t(which === 'start' ? 'autoReply.startTime' : 'autoReply.endTime')} htmlFor={`auto-reply-${which}-time`}>
      <Input
        id={`auto-reply-${which}-time`}
        type="time"
        className="max-w-40"
        value={which === 'start' ? model.startTime : model.endTime}
        onChange={(e) => update(which === 'start' ? { startTime: e.target.value } : { endTime: e.target.value })}
        required
      />
    </Row>
  )

  return (
    <PageBody>
      <PageHeader title={t('autoReply.title')} description={t('autoReply.description')} />
      <div className="max-w-3xl space-y-6">
        <label className="flex items-start gap-3 rounded-lg border border-border p-4">
          <Checkbox className="mt-0.5" checked={enabled} disabled={save.isPending} onCheckedChange={(on) => void toggle(on === true)} />
          <span>
            <span className="block text-sm font-medium">{t('autoReply.toggle')}</span>
            <span className="block text-sm text-muted-foreground">
              {saved?.enabled ? (data.active ? t('autoReply.answeringNow') : t('autoReply.outsideSchedule')) : t('autoReply.off')}
            </span>
          </span>
        </label>

        {enabled ? (
          <form
            className="space-y-5"
            onSubmit={(e) => {
              e.preventDefault()
              submit()
            }}
          >
            <Row label={t('autoReply.duration')} htmlFor="auto-reply-repeat">
              <Choice
                id="auto-reply-repeat"
                label={t('autoReply.duration')}
                value={model.repeat}
                options={REPEATS.map((r) => ({ value: r, label: t(`autoReply.repeat.${r}`) }))}
                onChange={(value) => update({ repeat: value as Repeat, ...(value === 'monthly' ? { startDay: 1, endDay: 1 } : value === 'weekly' ? { startDay: 1, endDay: 5 } : {}) })}
              />
            </Row>
            <Alert variant="info">{t(`autoReply.explain.${model.repeat}`)}</Alert>

            {model.repeat === 'fixed' ? (
              <>
                <Row label={t('autoReply.startDate')} htmlFor="auto-reply-start-date">
                  <Input id="auto-reply-start-date" type="date" className="max-w-48" value={model.startDate} onChange={(e) => update({ startDate: e.target.value })} required />
                </Row>
                {timeRow('start')}
                <Row label={t('autoReply.endDate')} htmlFor="auto-reply-end-date">
                  <Input id="auto-reply-end-date" type="date" className="max-w-48" value={model.endDate} onChange={(e) => update({ endDate: e.target.value })} required />
                </Row>
                {timeRow('end')}
              </>
            ) : null}

            {model.repeat === 'daily' ? (
              <>
                <Row label={t('autoReply.days')}>
                  <div className="flex flex-wrap gap-1.5" role="group" aria-label={t('autoReply.days')}>
                    {weekdays.map((day) => {
                      const on = model.days.includes(Number(day.value))
                      return (
                        <Button
                          key={day.value}
                          type="button"
                          size="sm"
                          variant={on ? 'secondary' : 'outline'}
                          aria-pressed={on}
                          onClick={() => update({ days: on ? model.days.filter((d) => d !== Number(day.value)) : [...model.days, Number(day.value)] })}
                        >
                          {day.label}
                        </Button>
                      )
                    })}
                  </div>
                </Row>
                {timeRow('start')}
                {timeRow('end')}
              </>
            ) : null}

            {model.repeat === 'weekly' || model.repeat === 'monthly' ? (
              <>
                <Row label={t(model.repeat === 'weekly' ? 'autoReply.startWeekday' : 'autoReply.startDayOfMonth')} htmlFor="auto-reply-start-day">
                  <Choice
                    id="auto-reply-start-day"
                    label={t(model.repeat === 'weekly' ? 'autoReply.startWeekday' : 'autoReply.startDayOfMonth')}
                    value={String(model.startDay)}
                    options={model.repeat === 'weekly' ? weekdays : monthDays}
                    onChange={(value) => update({ startDay: Number(value) })}
                  />
                </Row>
                {timeRow('start')}
                <Row label={t(model.repeat === 'weekly' ? 'autoReply.endWeekday' : 'autoReply.endDayOfMonth')} htmlFor="auto-reply-end-day">
                  <Choice
                    id="auto-reply-end-day"
                    label={t(model.repeat === 'weekly' ? 'autoReply.endWeekday' : 'autoReply.endDayOfMonth')}
                    value={String(model.endDay)}
                    options={model.repeat === 'weekly' ? weekdays : monthDays}
                    onChange={(value) => update({ endDay: Number(value) })}
                  />
                </Row>
                {timeRow('end')}
              </>
            ) : null}

            {model.repeat !== 'permanent' ? (
              <Row label={t('autoReply.zone')} htmlFor="auto-reply-zone">
                <Choice id="auto-reply-zone" label={t('autoReply.zone')} value={model.zone} options={zones} onChange={(zone) => update({ zone })} />
              </Row>
            ) : null}

            <div className="space-y-2">
              <p className="text-sm font-medium">{t('autoReply.message')}</p>
              <p className="text-sm text-muted-foreground">{t('autoReply.readableHint')}</p>
              <SimpleEditor value={model.html} label={t('autoReply.message')} onChange={(html, text) => update({ html, text })} />
              {tooLong ? <p className="text-sm text-destructive">{t('autoReply.tooLong')}</p> : null}
            </div>
            <Button type="submit" disabled={save.isPending || tooLong}>
              {t('common.save')}
            </Button>
          </form>
        ) : null}
      </div>
    </PageBody>
  )
}
