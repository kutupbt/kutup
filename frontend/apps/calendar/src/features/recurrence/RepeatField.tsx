import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { addDays, weekday, type CivilDate } from '@kutup/calendar-core/time'
import { Button } from '@kutup/ui/components/button'
import { Checkbox } from '@kutup/ui/components/checkbox'
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle } from '@kutup/ui/components/dialog'
import { Input } from '@kutup/ui/components/input'
import { Label } from '@kutup/ui/components/label'
import { Choice } from '../Choice'
import { formatWeekday } from '../format'
import {
  MAX_INTERVAL,
  frequencyOf,
  monthlyTypes,
  isWorkday,
  pickPreset,
  positiveSetPos,
  presetOf,
  workWeek,
  type Frequency,
  type FrequencyModel,
  type MonthlyType,
} from './frequency'

/** A date of the week holding 2026-11-01 (a Sunday) for weekday `day` (0 Sunday): names only. */
function dayDate(day: number): CivilDate {
  return addDays('2026-11-01', day)
}

/** Proton's monthly option texts (`getOnDayString`): on day 15, on the second Tuesday, on the last Tuesday. */
function useMonthlyText() {
  const { t, i18n } = useTranslation()
  return (type: MonthlyType, start: CivilDate) => {
    const day = formatWeekday(start, i18n.language, 'long')
    if (type === 'onMonthDay') return t('recurrence.onMonthDay', { day: Number(start.slice(8, 10)) })
    if (type === 'onLastDay') return t('recurrence.onLastDay', { day })
    const nth = [t('recurrence.nth.1'), t('recurrence.nth.2'), t('recurrence.nth.3'), t('recurrence.nth.4')][positiveSetPos(start) - 1]
    return t('recurrence.onNthDay', { nth, day })
  }
}

/**
 * The editor's Repeat field (Proton's `FrequencyInput`): does not repeat,
 * every day, every weekday, every week on the start's day, every month (on
 * the day or its weekday), every year, or custom (`CustomFrequencyModal`).
 */
export function RepeatField({
  model,
  start,
  weekStart,
  maxCount,
  disabled,
  onChange,
}: {
  model: FrequencyModel
  start: CivilDate
  weekStart: number
  maxCount: number
  disabled?: boolean
  onChange: (model: FrequencyModel) => void
}) {
  const { t, i18n } = useTranslation()
  const monthlyText = useMonthlyText()
  const [customOpen, setCustomOpen] = useState(false)
  const selected = presetOf(model, start, weekStart)
  const days = workWeek(weekStart)
  const options: { value: string; label: string }[] = [
    { value: 'once', label: t('recurrence.once') },
    { value: 'daily', label: t('recurrence.daily') },
    ...(isWorkday(start, weekStart)
      ? [
          {
            value: 'workdays',
            label: t('recurrence.workdays', {
              first: formatWeekday(dayDate(days[0]), i18n.language, 'long'),
              last: formatWeekday(dayDate(days[4]), i18n.language, 'long'),
            }),
          },
        ]
      : []),
    { value: 'weekly', label: t('recurrence.weekly', { day: formatWeekday(start, i18n.language, 'long') }) },
    ...monthlyTypes(start).map((type) => ({ value: `monthly:${type}`, label: t('recurrence.monthly', { on: monthlyText(type, start) }) })),
    { value: 'yearly', label: t('recurrence.yearly') },
    ...(model.type === 'other' ? [{ value: 'other', label: t('recurrence.other') }] : []),
    { value: 'custom', label: selected === 'custom' ? t('recurrence.customShown') : t('recurrence.custom') },
  ]
  return (
    <div className="flex items-center gap-2">
      <div className="min-w-0 flex-1">
        <Choice
          id="event-repeat"
          value={selected}
          options={options}
          disabled={disabled}
          testId="event-repeat"
          onChange={(value) => {
            if (value === 'custom') setCustomOpen(true)
            else if (value !== 'other') onChange(pickPreset(model, value as ReturnType<typeof presetOf>, start, weekStart))
          }}
        />
      </div>
      {selected === 'custom' && !disabled ? (
        <Button type="button" variant="ghost" size="sm" onClick={() => setCustomOpen(true)} data-testid="event-repeat-edit">
          {t('recurrence.editCustom')}
        </Button>
      ) : null}
      <CustomRepeatDialog
        open={customOpen}
        model={model}
        start={start}
        weekStart={weekStart}
        maxCount={maxCount}
        onClose={() => setCustomOpen(false)}
        onDone={(next) => {
          setCustomOpen(false)
          onChange(next)
        }}
      />
    </div>
  )
}

/** A whole number typed in a field, within `[min, max]`, or null while it isn't one. */
function wholeNumber(text: string, min: number, max: number): number | null {
  if (!/^\d+$/.test(text)) return null
  const value = Number(text)
  return value >= min && value <= max ? value : null
}

/**
 * Proton's `CustomFrequencyModal`: repeat every N days, weeks (on chosen
 * weekdays), months (on the day or its weekday) or years; ending never, on a
 * date, or after N events.
 */
function CustomRepeatDialog({
  open,
  model,
  start,
  weekStart,
  maxCount,
  onClose,
  onDone,
}: {
  open: boolean
  model: FrequencyModel
  start: CivilDate
  weekStart: number
  maxCount: number
  onClose: () => void
  onDone: (model: FrequencyModel) => void
}) {
  const { t, i18n } = useTranslation()
  const monthlyText = useMonthlyText()
  const initial = (): FrequencyModel => ({
    ...model,
    type: 'custom',
    // "Does not repeat" opens as weekly (Proton's).
    frequency: model.type === 'once' || model.type === 'other' ? 'weekly' : frequencyOf(model),
    text: null,
  })
  const [values, setValues] = useState<FrequencyModel>(initial)
  const [interval, setIntervalText] = useState(String(model.interval))
  const [count, setCount] = useState(String(model.ends.count))
  useEffect(() => {
    if (!open) return
    const next = initial()
    setValues(next)
    setIntervalText(String(next.interval))
    setCount(String(next.ends.count))
    // eslint-disable-next-line react-hooks/exhaustive-deps -- once per opening
  }, [open])
  const frequency = values.frequency
  const intervalValue = wholeNumber(interval, 1, MAX_INTERVAL[frequency])
  const countValue = wholeNumber(count, 1, maxCount)
  const valid =
    intervalValue !== null &&
    (values.ends.type !== 'count' || countValue !== null) &&
    (values.ends.type !== 'until' || (values.ends.until !== null && values.ends.until >= start))
  const plural = intervalValue ?? 1
  const units: { value: Frequency; label: string }[] = [
    { value: 'daily', label: t('recurrence.unit.day', { count: plural }) },
    { value: 'weekly', label: t('recurrence.unit.week', { count: plural }) },
    { value: 'monthly', label: t('recurrence.unit.month', { count: plural }) },
    { value: 'yearly', label: t('recurrence.unit.year', { count: plural }) },
  ]
  const startDay = weekday(start)
  const weekDays = Array.from({ length: 7 }, (_, i) => (weekStart + i) % 7)
  const setEnds = (change: Partial<FrequencyModel['ends']>) => setValues((v) => ({ ...v, ends: { ...v.ends, ...change } }))
  return (
    <Dialog open={open} onOpenChange={(next) => !next && onClose()}>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle>{t('recurrence.customTitle')}</DialogTitle>
        </DialogHeader>
        <div className="mt-2 space-y-4">
          <div className="flex items-center gap-2">
            <Label htmlFor="repeat-interval" className="shrink-0">
              {t('recurrence.every')}
            </Label>
            <Input
              id="repeat-interval"
              inputMode="numeric"
              className="w-20"
              value={interval}
              onChange={(e) => setIntervalText(e.target.value.trim())}
              aria-invalid={intervalValue === null}
              data-testid="repeat-interval"
            />
            <div className="min-w-0 flex-1">
              <Choice
                id="repeat-frequency"
                value={frequency}
                options={units}
                label={t('recurrence.frequency')}
                testId="repeat-frequency"
                onChange={(value) => {
                  const next = value as Frequency
                  // Proton's: the interval capped to the new frequency's largest.
                  if (intervalValue !== null && intervalValue > MAX_INTERVAL[next]) setIntervalText(String(MAX_INTERVAL[next]))
                  setValues((v) => ({ ...v, frequency: next }))
                }}
              />
            </div>
          </div>
          {frequency === 'weekly' ? (
            <fieldset className="space-y-1.5">
              <legend className="text-sm font-medium">{t('recurrence.repeatOn')}</legend>
              <div className="flex flex-wrap gap-3">
                {weekDays.map((day) => (
                  <label key={day} className="flex items-center gap-1.5 text-sm">
                    <Checkbox
                      checked={values.weeklyDays.includes(day)}
                      // The start's day always repeats (Proton's: the series starts on it).
                      disabled={day === startDay}
                      onCheckedChange={(checked) =>
                        setValues((v) => ({ ...v, weeklyDays: checked === true ? [...new Set([...v.weeklyDays, day])] : v.weeklyDays.filter((d) => d !== day) }))
                      }
                      data-testid={`repeat-day-${day}`}
                    />
                    {formatWeekday(dayDate(day), i18n.language, 'short')}
                  </label>
                ))}
              </div>
            </fieldset>
          ) : null}
          {frequency === 'monthly' ? (
            <div className="space-y-1.5" role="radiogroup" aria-label={t('recurrence.frequency')}>
              {monthlyTypes(start).map((type) => (
                <label key={type} className="flex items-center gap-2 text-sm">
                  <input
                    type="radio"
                    name="repeat-monthly"
                    checked={values.monthly === type}
                    onChange={() => setValues((v) => ({ ...v, monthly: type }))}
                    data-testid={`repeat-monthly-${type}`}
                  />
                  {monthlyText(type, start)}
                </label>
              ))}
            </div>
          ) : null}
          <fieldset className="space-y-2">
            <legend className="text-sm font-medium">{t('recurrence.ends')}</legend>
            <label className="flex items-center gap-2 text-sm">
              <input type="radio" name="repeat-ends" checked={values.ends.type === 'never'} onChange={() => setEnds({ type: 'never' })} data-testid="repeat-ends-never" />
              {t('recurrence.never')}
            </label>
            <div className="flex items-center gap-2 text-sm">
              <input
                type="radio"
                id="repeat-ends-until"
                name="repeat-ends"
                checked={values.ends.type === 'until'}
                onChange={() => setEnds({ type: 'until', until: values.ends.until ?? start })}
                data-testid="repeat-ends-until"
              />
              <label htmlFor="repeat-ends-until" className="w-28 shrink-0">
                {t('recurrence.endsOn')}
              </label>
              <Input
                type="date"
                className="w-44"
                min={start}
                max="2037-12-31"
                value={values.ends.until ?? ''}
                disabled={values.ends.type !== 'until'}
                aria-label={t('recurrence.endsOn')}
                onChange={(e) => e.target.value && setEnds({ until: e.target.value })}
                data-testid="repeat-until"
              />
            </div>
            <div className="flex items-center gap-2 text-sm">
              <input type="radio" id="repeat-ends-count" name="repeat-ends" checked={values.ends.type === 'count'} onChange={() => setEnds({ type: 'count' })} data-testid="repeat-ends-count" />
              <label htmlFor="repeat-ends-count" className="w-28 shrink-0">
                {t('recurrence.endsAfter')}
              </label>
              <Input
                inputMode="numeric"
                className="w-20"
                value={count}
                disabled={values.ends.type !== 'count'}
                aria-label={t('recurrence.endsAfter')}
                aria-invalid={values.ends.type === 'count' && countValue === null}
                onChange={(e) => setCount(e.target.value.trim())}
                data-testid="repeat-count"
              />
              <span className="text-muted-foreground">{t('recurrence.events', { count: countValue ?? 1 })}</span>
            </div>
            {values.ends.type === 'count' && countValue === null ? (
              <p className="text-xs text-destructive" role="alert">
                {t('recurrence.countRange', { max: maxCount })}
              </p>
            ) : null}
          </fieldset>
        </div>
        <DialogFooter>
          <Button type="button" variant="ghost" onClick={onClose}>
            {t('common.cancel')}
          </Button>
          <Button
            type="button"
            disabled={!valid}
            onClick={() =>
              onDone({
                ...values,
                type: 'custom',
                interval: intervalValue ?? 1,
                weeklyDays: [...new Set([startDay, ...values.weeklyDays])],
                ends: { ...values.ends, count: countValue ?? values.ends.count },
              })
            }
            data-testid="repeat-done"
          >
            {t('recurrence.done')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
