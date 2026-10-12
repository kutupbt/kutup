import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Button } from '@kutup/ui/components/button'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@kutup/ui/components/dialog'
import { Input } from '@kutup/ui/components/input'

const pad = (n: number) => String(n).padStart(2, '0')
const dateValue = (d: Date) => `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`
const timeValue = (d: Date) => `${pad(d.getHours())}:${pad(d.getMinutes())}`

/** A day and a time, local, checked by `valid` (scheduled send's and snooze's custom choice). */
export function DateTimeDialog({
  title,
  hint,
  initial,
  valid,
  invalidText,
  submit,
  onCancel,
  onChoose,
}: {
  title: string
  hint: string
  initial: Date
  valid: (at: Date) => boolean
  invalidText: string
  submit: string
  onCancel: () => void
  onChoose: (at: Date) => void
}) {
  const { t } = useTranslation()
  const [day, setDay] = useState(() => dateValue(initial))
  const [time, setTime] = useState(() => timeValue(initial))
  const chosen = new Date(`${day}T${time}`)
  const ok = valid(chosen)
  return (
    <Dialog open onOpenChange={(open) => !open && onCancel()}>
      <DialogContent className="max-w-sm">
        <DialogHeader>
          <DialogTitle>{title}</DialogTitle>
          <DialogDescription>{hint}</DialogDescription>
        </DialogHeader>
        <div className="grid grid-cols-2 gap-3">
          <label className="space-y-1 text-sm">
            <span className="block font-medium">{t('schedule.date')}</span>
            <Input type="date" value={day} onChange={(e) => setDay(e.target.value)} />
          </label>
          <label className="space-y-1 text-sm">
            <span className="block font-medium">{t('schedule.time')}</span>
            <Input type="time" value={time} onChange={(e) => setTime(e.target.value)} />
          </label>
        </div>
        {!ok ? (
          <p role="alert" className="text-sm text-destructive">
            {invalidText}
          </p>
        ) : null}
        <DialogFooter>
          <Button variant="outline" onClick={onCancel}>
            {t('common.cancel')}
          </Button>
          <Button disabled={!ok} onClick={() => onChoose(chosen)}>
            {submit}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
