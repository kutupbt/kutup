import { CalendarClock, ChevronDown } from 'lucide-react'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Button } from '@kutup/ui/components/button'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@kutup/ui/components/dialog'
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuLabel, DropdownMenuSeparator, DropdownMenuTrigger } from '@kutup/ui/components/dropdown-menu'
import { Input } from '@kutup/ui/components/input'
import { schedulable, scheduleSuggestions } from './schedule'

const pad = (n: number) => String(n).padStart(2, '0')
const dateValue = (d: Date) => `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`
const timeValue = (d: Date) => `${pad(d.getHours())}:${pad(d.getMinutes())}`

/**
 * Proton's "Schedule send" beside Send: tomorrow morning, Monday morning, or
 * a day and time of the reader's choosing (a minute to 90 days ahead).
 */
export function ScheduleSend({ disabled, onSchedule }: { disabled: boolean; onSchedule: (at: Date) => void }) {
  const { t, i18n } = useTranslation()
  const [custom, setCustom] = useState(false)
  const suggested = scheduleSuggestions()
  const [day, setDay] = useState(() => dateValue(suggested[0].at))
  const [time, setTime] = useState(() => timeValue(suggested[0].at))
  const chosen = new Date(`${day}T${time}`)
  const valid = schedulable(chosen)
  const when = (at: Date) => at.toLocaleString(i18n.language, { weekday: 'long', hour: '2-digit', minute: '2-digit' })
  return (
    <>
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Button size="icon" className="-ml-1.5 rounded-l-none border-l border-primary-foreground/30" disabled={disabled} aria-label={t('schedule.menu')} title={t('schedule.menu')}>
            <ChevronDown />
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="start" className="w-64">
          <DropdownMenuLabel>{t('schedule.menu')}</DropdownMenuLabel>
          {suggested.map(({ kind, at }) => (
            <DropdownMenuItem key={kind} onSelect={() => onSchedule(at)}>
              <CalendarClock />
              <span className="flex-1">{t(`schedule.${kind}`)}</span>
              <span className="text-xs text-muted-foreground">{when(at)}</span>
            </DropdownMenuItem>
          ))}
          <DropdownMenuSeparator />
          <DropdownMenuItem onSelect={() => setCustom(true)}>{t('schedule.custom')}</DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>
      {custom ? (
        <Dialog open onOpenChange={(open) => !open && setCustom(false)}>
          <DialogContent className="max-w-sm">
            <DialogHeader>
              <DialogTitle>{t('schedule.customTitle')}</DialogTitle>
              <DialogDescription>{t('schedule.customHint')}</DialogDescription>
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
            {!valid ? (
              <p role="alert" className="text-sm text-destructive">
                {t('schedule.outOfRange')}
              </p>
            ) : null}
            <DialogFooter>
              <Button variant="outline" onClick={() => setCustom(false)}>
                {t('common.cancel')}
              </Button>
              <Button
                disabled={!valid}
                onClick={() => {
                  setCustom(false)
                  onSchedule(chosen)
                }}
              >
                {t('schedule.schedule')}
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      ) : null}
    </>
  )
}
