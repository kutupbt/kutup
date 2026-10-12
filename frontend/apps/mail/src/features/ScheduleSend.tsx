import { CalendarClock, ChevronDown } from 'lucide-react'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Button } from '@kutup/ui/components/button'
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuLabel, DropdownMenuSeparator, DropdownMenuTrigger } from '@kutup/ui/components/dropdown-menu'
import { DateTimeDialog } from './DateTimeDialog'
import { schedulable, scheduleSuggestions } from './schedule'


/**
 * Proton's "Schedule send" beside Send: tomorrow morning, Monday morning, or
 * a day and time of the reader's choosing (a minute to 90 days ahead).
 */
export function ScheduleSend({ disabled, onSchedule }: { disabled: boolean; onSchedule: (at: Date) => void }) {
  const { t, i18n } = useTranslation()
  const [custom, setCustom] = useState(false)
  const suggested = scheduleSuggestions()
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
        <DateTimeDialog
          title={t('schedule.customTitle')}
          hint={t('schedule.customHint')}
          initial={suggested[0].at}
          valid={(at) => schedulable(at)}
          invalidText={t('schedule.outOfRange')}
          submit={t('schedule.schedule')}
          onCancel={() => setCustom(false)}
          onChoose={(at) => {
            setCustom(false)
            onSchedule(at)
          }}
        />
      ) : null}
    </>
  )
}
