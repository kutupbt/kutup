import { AlarmClock } from 'lucide-react'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { membersOf, useSnooze, type MailMessage } from '@kutup/mail-core/api'
import { Button } from '@kutup/ui/components/button'
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuLabel, DropdownMenuSeparator, DropdownMenuTrigger } from '@kutup/ui/components/dropdown-menu'
import { Tooltip } from '@kutup/ui/components/tooltip'
import { apiErrorMessage } from '@kutup/ui/lib/apiError'
import { DateTimeDialog } from './DateTimeDialog'
import { snoozable, snoozeChoices } from './schedule'

/**
 * Proton's Snooze: tomorrow, later this week, this weekend, next week (at
 * 9:00), or a day and time; the conversation leaves the Inbox and comes
 * back unread then.
 */
export function SnoozeButton({ rows, group, onDone }: { rows: MailMessage[]; group?: string; onDone?: () => void }) {
  const { t, i18n } = useTranslation()
  const snooze = useSnooze()
  const [custom, setCustom] = useState(false)
  const choices = snoozeChoices()
  const ids = membersOf(rows)
    .filter((m) => m.folder === 'inbox' || m.folder === 'snoozed')
    .map((m) => m.id)
  const when = (at: Date) => at.toLocaleString(i18n.language, { weekday: 'short', hour: '2-digit', minute: '2-digit' })
  // mutateAsync: the rows leave the list, and this button with them, before it settles.
  const go = (at: Date) =>
    void snooze.mutateAsync({ ids, until: at.toISOString(), group }).then(
      () => {
        toast.success(t('snooze.done', { count: rows.length, date: at.toLocaleString(i18n.language) }))
        onDone?.()
      },
      (error: unknown) => toast.error(apiErrorMessage(error, t('common.tryAgain'))),
    )
  return (
    <>
      <DropdownMenu>
        <Tooltip label={t('snooze.action')}>
          <DropdownMenuTrigger asChild>
            <Button variant="ghost" size="icon" aria-label={t('snooze.action')} disabled={ids.length === 0 || snooze.isPending}>
              <AlarmClock />
            </Button>
          </DropdownMenuTrigger>
        </Tooltip>
        <DropdownMenuContent align="end" className="w-64">
          <DropdownMenuLabel>{t('snooze.title')}</DropdownMenuLabel>
          {choices.map(({ kind, at }) => (
            <DropdownMenuItem key={kind} onSelect={() => go(at)}>
              <span className="flex-1">{t(`snooze.${kind}`)}</span>
              <span className="text-xs text-muted-foreground">{when(at)}</span>
            </DropdownMenuItem>
          ))}
          <DropdownMenuSeparator />
          <DropdownMenuItem onSelect={() => setCustom(true)}>{t('snooze.custom')}</DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>
      {custom ? (
        <DateTimeDialog
          title={t('snooze.customTitle')}
          hint={t('snooze.customHint')}
          initial={choices[0].at}
          valid={(at) => snoozable(at)}
          invalidText={t('snooze.outOfRange')}
          submit={t('snooze.action')}
          onCancel={() => setCustom(false)}
          onChoose={(at) => {
            setCustom(false)
            go(at)
          }}
        />
      ) : null}
    </>
  )
}

/** Proton's Unsnooze: back to the Inbox now. */
export function UnsnoozeButton({ rows, group, onDone }: { rows: MailMessage[]; group?: string; onDone?: () => void }) {
  const { t } = useTranslation()
  const snooze = useSnooze()
  const ids = membersOf(rows)
    .filter((m) => m.folder === 'snoozed')
    .map((m) => m.id)
  return (
    <Button
      variant="ghost"
      size="sm"
      disabled={ids.length === 0 || snooze.isPending}
      onClick={() =>
        void snooze.mutateAsync({ ids, group }).then(
          () => {
            toast.success(t('snooze.undone', { count: rows.length }))
            onDone?.()
          },
          (error: unknown) => toast.error(apiErrorMessage(error, t('common.tryAgain'))),
        )
      }
    >
      <AlarmClock />
      {t('snooze.unsnooze')}
    </Button>
  )
}
