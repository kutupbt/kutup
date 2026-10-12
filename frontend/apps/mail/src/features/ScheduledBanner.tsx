import { CalendarClock } from 'lucide-react'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { cancelSend, useMailRefresh, type MailMessage, type OpenedMessage } from '@kutup/mail-core/api'
import { Button } from '@kutup/ui/components/button'
import { formatInstant } from '@kutup/ui/lib/format'
import { openComposer } from './composerState'

/**
 * Proton's scheduled message banner: when it goes, and Edit, which takes
 * the send back (to Drafts) and opens the draft.
 */
export function ScheduledBanner({ message, opened }: { message: MailMessage; opened: OpenedMessage }) {
  const { t, i18n } = useTranslation()
  const refresh = useMailRefresh()
  const [busy, setBusy] = useState(false)
  return (
    <div className="flex w-full flex-wrap items-center gap-2 rounded-md border border-border bg-muted/50 px-3 py-2 text-sm">
      <CalendarClock className="size-4 text-muted-foreground" aria-hidden />
      <span className="flex-1">{t('schedule.willSend', { date: formatInstant(message.scheduledAt ?? '', i18n.language) ?? '' })}</span>
      <Button
        size="sm"
        variant="outline"
        disabled={busy}
        onClick={() => {
          setBusy(true)
          void cancelSend(message.outboxId!)
            .then((taken) => {
              if (!taken) {
                toast.info(t('compose.alreadySent'))
                return
              }
              refresh()
              openComposer({ kind: 'draft', message: { ...message, folder: 'drafts', scheduledAt: null, outboxId: null }, opened })
            })
            .catch(() => toast.error(t('common.tryAgain')))
            .finally(() => setBusy(false))
        }}
      >
        {t('schedule.edit')}
      </Button>
    </div>
  )
}
