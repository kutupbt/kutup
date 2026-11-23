import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { useQuery } from '@tanstack/react-query'
import { useCalendarMutation, type Calendar } from '@kutup/calendar-core/api'
import { useDriveIdentity } from '@kutup/drive-core/identity'
import { useMailAccount } from '@kutup/mail-core/api'
import { useRequiredSession } from '@kutup/session/store'
import { Alert } from '@kutup/ui/components/alert'
import { Button } from '@kutup/ui/components/button'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@kutup/ui/components/dialog'
import { apiErrorMessage } from '@kutup/ui/lib/apiError'
import { doubted, keyRecipients, rotateKey, trusted } from './client'
import { RecipientList } from './RecipientList'

/**
 * A key change that is due and wasn't made unasked (someone who gets the new
 * key isn't one the owner trusts yet, or it failed): who gets it, as the
 * pins see them, before the owner confirms (docs/plans/calendar-e3.md, T1).
 */
export function DueRotationDialog({ calendar, onClose, onDone }: { calendar: Calendar; onClose: () => void; onDone: () => void }) {
  const { t } = useTranslation()
  const session = useRequiredSession()
  const me = useDriveIdentity()
  const account = useMailAccount()
  const recipients = useQuery({
    queryKey: ['calendar', 'recipients', calendar.id, 'due'],
    enabled: !!me.data,
    queryFn: () => keyRecipients(me.data!, calendar.id, null),
  })
  const rotate = useCalendarMutation(() => rotateKey(session, me.data!, account.data!, calendar, null, { confirmed: doubted(recipients.data ?? []) }))
  const doubtful = (recipients.data ?? []).some((r) => !trusted(r))
  return (
    <Dialog open onOpenChange={(o) => !o && !rotate.isPending && onClose()}>
      <DialogContent data-testid="due-rotation">
        <DialogHeader>
          <DialogTitle>{t('sharing.due.title', { name: calendar.name })}</DialogTitle>
          <DialogDescription>{t('sharing.due.description')}</DialogDescription>
        </DialogHeader>
        <RecipientList recipients={recipients.data} pending={recipients.isPending} error={recipients.error} />
        {doubtful ? <Alert variant="warn">{t('sharing.due.doubt')}</Alert> : null}
        {rotate.error ? <Alert variant="error">{apiErrorMessage(rotate.error, t('sharing.due.failed'))}</Alert> : null}
        <DialogFooter>
          <Button variant="ghost" onClick={onClose} disabled={rotate.isPending}>
            {t('common.cancel')}
          </Button>
          <Button
            loading={rotate.isPending}
            disabled={!recipients.data || !account.data}
            onClick={() =>
              rotate.mutate(undefined, {
                onSuccess: () => {
                  toast.success(t('sharing.due.done', { name: calendar.name }))
                  onDone()
                },
              })
            }
            data-testid="due-rotation-confirm"
          >
            {t('sharing.due.confirm')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
