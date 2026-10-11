import { useTranslation } from 'react-i18next'
import { Link } from 'react-router-dom'
import { toast } from 'sonner'
import { useDeleteSenderRules, useSetSenderRules } from '@kutup/mail-core/senderRules'
import { Button } from '@kutup/ui/components/button'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@kutup/ui/components/dialog'
import { apiErrorMessage } from '@kutup/ui/lib/apiError'
import { openBlockSender, useBlockSender } from './blockState'

/**
 * Proton's "Block sender" (`BlockSenderModal`): "New emails from … won't be
 * delivered and will be permanently deleted." Blocking can be undone from
 * its toast, or later in Settings.
 */
export function BlockSenderHost() {
  const { t } = useTranslation()
  const addresses = useBlockSender()
  const block = useSetSenderRules()
  const unblock = useDeleteSenderRules()
  if (!addresses) return null
  const close = () => openBlockSender(null)
  const who = addresses.length <= 2 ? addresses.join(', ') : t('senders.count', { count: addresses.length })
  return (
    <Dialog open onOpenChange={(open) => !open && close()}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>{t('senders.blockTitle')}</DialogTitle>
          <DialogDescription className="break-words">
            {t('senders.blockDescription', { who })}{' '}
            <Link to="/settings/senders" className="underline" onClick={close}>
              {t('senders.manage')}
            </Link>
          </DialogDescription>
        </DialogHeader>
        <DialogFooter>
          <Button variant="outline" onClick={close}>
            {t('common.cancel')}
          </Button>
          <Button
            variant="destructive"
            disabled={block.isPending}
            onClick={() => {
              block
                .mutateAsync({ patterns: addresses, kind: 'block' })
                .then((rules) => {
                  toast.success(t('senders.blocked', { who }), {
                    action: { label: t('moved.undo'), onClick: () => void unblock.mutateAsync(rules.map((r) => r.id)).catch(() => undefined) },
                  })
                  close()
                })
                .catch((error: unknown) => toast.error(apiErrorMessage(error, t('common.tryAgain'))))
            }}
          >
            {t('senders.block')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
