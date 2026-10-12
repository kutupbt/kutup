import { Bell, Check } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { usePinnedKeys, useSendReceipt, type MailAccount, type MailMessage } from '@kutup/mail-core/api'
import type { ParsedMessage } from '@kutup/mail-core/mime'
import { Button } from '@kutup/ui/components/button'
import { Tooltip } from '@kutup/ui/components/tooltip'
import { apiErrorMessage } from '@kutup/ui/lib/apiError'

/**
 * Proton's ExtraReadReceipt: a received message asking for a read receipt
 * offers to send one; once sent, it says so. Never sent on its own.
 */
export function ReadReceipt({ account, message, parsed }: { account: MailAccount; message: MailMessage; parsed: ParsedMessage }) {
  const { t, i18n } = useTranslation()
  const pinned = usePinnedKeys()
  const send = useSendReceipt()
  if (!parsed.receiptTo || message.direction !== 'inbound') return null
  if (message.receiptSent) {
    return (
      <p className="flex items-center gap-2 text-sm text-status-ok">
        <Check className="size-4" aria-hidden />
        {t('readReceipt.sent')}
      </p>
    )
  }
  const subject = parsed.subject || message.subject
  const sentOn = parsed.date ?? new Date(message.receivedAt)
  return (
    <div>
      <Tooltip label={t('readReceipt.asked')}>
        <Button
          variant="outline"
          size="sm"
          disabled={send.isPending}
          onClick={() =>
            send.mutate(
              {
                account,
                message,
                parsed,
                pinned: pinned ?? (() => undefined),
                subject: t('readReceipt.subject', { subject }),
                text: t('readReceipt.body', { subject, sent: sentOn.toLocaleString(i18n.language), read: new Date().toLocaleString(i18n.language) }),
              },
              {
                onSuccess: () => toast.success(t('readReceipt.sent')),
                onError: (error) => toast.error(apiErrorMessage(error, t('readReceipt.failed'))),
              },
            )
          }
        >
          <Bell />
          {t('readReceipt.send')}
        </Button>
      </Tooltip>
    </div>
  )
}
