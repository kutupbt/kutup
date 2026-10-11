import { MailMinus } from 'lucide-react'
import { useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { emptyDraft, sendDraft, useMailRefresh, usePinnedKeys, useUnsubscribe, type MailAccount, type MailMessage } from '@kutup/mail-core/api'
import { unsubscribeMethods } from '@kutup/mail-core/unsubscribe'
import { Button } from '@kutup/ui/components/button'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@kutup/ui/components/dialog'
import { apiErrorMessage } from '@kutup/ui/lib/apiError'

/**
 * Proton's unsubscribe banner (ExtraUnsubscribe), for mail from a list that
 * names its ways out: one click, sent by the server so the list never sees
 * the reader; a web page the list explains it on; or an email from the
 * reader's address. Once done, the message says "Unsubscribed".
 */
export function UnsubscribeBanner({ account, message, raw, group }: { account: MailAccount; message: MailMessage; raw: Uint8Array; group?: string }) {
  const { t } = useTranslation()
  const methods = useMemo(() => unsubscribeMethods(raw), [raw])
  const unsubscribe = useUnsubscribe(group)
  const pinned = usePinnedKeys()
  const refresh = useMailRefresh()
  const [asking, setAsking] = useState(false)
  const [sending, setSending] = useState(false)
  if (!methods || message.direction !== 'inbound') return null
  const done = message.unsubscribed === true

  async function confirm() {
    if (!methods) return
    setSending(true)
    try {
      if (methods.oneClick) {
        await unsubscribe.mutateAsync({ id: message.id, oneClickUrl: methods.oneClick })
        toast.success(t('unsubscribe.requestSent'))
      } else if (methods.http) {
        window.open(methods.http, '_blank', 'noopener,noreferrer')
        await unsubscribe.mutateAsync({ id: message.id })
        toast.success(t('unsubscribe.done'))
      } else if (methods.mailto) {
        const draft = emptyDraft(account, { to: [{ address: methods.mailto.to, name: '' }], subject: methods.mailto.subject, text: methods.mailto.body, html: `<p>${methods.mailto.body.replace(/[&<>]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' })[c]!)}</p>` })
        await sendDraft(account, draft, [], pinned ?? (() => undefined))
        await unsubscribe.mutateAsync({ id: message.id })
        refresh()
        toast.success(t('unsubscribe.done'))
      }
      setAsking(false)
    } catch (error) {
      toast.error(apiErrorMessage(error, t('unsubscribe.failed')))
    } finally {
      setSending(false)
    }
  }

  return (
    <>
      <div className="flex flex-wrap items-center gap-2 rounded-md border border-border bg-muted/50 px-3 py-2 text-sm">
        <MailMinus className="size-4 text-muted-foreground" aria-hidden />
        <span className="flex-1">{t('unsubscribe.fromList')}</span>
        <Button variant="outline" size="sm" disabled={done} onClick={() => setAsking(true)}>
          {done ? t('unsubscribe.unsubscribed') : t('unsubscribe.action')}
        </Button>
      </div>
      {asking ? (
        <Dialog open onOpenChange={(open) => !open && setAsking(false)}>
          <DialogContent className="max-w-lg">
            <DialogHeader>
              <DialogTitle>{t('unsubscribe.title')}</DialogTitle>
              <DialogDescription>
                {methods.oneClick ? t('unsubscribe.oneClick') : methods.http ? t('unsubscribe.http') : t('unsubscribe.mailto', { address: account.address })}
              </DialogDescription>
            </DialogHeader>
            {!methods.oneClick && methods.http ? <code className="block break-all rounded-md border border-border bg-muted/40 p-3 text-sm">{methods.http}</code> : null}
            {!methods.oneClick && !methods.http && methods.mailto ? (
              <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 rounded-md border border-border bg-muted/40 p-3 text-sm">
                <dt className="text-muted-foreground">{t('unsubscribe.recipient')}</dt>
                <dd className="break-all">{methods.mailto.to}</dd>
                <dt className="text-muted-foreground">{t('unsubscribe.subject')}</dt>
                <dd className="break-all">{methods.mailto.subject}</dd>
                <dt className="text-muted-foreground">{t('unsubscribe.body')}</dt>
                <dd className="break-all">{methods.mailto.body}</dd>
              </dl>
            ) : null}
            <DialogFooter>
              <Button variant="outline" onClick={() => setAsking(false)}>
                {t('common.cancel')}
              </Button>
              <Button onClick={() => void confirm()} disabled={sending}>
                {t('unsubscribe.action')}
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      ) : null}
    </>
  )
}
