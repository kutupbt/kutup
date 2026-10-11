import { Copy } from 'lucide-react'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { useUpdateMailSettings } from '@kutup/mail-core/api'
import { Alert } from '@kutup/ui/components/alert'
import { Button } from '@kutup/ui/components/button'
import { Checkbox } from '@kutup/ui/components/checkbox'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@kutup/ui/components/dialog'
import { shownUrl } from './links'

/**
 * Proton's link confirmation (LinkConfirmationModal): where a link really
 * goes, a homograph warning for a punycode host, "Don't ask again"; for a
 * message filed as spam, "suspected fake website" and "I understand the
 * risk" before it opens.
 */
export function LinkConfirm({ href, suspicious, onClose }: { href: string; suspicious: boolean; onClose: () => void }) {
  const { t } = useTranslation()
  const update = useUpdateMailSettings()
  const [dontAsk, setDontAsk] = useState(false)
  const [understood, setUnderstood] = useState(false)
  const url = shownUrl(href)
  const punycode = /:\/\/([^/]*\.)?xn--/i.test(url)

  function confirm() {
    window.open(url, '_blank', 'noopener,noreferrer')
    if (dontAsk && !suspicious) update.mutate({ confirmLink: false })
    onClose()
  }

  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent className="max-w-xl">
        <DialogHeader>
          <DialogTitle>{suspicious ? t('link.suspiciousTitle') : t('link.title')}</DialogTitle>
          <DialogDescription>{suspicious ? t('link.suspiciousBody') : t('link.body')}</DialogDescription>
        </DialogHeader>
        <div className="flex items-start gap-2 rounded-md border border-border bg-muted/40 p-3">
          <code className="min-w-0 flex-1 break-all text-sm" data-testid="link-url">
            {url}
          </code>
          <Button
            variant="ghost"
            size="icon"
            className="size-8 shrink-0"
            aria-label={t('link.copy')}
            onClick={() => void navigator.clipboard.writeText(url).then(() => toast.success(t('link.copied')))}
          >
            <Copy />
          </Button>
        </div>
        {punycode ? <Alert variant="warn">{t('link.punycode')}</Alert> : null}
        {suspicious ? (
          <label className="flex items-center gap-2 text-sm">
            <Checkbox checked={understood} onCheckedChange={(on) => setUnderstood(on === true)} />
            {t('link.understand')}
          </label>
        ) : (
          <label className="flex items-center gap-2 text-sm">
            <Checkbox checked={dontAsk} onCheckedChange={(on) => setDontAsk(on === true)} />
            {t('link.dontAsk')}
          </label>
        )}
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>
            {t('common.cancel')}
          </Button>
          <Button variant={suspicious ? 'destructive' : 'default'} disabled={suspicious && !understood} onClick={confirm} aria-label={t('link.confirmOpen', { url })}>
            {t('link.confirm')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
