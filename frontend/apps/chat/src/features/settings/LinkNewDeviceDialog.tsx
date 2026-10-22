import { useEffect, useState } from 'react'
import { Camera, Link2, Loader2 } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import {
  AlertDialog,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '@kutup/ui/components/alert-dialog'
import { Button } from '@kutup/ui/components/button'
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from '@kutup/ui/components/dialog'
import { Textarea } from '@kutup/ui/components/textarea'
import { useQrScanner } from '@kutup/ui/lib/qrScanner'
import { useChat } from '../../app/chatStore'
import { chatErrorMessage } from '../../lib/errors'
import { useReadReceipts, useTypingIndicators } from '../../state/prefs'

/** What a new device's "Link this device" screen shows. */
const LINK_CODE_PREFIX = 'kutup://link?'

/**
 * Link a new device of this account (Signal's "Link a new device"): scan the
 * QR code its "Link this device" screen shows, or paste its code, confirm
 * (Signal's "Link this device?"), and send it the account's Chat identity. It
 * then finishes on its own.
 */
export function LinkNewDeviceDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (open: boolean) => void }) {
  const { t } = useTranslation()
  const { service } = useChat()
  const readReceipts = useReadReceipts()
  const typingIndicators = useTypingIndicators()
  const [code, setCode] = useState('')
  const [linking, setLinking] = useState(false)
  const [confirming, setConfirming] = useState(false)
  const scanner = useQrScanner(
    LINK_CODE_PREFIX,
    (value) => {
      setCode(value)
      setConfirming(true)
    },
    (failure) => toast.error(t(failure === 'unsupported' ? 'chat.linkNew.scanUnsupported' : 'chat.linkNew.cameraUnavailable')),
  )

  useEffect(() => {
    if (!open) {
      scanner.stop()
      setCode('')
      setConfirming(false)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open])

  const valid = code.trim().startsWith(LINK_CODE_PREFIX)

  async function link() {
    if (!service || !valid || linking) return
    setConfirming(false)
    setLinking(true)
    try {
      const sent = await service.linkDevice(code, { readReceipts, typingIndicators })
      if (sent) {
        toast.success(t('chat.linkNew.sent'))
        onOpenChange(false)
      } else {
        toast.error(t('chat.linkNew.expired'))
      }
    } catch (error) {
      toast.error(chatErrorMessage(error, t))
    } finally {
      setLinking(false)
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-md" data-testid="chat-link-new-dialog">
        <DialogHeader>
          <DialogTitle>{t('chat.linkNew.title')}</DialogTitle>
          <DialogDescription>{t('chat.linkNew.description')}</DialogDescription>
        </DialogHeader>
        <div className="grid gap-3">
          <video
            ref={scanner.videoRef}
            className={scanner.scanning ? 'aspect-square w-full rounded-lg bg-black object-cover' : 'hidden'}
            muted
            playsInline
          />
          <Button type="button" variant="outline" onClick={() => void scanner.start()}>
            <Camera />
            {scanner.scanning ? t('chat.linkNew.scanning') : t('chat.linkNew.scan')}
          </Button>
          <label className="grid gap-2 text-xs font-medium">
            {t('chat.linkNew.pasteLabel')}
            <Textarea
              value={code}
              onChange={(event) => setCode(event.target.value.trim())}
              autoComplete="off"
              spellCheck={false}
              placeholder={`${LINK_CODE_PREFIX}…`}
              className="min-h-20 font-mono text-xs"
              data-testid="chat-link-new-code"
            />
          </label>
          <p className="text-xs text-muted-foreground">{t('chat.linkNew.warning')}</p>
          <Button type="button" disabled={!valid || linking} onClick={() => setConfirming(true)} data-testid="chat-link-new-submit">
            {linking ? <Loader2 className="animate-spin" /> : <Link2 />}
            {t('chat.linkNew.submit')}
          </Button>
        </div>
        <AlertDialog open={confirming && valid} onOpenChange={setConfirming}>
          <AlertDialogContent data-testid="chat-link-new-confirm-dialog">
            <AlertDialogHeader>
              <AlertDialogTitle>{t('chat.linkNew.confirmTitle')}</AlertDialogTitle>
              <AlertDialogDescription>{t('chat.linkNew.confirmBody')}</AlertDialogDescription>
            </AlertDialogHeader>
            <AlertDialogFooter>
              <AlertDialogCancel>{t('common.cancel')}</AlertDialogCancel>
              <Button onClick={() => void link()} data-testid="chat-link-new-confirm">
                {t('chat.linkNew.confirm')}
              </Button>
            </AlertDialogFooter>
          </AlertDialogContent>
        </AlertDialog>
      </DialogContent>
    </Dialog>
  )
}
