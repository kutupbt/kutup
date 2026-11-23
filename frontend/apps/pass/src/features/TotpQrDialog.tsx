import { QRCodeSVG } from 'qrcode.react'
import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Alert } from '@kutup/ui/components/alert'
import { Button } from '@kutup/ui/components/button'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@kutup/ui/components/dialog'

/**
 * The one-time code's setup as a QR code, to add it to another
 * authenticator (KeePassXC's "Export settings"): shown only after a warning,
 * since anyone who sees it can make the codes.
 */
export function TotpQrDialog({ uri, open, onOpenChange }: { uri: string; open: boolean; onOpenChange: (open: boolean) => void }) {
  const { t } = useTranslation()
  const [shown, setShown] = useState(false)
  useEffect(() => {
    if (!open) setShown(false)
  }, [open])
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{t('totp.qrTitle')}</DialogTitle>
          <DialogDescription>{t('totp.qrDescription')}</DialogDescription>
        </DialogHeader>
        {shown ? (
          <div className="mt-4 flex justify-center rounded-md bg-white p-4">
            <QRCodeSVG value={uri} size={224} marginSize={2} title={t('totp.qrTitle')} />
          </div>
        ) : (
          <Alert variant="warn" className="mt-4">
            {t('totp.qrWarning')}
          </Alert>
        )}
        <DialogFooter>
          <Button type="button" variant="outline" onClick={() => onOpenChange(false)}>
            {t('common.close')}
          </Button>
          {!shown ? (
            <Button type="button" onClick={() => setShown(true)}>
              {t('totp.qrShow')}
            </Button>
          ) : null}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
