import { Copy } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { Alert } from '@kutup/ui/components/alert'
import { Button } from '@kutup/ui/components/button'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@kutup/ui/components/dialog'
import { Input } from '@kutup/ui/components/input'
import { copyText } from '@kutup/ui/lib/clipboard'

/** Show a secret link once (a public link, a federated invite) with copy. */
export function LinkDialog({
  link,
  title,
  description,
  warning,
  onClose,
}: {
  link: string | null
  title: string
  description: string
  warning: string
  onClose: () => void
}) {
  const { t } = useTranslation()
  return (
    <Dialog open={link !== null} onOpenChange={(o) => !o && onClose()}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{title}</DialogTitle>
          <DialogDescription>{description}</DialogDescription>
        </DialogHeader>
        <div className="flex gap-2">
          <Input value={link ?? ''} readOnly className="font-mono text-xs" onFocus={(e) => e.currentTarget.select()} aria-label={title} />
          <Button
            variant="outline"
            onClick={() => link && void copyText(link).then(() => toast.success(t('common.copied')))}
          >
            <Copy />
            {t('common.copy')}
          </Button>
        </div>
        <Alert variant="warn">{warning}</Alert>
        <DialogFooter>
          <Button onClick={onClose}>{t('common.close')}</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
