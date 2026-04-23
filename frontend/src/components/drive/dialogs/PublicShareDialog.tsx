import { useTranslation } from 'react-i18next'
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from '@/components/ui/dialog'
import { Button } from '@/components/ui/button'
import { Copy, Check } from 'lucide-react'
import { useState } from 'react'
import { copyText } from '@/lib/format'

interface Props {
  url: string | null
  onOpenChange: (open: boolean) => void
  title?: string
  description?: string
}

export default function PublicShareDialog({ url, onOpenChange, title = 'Link ready', description }: Props) {
  const { t } = useTranslation()
  const [copied, setCopied] = useState(false)

  async function handleCopy() {
    if (!url) return
    await copyText(url)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  return (
    <Dialog open={url !== null} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>{title}</DialogTitle>
        </DialogHeader>
        {description && (
          <p className="text-sm text-muted-foreground">{description}</p>
        )}
        {url && (
          <div className="bg-muted rounded-lg p-3 font-mono text-xs break-all text-primary">
            {url}
          </div>
        )}
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            {t('dialogs.publicShare.close')}
          </Button>
          <Button onClick={handleCopy}>
            {copied ? (
              <>
                <Check className="h-4 w-4 mr-2" />
                {t('dialogs.publicShare.copied')}
              </>
            ) : (
              <>
                <Copy className="h-4 w-4 mr-2" />
                {t('dialogs.publicShare.copyLink')}
              </>
            )}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
