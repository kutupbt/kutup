import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useMailSettings } from '@kutup/mail-core/api'
import { Button } from '@kutup/ui/components/button'
import { Checkbox } from '@kutup/ui/components/checkbox'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@kutup/ui/components/dialog'

/** Proton's ComposerInsertImageModal: inline in the text or attached, with "Remove metadata". */
export function ImageInsertDialog({ count, onCancel, onChoose }: { count: number; onCancel: () => void; onChoose: (inline: boolean, strip: boolean) => void }) {
  const { t } = useTranslation()
  // Starts as Settings → General says (Proton's RemoveImageMetadata).
  const settings = useMailSettings()
  const [strip, setStrip] = useState(settings.data?.removeImageMetadata ?? true)
  return (
    <Dialog open onOpenChange={(open) => !open && onCancel()}>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle>{t('images.title', { count })}</DialogTitle>
          <DialogDescription>{t('images.body')}</DialogDescription>
        </DialogHeader>
        <label className="flex items-start gap-2 text-sm">
          <Checkbox className="mt-0.5" checked={strip} onCheckedChange={(on) => setStrip(on === true)} />
          <span>
            <span className="block font-medium">{t('images.removeMetadata')}</span>
            <span className="block text-muted-foreground">{t('images.removeMetadataHint')}</span>
          </span>
        </label>
        <DialogFooter>
          <Button variant="outline" onClick={() => onChoose(false, strip)}>
            {t('images.attachment')}
          </Button>
          <Button onClick={() => onChoose(true, strip)}>{t('images.inline')}</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
