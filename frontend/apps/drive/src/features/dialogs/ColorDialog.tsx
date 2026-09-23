import { Check } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { Alert } from '@kutup/ui/components/alert'
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from '@kutup/ui/components/dialog'
import { apiErrorMessage } from '@kutup/ui/lib/apiError'
import { cn } from '@kutup/ui/lib/cn'
import { FOLDER_COLORS } from '../drive/colors'
import type { Folder } from '../drive/model'
import { useSetFolderColor } from '../drive/mutations'

export function ColorDialog({ folder, onClose }: { folder: Folder | null; onClose: () => void }) {
  const { t } = useTranslation()
  const setColor = useSetFolderColor()
  const choose = (color: string | null) =>
    folder && setColor.mutate({ folder, color }, { onSuccess: onClose })
  return (
    <Dialog open={folder !== null} onOpenChange={(o) => !o && (setColor.reset(), onClose())}>
      <DialogContent className="max-w-sm">
        <DialogHeader>
          <DialogTitle>{t('dialogs.color.title')}</DialogTitle>
          <DialogDescription>{folder?.name}</DialogDescription>
        </DialogHeader>
        <div className="flex flex-wrap gap-2" role="radiogroup" aria-label={t('dialogs.color.title')}>
          <button
            type="button"
            role="radio"
            aria-checked={!folder?.color}
            onClick={() => choose(null)}
            className={cn('h-10 rounded-full border border-border px-4 text-sm hover:bg-accent', !folder?.color && 'border-primary bg-accent')}
          >
            {t('dialogs.color.default')}
          </button>
          {FOLDER_COLORS.map((c) => (
            <button
              key={c.value}
              type="button"
              role="radio"
              aria-checked={folder?.color === c.value}
              aria-label={t(`dialogs.color.${c.name}`)}
              onClick={() => choose(c.value)}
              style={{ backgroundColor: c.hex }}
              className="flex size-10 items-center justify-center rounded-full text-white ring-offset-2 ring-offset-background focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
            >
              {folder?.color === c.value ? <Check className="size-4" /> : null}
            </button>
          ))}
        </div>
        {setColor.isError ? <Alert variant="error">{apiErrorMessage(setColor.error, t('dialogs.color.failed'))}</Alert> : null}
      </DialogContent>
    </Dialog>
  )
}
