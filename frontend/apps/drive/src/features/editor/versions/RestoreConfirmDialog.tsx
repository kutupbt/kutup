import { useTranslation } from 'react-i18next'
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from '@kutup/ui/components/dialog'
import { Button } from '@kutup/ui/components/button'

export type RestoreChoice = 'save-and-restore' | 'restore-only'

interface Props {
  open: boolean
  onChoose: (choice: RestoreChoice) => void
  onCancel: () => void
}

// Single dialog used by both notes and office restore. Three actions:
// - Save & restore: snapshot the current state as a new version, then
//   apply the chosen old version.
// - Restore only: skip the pre-snapshot — useful when the current state
//   is throwaway / already saved.
// - Cancel: do nothing.
export default function RestoreConfirmDialog({ open, onChoose, onCancel }: Props) {
  const { t } = useTranslation()
  return (
    <Dialog open={open} onOpenChange={(v) => { if (!v) onCancel() }}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>{t('editor.restore.title')}</DialogTitle>
          <DialogDescription>{t('editor.restore.description')}</DialogDescription>
        </DialogHeader>
        <DialogFooter className="flex flex-col-reverse gap-2 sm:flex-row sm:justify-end">
          <Button type="button" variant="ghost" onClick={onCancel}>
            {t('common.cancel')}
          </Button>
          <Button type="button" variant="outline" onClick={() => onChoose('restore-only')}>
            {t('editor.restore.restoreOnly')}
          </Button>
          <Button type="button" onClick={() => onChoose('save-and-restore')}>
            {t('editor.restore.saveAndRestore')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
