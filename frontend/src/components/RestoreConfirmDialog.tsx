import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from '@/components/ui/dialog'
import { Button } from '@/components/ui/button'

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
  return (
    <Dialog open={open} onOpenChange={(v) => { if (!v) onCancel() }}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>Restore this version?</DialogTitle>
          <DialogDescription>
            Save the current state as a backup version first, or restore directly without backing up.
          </DialogDescription>
        </DialogHeader>
        <DialogFooter className="flex flex-col-reverse gap-2 sm:flex-row sm:justify-end">
          <Button type="button" variant="ghost" onClick={onCancel}>
            Cancel
          </Button>
          <Button type="button" variant="outline" onClick={() => onChoose('restore-only')}>
            Restore only
          </Button>
          <Button type="button" onClick={() => onChoose('save-and-restore')}>
            Save & restore
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
