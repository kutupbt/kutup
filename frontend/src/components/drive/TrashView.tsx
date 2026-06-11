import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Trash2, Folder, FileText, RotateCcw } from 'lucide-react'
import { useTrash, type TrashItem } from '@/hooks/useTrash'
import { formatBytes } from '@/lib/format'
import { Button } from '@/components/ui/button'
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '@/components/ui/alert-dialog'

/**
 * TrashView — the desktop trash board, rendered inside Drive's Sidebar +
 * DriveTopBar chrome when `viewMode === 'trash'`. Lists the user's trash
 * roots with Restore / Delete-forever per row and an Empty-trash header
 * action; both destructive paths confirm first.
 */
export default function TrashView({ onChanged }: { onChanged?: () => void }) {
  const { t } = useTranslation()
  const { items, isLoading, restore, destroy, emptyAll } = useTrash(onChanged)
  const [confirmDestroy, setConfirmDestroy] = useState<TrashItem | null>(null)
  const [confirmEmpty, setConfirmEmpty] = useState(false)

  if (!isLoading && items.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center h-full text-center py-12">
        <div className="w-16 h-16 rounded-2xl bg-muted text-muted-foreground inline-flex items-center justify-center mb-3">
          <Trash2 className="h-7 w-7" />
        </div>
        <div className="text-base font-semibold text-foreground">
          {t('mobile.trash.empty.title', 'Trash is empty')}
        </div>
        <div className="text-sm text-muted-foreground mt-1 max-w-md">
          {t('mobile.trash.empty.subtitle', 'Deleted files appear here for 30 days')}
        </div>
      </div>
    )
  }

  return (
    <div className="flex flex-col gap-4">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-lg font-semibold">{t('nav.trash', 'Trash')}</h2>
          <p className="text-sm text-muted-foreground">
            {t('mobile.trash.subtitle', 'Items are permanently deleted after 30 days')}
          </p>
        </div>
        <Button size="sm" variant="destructive" onClick={() => setConfirmEmpty(true)}>
          <Trash2 className="h-4 w-4 mr-1.5" />
          {t('trash.emptyTrash', 'Empty trash')}
        </Button>
      </div>

      <div className="border border-border rounded-lg divide-y divide-border bg-card">
        {items.map((item) => (
          <div key={item.id} data-testid="trash-row" className="flex items-center gap-3 px-4 py-3">
            <div className="w-9 h-9 rounded-lg bg-muted text-muted-foreground inline-flex items-center justify-center shrink-0">
              {item.kind === 'folder' ? (
                <Folder className="h-4.5 w-4.5" style={item.color ? { color: item.color } : undefined} />
              ) : (
                <FileText className="h-4.5 w-4.5" />
              )}
            </div>
            <div className="min-w-0 flex-1">
              <div className="text-sm font-medium truncate">{item.name}</div>
              <div className="text-xs text-muted-foreground">
                {item.kind === 'folder'
                  ? t('trash.items', { count: item.items, defaultValue: '{{count}} items' })
                  : formatBytes(item.size)}
                {' · '}
                {t('trash.deletedOn', {
                  date: new Date(item.deletedAt).toLocaleDateString(),
                  defaultValue: 'Deleted {{date}}',
                })}
              </div>
            </div>
            <Button size="sm" variant="outline" onClick={() => restore(item.id)}>
              <RotateCcw className="h-4 w-4 mr-1.5" />
              {t('trash.restore', 'Restore')}
            </Button>
            <Button size="sm" variant="ghost" className="text-destructive" onClick={() => setConfirmDestroy(item)}>
              {t('trash.deleteForever', 'Delete forever')}
            </Button>
          </div>
        ))}
      </div>

      <AlertDialog open={confirmDestroy !== null} onOpenChange={(o) => !o && setConfirmDestroy(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>
              {t('trash.deleteConfirm.title', {
                name: confirmDestroy?.name,
                defaultValue: 'Delete “{{name}}” forever?',
              })}
            </AlertDialogTitle>
            <AlertDialogDescription>
              {t('trash.deleteConfirm.desc', 'This item will be permanently deleted. This cannot be undone.')}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>{t('common.cancel', 'Cancel')}</AlertDialogCancel>
            <AlertDialogAction
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
              onClick={() => {
                if (confirmDestroy) destroy(confirmDestroy.id)
                setConfirmDestroy(null)
              }}
            >
              {t('trash.deleteForever', 'Delete forever')}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      <AlertDialog open={confirmEmpty} onOpenChange={setConfirmEmpty}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{t('trash.emptyConfirm.title', 'Empty trash?')}</AlertDialogTitle>
            <AlertDialogDescription>
              {t(
                'trash.emptyConfirm.desc',
                'All items in the trash will be permanently deleted. This cannot be undone.',
              )}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>{t('common.cancel', 'Cancel')}</AlertDialogCancel>
            <AlertDialogAction
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
              onClick={() => {
                emptyAll()
                setConfirmEmpty(false)
              }}
            >
              {t('trash.emptyTrash', 'Empty trash')}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  )
}
