import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Folder, FileText, RotateCcw, Trash2 } from 'lucide-react'
import { MobileShell } from '@/components/mobile/MobileShell'
import { MobilePageHeader } from '@/components/mobile/MobilePageHeader'
import { EmptyState } from '@/components/ui/empty-state'
import { useTrash, type TrashItem } from '@/hooks/useTrash'
import { formatBytes } from '@/lib/format'
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
 * MobileTrashPage — `/drive/trash` mobile layout.
 *
 * Lists the user's trash roots with a Restore pill + a delete-forever button
 * per row; the header's Empty action and per-row permanent deletes confirm
 * first. Data + decryption come from `useTrash()` (same hook as desktop).
 */
export default function MobileTrashPage() {
  const { t } = useTranslation()
  const { items, restore, destroy, emptyAll } = useTrash()
  const [confirmDestroy, setConfirmDestroy] = useState<TrashItem | null>(null)
  const [confirmEmpty, setConfirmEmpty] = useState(false)

  const hasItems = items.length > 0

  return (
    <MobileShell>
      <MobilePageHeader
        title={t('nav.trash', 'Trash')}
        subtitle={t(
          'mobile.trash.subtitle',
          'Items are permanently deleted after 30 days',
        )}
        large
        right={
          hasItems ? (
            <button
              type="button"
              onClick={() => setConfirmEmpty(true)}
              className="bg-transparent border-0 cursor-pointer text-destructive text-sm font-medium px-3 py-2"
            >
              {t('mobile.trash.empty.action', 'Empty')}
            </button>
          ) : null
        }
      />
      <div className="flex-1 overflow-auto px-3.5 pt-3 pb-24">
        {hasItems ? (
          <div role="list" aria-label={t('nav.trash', 'Trash')} className="flex flex-col gap-1">
            {items.map((item) => (
              <div
                key={item.id}
                role="listitem"
                className="flex items-center gap-3 px-2.5 py-2.5 rounded-xl bg-card border border-border"
              >
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
                <button
                  type="button"
                  onClick={() => restore(item.id)}
                  className="inline-flex items-center gap-1 text-xs font-medium text-primary bg-primary/10 rounded-full px-3 py-1.5"
                >
                  <RotateCcw className="h-3.5 w-3.5" />
                  {t('mobile.trash.restore', 'Restore')}
                </button>
                <button
                  type="button"
                  onClick={() => setConfirmDestroy(item)}
                  aria-label={t('trash.deleteForever', 'Delete forever')}
                  className="text-destructive p-1.5"
                >
                  <Trash2 className="h-4 w-4" />
                </button>
              </div>
            ))}
          </div>
        ) : (
          <EmptyState
            icon="trash"
            title={t('mobile.trash.empty.title', 'Trash is empty')}
            subtitle={t(
              'mobile.trash.empty.subtitle',
              'Deleted files appear here for 30 days',
            )}
            tint="muted"
          />
        )}
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
    </MobileShell>
  )
}
