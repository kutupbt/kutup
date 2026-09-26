import { Download, Share2, Trash2, X } from 'lucide-react'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { shareRole } from '@kutup/drive-core/fileShares'
import { useTrashFile } from '@kutup/drive-core/mutations'
import { FileShareDialog, type FileShareTarget } from '@kutup/drive-ui/FileShareDialog'
import { useRequiredSession } from '@kutup/session/store'
import { Button } from '@kutup/ui/components/button'
import { ConfirmDestructive } from '@kutup/ui/components/confirm-destructive'
import type { Photo } from '../library/library'
import { downloadPhoto, downloadPhotosZip, FsaRequiredError } from './downloads'
import { mayTrash } from './mayTrash'

/** What to do with the selected photos: download, share one, move to trash. */
export function SelectionBar({ photos, onClear }: { photos: Photo[]; onClear: () => void }) {
  const { t } = useTranslation()
  const session = useRequiredSession()
  const trash = useTrashFile()
  const [confirming, setConfirming] = useState(false)
  const [sharing, setSharing] = useState<FileShareTarget | null>(null)
  const [downloading, setDownloading] = useState(false)
  const trashable = photos.filter((p) => mayTrash(p, session.userId))
  const only = photos.length === 1 ? photos[0] : null
  const role = only ? shareRole(only.folder, only.file) : null

  async function download() {
    setDownloading(true)
    try {
      if (only) await downloadPhoto(only)
      else {
        const id = toast.loading(t('selection.zipping', { done: 0, count: photos.length }))
        try {
          await downloadPhotosZip(photos, t('selection.archiveName'), (done, total) =>
            toast.loading(t('selection.zipping', { done, count: total }), { id }),
          )
          toast.dismiss(id)
        } catch (error) {
          toast.dismiss(id)
          throw error
        }
      }
    } catch (error) {
      if (error instanceof DOMException && error.name === 'AbortError') return
      toast.error(error instanceof FsaRequiredError ? t('selection.tooLargeForBrowser') : t('selection.downloadFailed'))
    } finally {
      setDownloading(false)
    }
  }

  async function moveToTrash() {
    let failed = 0
    for (const photo of trashable) {
      try {
        await trash.mutateAsync({ folder: photo.folder, file: photo.file })
      } catch {
        failed++
      }
    }
    setConfirming(false)
    onClear()
    if (failed > 0) toast.error(t('selection.trashFailed', { count: failed }))
    else toast.success(t('selection.trashed', { count: trashable.length }))
  }

  return (
    <div className="sticky top-14 z-20 flex items-center gap-2 border-b border-border bg-background/95 px-3 py-2 backdrop-blur-sm md:px-8">
      <Button variant="ghost" size="icon" aria-label={t('selection.clear')} onClick={onClear}>
        <X />
      </Button>
      <p className="min-w-0 flex-1 truncate text-sm font-medium">{t('selection.count', { count: photos.length })}</p>
      <Button variant="outline" size="sm" disabled={downloading} onClick={() => void download()}>
        <Download /> <span className="hidden sm:inline">{t('selection.download')}</span>
      </Button>
      {only && role ? (
        <Button variant="outline" size="sm" onClick={() => setSharing({ folder: only.folder, file: only.file, role })}>
          <Share2 /> <span className="hidden sm:inline">{t('selection.share')}</span>
        </Button>
      ) : null}
      {trashable.length > 0 ? (
        <Button variant="outline" size="sm" onClick={() => setConfirming(true)}>
          <Trash2 /> <span className="hidden sm:inline">{t('selection.trash')}</span>
        </Button>
      ) : null}
      <ConfirmDestructive
        open={confirming}
        onOpenChange={setConfirming}
        title={t('selection.trashTitle', { count: trashable.length })}
        description={t('selection.trashDescription', { count: trashable.length })}
        warning={trashable.length < photos.length ? t('selection.trashSome', { count: photos.length - trashable.length }) : undefined}
        warningVariant="warn"
        submit={t('selection.trash')}
        pending={trash.isPending}
        errorFallback={t('selection.trashFailed', { count: trashable.length })}
        onConfirm={() => void moveToTrash()}
      />
      <FileShareDialog target={sharing} onClose={() => setSharing(null)} />
    </div>
  )
}
