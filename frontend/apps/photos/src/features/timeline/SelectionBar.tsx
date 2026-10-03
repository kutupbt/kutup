import { Archive, ArchiveRestore, BookImage, Download, Eye, EyeOff, Heart, ImageMinus, MoreHorizontal, Share2, Trash2, X } from 'lucide-react'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { shareRole } from '@kutup/drive-core/fileShares'
import { useTrashFile } from '@kutup/drive-core/mutations'
import { FileShareDialog, type FileShareTarget } from '@kutup/drive-ui/FileShareDialog'
import { useRequiredSession } from '@kutup/session/store'
import { Button } from '@kutup/ui/components/button'
import { ConfirmDestructive } from '@kutup/ui/components/confirm-destructive'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@kutup/ui/components/dropdown-menu'
import { AddToAlbumDialog } from '../albums/AddToAlbumDialog'
import { useRemoveFromAlbum, type Album } from '../albums/albums'
import { useLibraryContext } from '../library/libraryContext'
import type { MarkKind } from '../library/marks'
import { filesOf, type Photo } from '../library/library'
import { downloadPhoto, downloadPhotosZip, FsaRequiredError } from './downloads'
import { mayTrash } from './mayTrash'

/** What to do with the selected photos: download, share one, move to trash. */
export function SelectionBar({ photos, album, onClear }: { photos: Photo[]; album?: Album; onClear: () => void }) {
  const { t } = useTranslation()
  const session = useRequiredSession()
  const trash = useTrashFile()
  const [confirming, setConfirming] = useState(false)
  const [sharing, setSharing] = useState<FileShareTarget | null>(null)
  const [downloading, setDownloading] = useState(false)
  const [adding, setAdding] = useState(false)
  const removeFromAlbum = useRemoveFromAlbum()
  // Only your own photos go in albums (others' are theirs to share).
  const own = photos.filter((p) => p.folder.source === 'owned')
  // In an album: its owner takes out any photo, a member those they put in.
  const removable = album ? photos.filter((p) => album.owned || p.addedBy === session.userId) : []
  const trashablePhotos = photos.filter((p) => mayTrash(p, session.userId))
  // A live photo's video goes with its still.
  const trashable = trashablePhotos.flatMap(filesOf)
  const only = photos.length === 1 ? photos[0] : null
  const role = only ? shareRole(only.folder, only.file) : null
  const { marks } = useLibraryContext()
  const ids = photos.map((p) => p.id)
  // A mark goes on unless every selected photo has it already.
  const allHave = (set: ReadonlySet<string>) => ids.every((id) => set.has(id))
  const allFavourite = allHave(marks.favourites)
  const allArchived = allHave(marks.archived)
  const allHidden = allHave(marks.hidden)

  function mark(kind: MarkKind, on: boolean, done: string) {
    marks.set(kind, ids, on).then(
      () => {
        toast.success(t(done, { count: ids.length }))
        // Archiving or hiding takes them off this page: nothing is left selected.
        if (kind !== 'favourites') onClear()
      },
      () => toast.error(t('selection.markFailed')),
    )
  }

  async function download() {
    setDownloading(true)
    try {
      if (only) await downloadPhoto(only)
      else {
        const id = toast.loading(t('selection.zipping', { done: 0, count: photos.length }))
        try {
          await downloadPhotosZip(photos.flatMap(filesOf), t('selection.archiveName'), (done, total) =>
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
    else toast.success(t('selection.trashed', { count: trashablePhotos.length }))
  }

  return (
    <div className="sticky top-14 z-20 flex items-center gap-2 border-b border-border bg-background/95 px-3 py-2 backdrop-blur-sm md:px-8">
      <Button variant="ghost" size="icon" aria-label={t('selection.clear')} onClick={onClear}>
        <X />
      </Button>
      <p className="min-w-0 flex-1 truncate text-sm font-medium">{t('selection.count', { count: photos.length })}</p>
      <Button
        variant="outline"
        size="sm"
        aria-pressed={allFavourite}
        onClick={() => mark('favourites', !allFavourite, allFavourite ? 'selection.unfavourited' : 'selection.favourited')}
      >
        <Heart className={allFavourite ? 'fill-current' : undefined} />
        <span className="hidden sm:inline">{allFavourite ? t('selection.unfavourite') : t('selection.favourite')}</span>
      </Button>
      <Button variant="outline" size="sm" disabled={downloading} onClick={() => void download()}>
        <Download /> <span className="hidden sm:inline">{t('selection.download')}</span>
      </Button>
      {only && role ? (
        <Button variant="outline" size="sm" onClick={() => setSharing({ folder: only.folder, file: only.file, role })}>
          <Share2 /> <span className="hidden sm:inline">{t('selection.share')}</span>
        </Button>
      ) : null}
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Button variant="outline" size="sm" aria-label={t('selection.more')}>
            <MoreHorizontal />
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end">
          {own.length > 0 ? (
            <DropdownMenuItem onSelect={() => setAdding(true)}>
              <BookImage />
              {t('albums.addTo')}
            </DropdownMenuItem>
          ) : null}
          {album && removable.length > 0 ? (
            <DropdownMenuItem
              onSelect={() =>
                removeFromAlbum.mutate(
                  { album, photos: removable },
                  {
                    onSuccess: () => {
                      toast.success(t('albums.removed', { count: removable.length }))
                      onClear()
                    },
                    onError: () => toast.error(t('albums.failed')),
                  },
                )
              }
            >
              <ImageMinus />
              {t('albums.removeFrom')}
            </DropdownMenuItem>
          ) : null}
          <DropdownMenuSeparator />
          <DropdownMenuItem onSelect={() => mark('archived', !allArchived, allArchived ? 'selection.unarchived' : 'selection.archived')}>
            {allArchived ? <ArchiveRestore /> : <Archive />}
            {allArchived ? t('selection.unarchive') : t('selection.archive')}
          </DropdownMenuItem>
          <DropdownMenuItem onSelect={() => mark('hidden', !allHidden, allHidden ? 'selection.unhidden' : 'selection.hiddenDone')}>
            {allHidden ? <Eye /> : <EyeOff />}
            {allHidden ? t('selection.unhide') : t('selection.hide')}
          </DropdownMenuItem>
          {trashablePhotos.length > 0 ? (
            <>
              <DropdownMenuSeparator />
              <DropdownMenuItem onSelect={() => setConfirming(true)}>
                <Trash2 />
                {t('selection.trash')}
              </DropdownMenuItem>
            </>
          ) : null}
        </DropdownMenuContent>
      </DropdownMenu>
      <ConfirmDestructive
        open={confirming}
        onOpenChange={setConfirming}
        title={t('selection.trashTitle', { count: trashablePhotos.length })}
        description={t('selection.trashDescription', { count: trashablePhotos.length })}
        warning={photos.some((p) => !mayTrash(p, session.userId)) ? t('selection.trashSome', { count: photos.filter((p) => !mayTrash(p, session.userId)).length }) : undefined}
        warningVariant="warn"
        submit={t('selection.trash')}
        pending={trash.isPending}
        errorFallback={t('selection.trashFailed', { count: trashablePhotos.length })}
        onConfirm={() => void moveToTrash()}
      />
      <FileShareDialog target={sharing} onClose={() => setSharing(null)} />
      <AddToAlbumDialog photos={own} open={adding} onClose={() => setAdding(false)} onAdded={onClear} />
    </div>
  )
}
