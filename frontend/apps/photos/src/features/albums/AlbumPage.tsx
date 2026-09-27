import { LogOut, MoreVertical, Pencil, Share2, Trash2 } from 'lucide-react'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { toast } from 'sonner'
import { Button } from '@kutup/ui/components/button'
import { ConfirmDestructive } from '@kutup/ui/components/confirm-destructive'
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from '@kutup/ui/components/dropdown-menu'
import { EmptyState, LoadingPanel } from '@kutup/ui/components/states'
import { useLibraryContext } from '../library/libraryContext'
import { PhotoGrid } from '../timeline/PhotoGrid'
import { NameAlbumDialog } from './NameAlbumDialog'
import { ShareAlbumDialog } from './ShareAlbumDialog'
import { AlbumGone, useAlbumItems, useAlbums, useDeleteAlbum, useLeaveAlbum, useRenameAlbum } from './albums'

/** One album: its photos newest first, as the timeline shows them. */
export function AlbumPage() {
  const { t } = useTranslation()
  const { id } = useParams()
  const navigate = useNavigate()
  const { index, photos: library, marks } = useLibraryContext()
  const albums = useAlbums()
  const album = albums.data?.find((a) => a.id === id)
  const items = useAlbumItems(album, index, library)
  const rename = useRenameAlbum()
  const remove = useDeleteAlbum()
  const leave = useLeaveAlbum()
  const [renaming, setRenaming] = useState(false)
  const [deleting, setDeleting] = useState(false)
  const [sharing, setSharing] = useState(false)
  const [leaving, setLeaving] = useState(false)

  if (albums.isPending || (album && items.isPending)) return <LoadingPanel label={t('albums.loading')} />
  if (!album) {
    return (
      <div className="px-4 py-6 md:px-8">
        <EmptyState
          title={t('albums.notFoundTitle')}
          description={t('albums.notFound')}
          action={
            <Button asChild variant="outline">
              <Link to="/albums">{t('albums.all')}</Link>
            </Button>
          }
        />
      </div>
    )
  }
  if (items.isError) {
    const gone = items.error instanceof AlbumGone
    return (
      <div className="px-4 py-6 md:px-8">
        <EmptyState
          title={gone ? t('albums.goneTitle', { name: album.name }) : t('albums.loadFailedTitle')}
          description={gone ? t('albums.gone', { owner: album.ownerAccount }) : t('albums.loadFailed')}
          action={
            gone ? (
              <Button
                variant="outline"
                loading={leave.isPending}
                onClick={() =>
                  leave.mutate(
                    { album },
                    { onSuccess: () => void navigate('/albums', { replace: true }), onError: () => toast.error(t('albums.failed')) },
                  )
                }
              >
                {t('albums.forget')}
              </Button>
            ) : (
              <Button variant="outline" onClick={() => void items.refetch()}>
                {t('albums.retry')}
              </Button>
            )
          }
        />
      </div>
    )
  }
  // Hidden photos stay out of sight here too.
  const shown = (items.data ?? []).filter((p) => !marks.hidden.has(p.id))
  return (
    <>
      <PhotoGrid
        photos={shown}
        title={album.ownerAccount ? t('albums.sharedTitle', { name: album.name, owner: album.ownerAccount }) : album.name}
        album={album}
        dropToUpload={false}
        empty={{ title: t('albums.emptyAlbumTitle'), description: t('albums.emptyAlbum') }}
        actions={
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="ghost" size="icon" aria-label={t('albums.menu')}>
                <MoreVertical />
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end">
              {album.owned ? (
                <>
                  <DropdownMenuItem onSelect={() => setSharing(true)}>
                    <Share2 /> {t('albums.share')}
                  </DropdownMenuItem>
                  <DropdownMenuItem onSelect={() => setRenaming(true)}>
                    <Pencil /> {t('albums.rename')}
                  </DropdownMenuItem>
                  <DropdownMenuItem onSelect={() => setDeleting(true)}>
                    <Trash2 /> {t('albums.delete')}
                  </DropdownMenuItem>
                </>
              ) : (
                <DropdownMenuItem onSelect={() => setLeaving(true)}>
                  <LogOut /> {t('albums.leave')}
                </DropdownMenuItem>
              )}
            </DropdownMenuContent>
          </DropdownMenu>
        }
      />
      {album.owned ? <ShareAlbumDialog album={album} open={sharing} onClose={() => setSharing(false)} /> : null}
      <ConfirmDestructive
        open={leaving}
        onOpenChange={setLeaving}
        title={t('albums.leaveTitle', { name: album.name })}
        description={album.folder.source === 'remote' ? t('albums.leaveRemoteDescription') : t('albums.leaveDescription')}
        submit={t('albums.leave')}
        pending={leave.isPending}
        errorFallback={t('albums.failed')}
        onConfirm={() =>
          leave.mutate(
            { album },
            {
              onSuccess: () => {
                setLeaving(false)
                void navigate('/albums', { replace: true })
              },
            },
          )
        }
      />
      <NameAlbumDialog
        open={renaming}
        title={t('albums.rename')}
        initial={album.name}
        pending={rename.isPending}
        onClose={() => setRenaming(false)}
        onSubmit={(name) => rename.mutate({ album, name }, { onSuccess: () => setRenaming(false), onError: () => toast.error(t('albums.failed')) })}
      />
      <ConfirmDestructive
        open={deleting}
        onOpenChange={setDeleting}
        title={t('albums.deleteTitle', { name: album.name })}
        description={t('albums.deleteDescription')}
        submit={t('albums.delete')}
        pending={remove.isPending}
        errorFallback={t('albums.failed')}
        onConfirm={() =>
          remove.mutate(
            { album },
            {
              onSuccess: () => {
                setDeleting(false)
                void navigate('/albums', { replace: true })
              },
            },
          )
        }
      />
    </>
  )
}
