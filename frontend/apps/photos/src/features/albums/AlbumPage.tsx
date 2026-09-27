import { MoreVertical, Pencil, Trash2 } from 'lucide-react'
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
import { useAlbumItems, useAlbums, useDeleteAlbum, useRenameAlbum } from './albums'

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
  const [renaming, setRenaming] = useState(false)
  const [deleting, setDeleting] = useState(false)

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
  // Hidden photos stay out of sight here too.
  const shown = (items.data ?? []).filter((p) => !marks.hidden.has(p.id))
  return (
    <>
      <PhotoGrid
        photos={shown}
        title={album.name}
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
              <DropdownMenuItem onSelect={() => setRenaming(true)}>
                <Pencil /> {t('albums.rename')}
              </DropdownMenuItem>
              <DropdownMenuItem onSelect={() => setDeleting(true)}>
                <Trash2 /> {t('albums.delete')}
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
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
