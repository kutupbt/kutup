import { BookImage, Link2, Plus } from 'lucide-react'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Link } from 'react-router-dom'
import { Button } from '@kutup/ui/components/button'
import { PageBody, PageHeader } from '@kutup/ui/components/page'
import { EmptyState, LoadingPanel } from '@kutup/ui/components/states'
import { useLibraryContext } from '../library/libraryContext'
import { useThumbnail } from '../timeline/useThumbnail'
import type { Photo } from '../library/library'
import { AcceptAlbumInviteDialog } from './AcceptAlbumInviteDialog'
import { NameAlbumDialog } from './NameAlbumDialog'
import { AlbumGone, useAlbumItems, useAlbums, useCreateAlbum, type Album } from './albums'

function Cover({ photo }: { photo: Photo }) {
  const url = useThumbnail(photo.file, 'sm', photo.folder)
  return url ? <img src={url} alt="" className="size-full object-cover transition-transform group-hover:scale-[1.03]" draggable={false} /> : null
}

function AlbumCard({ album }: { album: Album }) {
  const { t } = useTranslation()
  const { index, photos } = useLibraryContext()
  const items = useAlbumItems(album, index, photos)
  const cover = items.data?.[0]
  return (
    <Link
      to={`/albums/${album.id}`}
      className="group block rounded-lg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
    >
      <div className="flex aspect-square items-center justify-center overflow-hidden rounded-lg bg-muted">
        {cover ? <Cover photo={cover} /> : <BookImage className="size-10 text-muted-foreground/60" aria-hidden />}
      </div>
      <p className="mt-2 truncate text-sm font-medium">{album.name}</p>
      {album.ownerAccount ? <p className="truncate text-xs text-muted-foreground">{t('albums.sharedBy', { owner: album.ownerAccount })}</p> : null}
      {/* What it shows: a live photo is one, though it is two files. */}
      <p className="text-xs text-muted-foreground">
        {items.error instanceof AlbumGone ? t('albums.goneShort') : t('albums.itemCount', { count: items.data?.length ?? album.itemCount })}
      </p>
    </Link>
  )
}

/** Your albums: each a view of photos, which stay where they are in Drive. */
export function AlbumsPage() {
  const { t } = useTranslation()
  const albums = useAlbums()
  const create = useCreateAlbum()
  const [naming, setNaming] = useState(false)
  const [inviting, setInviting] = useState(false)
  if (albums.isPending) return <LoadingPanel label={t('albums.loading')} />
  return (
    <PageBody className="px-4 py-6 md:px-8 md:py-8">
      <PageHeader
        title={t('albums.title')}
        description={t('albums.description')}
        actions={
          <>
            <Button variant="outline" onClick={() => setInviting(true)}>
              <Link2 /> {t('albums.invite.open')}
            </Button>
            <Button onClick={() => setNaming(true)}>
              <Plus /> {t('albums.new')}
            </Button>
          </>
        }
      />
      {(albums.data ?? []).length === 0 ? (
        <EmptyState title={t('albums.emptyTitle')} description={t('albums.emptyDescription')} />
      ) : (
        <div className="grid grid-cols-2 gap-4 sm:grid-cols-3 lg:grid-cols-5">
          {albums.data!.map((album) => (
            <AlbumCard key={album.id} album={album} />
          ))}
        </div>
      )}
      <AcceptAlbumInviteDialog open={inviting} onClose={() => setInviting(false)} />
      <NameAlbumDialog
        open={naming}
        title={t('albums.new')}
        initial=""
        pending={create.isPending}
        onClose={() => setNaming(false)}
        onSubmit={(name) => create.mutate({ name }, { onSuccess: () => setNaming(false) })}
      />
    </PageBody>
  )
}
