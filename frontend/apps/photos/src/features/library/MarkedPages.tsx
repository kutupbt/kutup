import { useMemo } from 'react'
import { useTranslation } from 'react-i18next'
import { PhotoGrid } from '../timeline/PhotoGrid'
import { useLibraryContext } from './libraryContext'

/** Your favourites (those you hid stay out of sight). */
export function FavouritesPage() {
  const { t } = useTranslation()
  const { photos, marks } = useLibraryContext()
  const shown = useMemo(
    () => photos.filter((p) => marks.favourites.has(p.id) && !marks.hidden.has(p.id)),
    [photos, marks.favourites, marks.hidden],
  )
  return <PhotoGrid photos={shown} title={t('favourites.title')} empty={{ title: t('favourites.emptyTitle'), description: t('favourites.emptyDescription') }} />
}

/** Photos kept but out of the timeline and Places. */
export function ArchivePage() {
  const { t } = useTranslation()
  const { photos, marks } = useLibraryContext()
  const shown = useMemo(
    () => photos.filter((p) => marks.archived.has(p.id) && !marks.hidden.has(p.id)),
    [photos, marks.archived, marks.hidden],
  )
  return <PhotoGrid photos={shown} title={t('archive.title')} empty={{ title: t('archive.emptyTitle'), description: t('archive.emptyDescription') }} />
}

/** Photos out of sight everywhere but here. */
export function HiddenPage() {
  const { t } = useTranslation()
  const { photos, marks } = useLibraryContext()
  const shown = useMemo(() => photos.filter((p) => marks.hidden.has(p.id)), [photos, marks.hidden])
  return (
    <PhotoGrid
      photos={shown}
      title={t('hidden.title')}
      dropToUpload={false}
      empty={{ title: t('hidden.emptyTitle'), description: t('hidden.emptyDescription') }}
    />
  )
}
