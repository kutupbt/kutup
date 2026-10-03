import { useMemo } from 'react'
import { useTranslation } from 'react-i18next'
import { Link } from 'react-router-dom'
import { Button } from '@kutup/ui/components/button'
import { useLibraryContext } from '../library/libraryContext'
import { PhotoGrid } from './PhotoGrid'

/** Every photo and video in the library, but those archived or hidden. */
export function TimelinePage() {
  const { t } = useTranslation()
  const { photos, marks } = useLibraryContext()
  const shown = useMemo(
    () => photos.filter((p) => !marks.archived.has(p.id) && !marks.hidden.has(p.id)),
    [photos, marks.archived, marks.hidden],
  )
  return (
    <PhotoGrid
      photos={shown}
      title={t('timeline.title')}
      empty={{
        title: t('timeline.emptyTitle'),
        description: t('timeline.emptyDescription'),
        action: (
          <Button asChild variant="outline">
            <Link to="/settings">{t('timeline.chooseFolders')}</Link>
          </Button>
        ),
      }}
    />
  )
}
