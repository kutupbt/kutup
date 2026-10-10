import { useQueryClient } from '@tanstack/react-query'
import { lazy, Suspense, useEffect } from 'react'
import { useTranslation } from 'react-i18next'
import { LoadingPanel } from '@kutup/ui/components/states'
import { BrowserRouter, Route, Routes } from 'react-router-dom'
import { useKeepFileSharesCurrent } from '@kutup/drive-core/fileShares'
import { setThumbnailStoredListener } from '@kutup/drive-core/thumbnailQueue'
import { UploadPanel } from '@kutup/drive-ui/UploadPanel'
import { useRequiredSession } from '@kutup/session/store'
import { useResumePhotos } from './features/upload/useUploadPhotos'
import { setUnauthenticatedHandler } from '@kutup/session/client'
import { requestFork } from '@kutup/session/fork'
import { Toaster } from '@kutup/ui/components/sonner'
import { TooltipProvider } from '@kutup/ui/components/tooltip'
import { Boot } from './app/Boot'
import { PhotosShell } from './app/PhotosShell'
import { AlbumPage } from './features/albums/AlbumPage'
import { AlbumsPage } from './features/albums/AlbumsPage'
import { LibraryProvider } from './features/library/LibraryProvider'
import { ArchivePage, FavouritesPage, HiddenPage } from './features/library/MarkedPages'
import { PublicAlbumPage } from './features/public/PublicAlbumPage'
import { TrashPage } from './features/trash/TrashPage'
import { SettingsPage } from './features/settings/SettingsPage'
import { TimelinePage } from './features/timeline/TimelinePage'
import { UploadButton } from './features/upload/UploadButton'
import { NotFoundPage } from './NotFoundPage'

// The map (maplibre, about a megabyte) loads only when Places is opened.
const PlacesPage = lazy(() => import('./features/places/PlacesPage').then((m) => ({ default: m.PlacesPage })))

function Places() {
  const { t } = useTranslation()
  return (
    <Suspense fallback={<LoadingPanel label={t('places.loading')} />}>
      <PlacesPage />
    </Suspense>
  )
}

/** When the sign-in ends (signed out elsewhere, expired), ask the account app again. */
function UnauthenticatedHandler() {
  useEffect(() => {
    setUnauthenticatedHandler(() => requestFork('photos'))
  }, [])
  return null
}

/**
 * Photos are Drive files: their shares follow the owner's key changes here
 * too, and listings refresh once new details or thumbnails are stored.
 */
function DriveUpkeep() {
  const queryClient = useQueryClient()
  useKeepFileSharesCurrent()
  useEffect(() => {
    setThumbnailStoredListener(() => void queryClient.invalidateQueries({ queryKey: ['files'] }))
    return () => setThumbnailStoredListener(null)
  }, [queryClient])
  return null
}

/** The upload queue, and the uploads a reload or a crash stopped, to go on with. */
function PhotosUploadPanel() {
  const session = useRequiredSession()
  const onResume = useResumePhotos()
  return <UploadPanel resume={{ owner: session.userId, onResume }} />
}

/** Everything behind the session: the library and its pages. */
function SignedIn() {
  return (
    <Boot>
      <UnauthenticatedHandler />
      <DriveUpkeep />
      <LibraryProvider>
        <Routes>
          <Route element={<PhotosShell primaryAction={<UploadButton />} />}>
            <Route index element={<TimelinePage />} />
            <Route path="/places" element={<Places />} />
            <Route path="/albums" element={<AlbumsPage />} />
            <Route path="/albums/:id" element={<AlbumPage />} />
            <Route path="/favourites" element={<FavouritesPage />} />
            <Route path="/archive" element={<ArchivePage />} />
            <Route path="/hidden" element={<HiddenPage />} />
            <Route path="/trash" element={<TrashPage />} />
            <Route path="/settings" element={<SettingsPage />} />
          </Route>
          <Route path="*" element={<NotFoundPage />} />
        </Routes>
      </LibraryProvider>
      <PhotosUploadPanel />
    </Boot>
  )
}

export function App() {
  return (
    <BrowserRouter>
      <TooltipProvider delayDuration={300}>
        <Routes>
          {/* A public album link needs no account: it bypasses the session boot. */}
          <Route path="/s/:token" element={<PublicAlbumPage />} />
          <Route path="*" element={<SignedIn />} />
        </Routes>
        <Toaster />
      </TooltipProvider>
    </BrowserRouter>
  )
}
