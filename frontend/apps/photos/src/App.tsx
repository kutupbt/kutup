import { useQueryClient } from '@tanstack/react-query'
import { useEffect } from 'react'
import { BrowserRouter, Route, Routes } from 'react-router-dom'
import { useKeepFileSharesCurrent } from '@kutup/drive-core/fileShares'
import { setThumbnailStoredListener } from '@kutup/drive-core/thumbnailQueue'
import { UploadPanel } from '@kutup/drive-ui/UploadPanel'
import { setUnauthenticatedHandler } from '@kutup/session/client'
import { requestFork } from '@kutup/session/fork'
import { Toaster } from '@kutup/ui/components/sonner'
import { TooltipProvider } from '@kutup/ui/components/tooltip'
import { Boot } from './app/Boot'
import { PhotosShell } from './app/PhotosShell'
import { LibraryProvider } from './features/library/LibraryProvider'
import { ArchivePage, FavouritesPage, HiddenPage } from './features/library/MarkedPages'
import { PlacesPage } from './features/places/PlacesPage'
import { TrashPage } from './features/trash/TrashPage'
import { SettingsPage } from './features/settings/SettingsPage'
import { TimelinePage } from './features/timeline/TimelinePage'
import { UploadButton } from './features/upload/UploadButton'
import { NotFoundPage } from './NotFoundPage'

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

export function App() {
  return (
    <BrowserRouter>
      <TooltipProvider delayDuration={300}>
        <Boot>
          <UnauthenticatedHandler />
          <DriveUpkeep />
          <LibraryProvider>
            <Routes>
              <Route element={<PhotosShell primaryAction={<UploadButton />} />}>
                <Route index element={<TimelinePage />} />
                <Route path="/places" element={<PlacesPage />} />
                <Route path="/favourites" element={<FavouritesPage />} />
                <Route path="/archive" element={<ArchivePage />} />
                <Route path="/hidden" element={<HiddenPage />} />
                <Route path="/trash" element={<TrashPage />} />
                <Route path="/settings" element={<SettingsPage />} />
              </Route>
              <Route path="*" element={<NotFoundPage />} />
            </Routes>
          </LibraryProvider>
          <UploadPanel />
        </Boot>
        <Toaster />
      </TooltipProvider>
    </BrowserRouter>
  )
}
