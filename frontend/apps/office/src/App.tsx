import { useQueryClient } from '@tanstack/react-query'
import { useEffect } from 'react'
import { BrowserRouter, Route, Routes } from 'react-router-dom'
import { useKeepFileSharesCurrent } from '@kutup/drive-core/fileShares'
import { FileRoute } from '@kutup/editors/FileRoute'
import { PublicFileRoute } from '@kutup/editors/PublicFileRoute'
import { setThumbnailStoredListener } from '@kutup/drive-core/thumbnailQueue'
import { setUnauthenticatedHandler } from '@kutup/session/client'
import { requestFork } from '@kutup/session/fork'
import { Toaster } from '@kutup/ui/components/sonner'
import { TooltipProvider } from '@kutup/ui/components/tooltip'
import { Boot } from './app/Boot'
import { OfficeShell } from './app/OfficeShell'
import { HomePage } from './features/home/HomePage'
import { NotFoundPage } from './NotFoundPage'

/** When the sign-in ends (signed out elsewhere, expired), ask the account app again. */
function UnauthenticatedHandler() {
  useEffect(() => {
    setUnauthenticatedHandler(() => requestFork('office'))
  }, [])
  return null
}

/** Documents are Drive files: their shares follow the owner's key changes here too. */
function FileSharesUpkeep() {
  useKeepFileSharesCurrent()
  return null
}

/** A document's new thumbnail (drawn as it is saved) shows on the home without a reload. */
function ThumbnailRefresh() {
  const queryClient = useQueryClient()
  useEffect(() => {
    setThumbnailStoredListener(() => void queryClient.invalidateQueries({ queryKey: ['files'] }))
    return () => setThumbnailStoredListener(null)
  }, [queryClient])
  return null
}

/** Everything that needs the account: the home and the documents. */
function SignedIn() {
  return (
    <Boot>
      <UnauthenticatedHandler />
      <FileSharesUpkeep />
      <ThumbnailRefresh />
      <Routes>
        {/* A document opens full screen, outside the Office frame: the
            same page and address as Drive's (@kutup/editors/paths). */}
        <Route path="/file/:cid/:fid" element={<FileRoute />} />
        <Route path="/shared/file/:fid" element={<FileRoute shared />} />
        <Route element={<OfficeShell />}>
          <Route index element={<HomePage />} />
          <Route path="/notes" element={<HomePage kind="note" />} />
          <Route path="/documents" element={<HomePage kind="document" />} />
          <Route path="/spreadsheets" element={<HomePage kind="spreadsheet" />} />
          <Route path="/presentations" element={<HomePage kind="presentation" />} />
          <Route path="/whiteboards" element={<HomePage kind="whiteboard" />} />
        </Route>
        <Route path="*" element={<NotFoundPage />} />
      </Routes>
    </Boot>
  )
}

export function App() {
  return (
    <BrowserRouter>
      <TooltipProvider delayDuration={300}>
        <Routes>
          {/* Public links need no account: they bypass the session boot entirely. */}
          <Route path="/s/:token" element={<PublicFileRoute />} />
          <Route path="/s/:token/:fid" element={<PublicFileRoute />} />
          <Route path="*" element={<SignedIn />} />
        </Routes>
        <Toaster />
      </TooltipProvider>
    </BrowserRouter>
  )
}
