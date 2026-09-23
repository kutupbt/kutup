import { useEffect } from 'react'
import { BrowserRouter, Route, Routes } from 'react-router-dom'
import { setUnauthenticatedHandler } from '@kutup/session/client'
import { requestFork } from '@kutup/session/fork'
import { Toaster } from '@kutup/ui/components/sonner'
import { TooltipProvider } from '@kutup/ui/components/tooltip'
import { Boot } from './app/Boot'
import { DriveShell } from './app/DriveShell'
import { NewMenu } from './features/create/NewMenu'
import { CurrentFolderProvider } from './features/drive/currentFolder'
import { FileEditorPage } from './features/editor/FileEditorPage'
import { FolderPage } from './features/folder/FolderPage'
import { PublicSharePage } from './features/public/PublicSharePage'
import { SharedPage } from './features/shared/SharedPage'
import { TrashPage } from './features/trash/TrashPage'
import { UploadPanel } from './features/uploads/UploadPanel'
import { NotFoundPage } from './NotFoundPage'

/** When the sign-in ends (signed out elsewhere, expired), ask the account app again. */
function UnauthenticatedHandler() {
  useEffect(() => {
    setUnauthenticatedHandler(() => requestFork('drive'))
  }, [])
  return null
}

/** Everything behind the session: the Drive shell and its pages. */
function SignedIn() {
  return (
    <Boot>
      <UnauthenticatedHandler />
      <CurrentFolderProvider>
        <Routes>
          {/* A file opens full screen, outside the Drive frame. */}
          <Route path="/file/:cid/:fid" element={<FileEditorPage />} />
          <Route element={<DriveShell primaryAction={<NewMenu />} />}>
            <Route index element={<FolderPage />} />
            <Route path="/folders/:id" element={<FolderPage />} />
            <Route path="/remote/:shareId" element={<FolderPage />} />
            <Route path="/shared" element={<SharedPage />} />
            <Route path="/trash" element={<TrashPage />} />
            <Route path="*" element={<NotFoundPage />} />
          </Route>
        </Routes>
        <UploadPanel />
      </CurrentFolderProvider>
    </Boot>
  )
}

export function App() {
  return (
    <BrowserRouter>
      <TooltipProvider delayDuration={300}>
        <Routes>
          {/* Public links need no account: they bypass the session boot entirely. */}
          <Route path="/s/:token" element={<PublicSharePage />} />
          <Route path="*" element={<SignedIn />} />
        </Routes>
        {/* Outside the routes so a toast survives the navigation after a save. */}
        <Toaster />
      </TooltipProvider>
    </BrowserRouter>
  )
}
