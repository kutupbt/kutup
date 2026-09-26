import { useEffect } from 'react'
import { BrowserRouter, Route, Routes } from 'react-router-dom'
import { useKeepFileSharesCurrent } from '@kutup/drive-core/fileShares'
import { setUnauthenticatedHandler } from '@kutup/session/client'
import { requestFork } from '@kutup/session/fork'
import { Toaster } from '@kutup/ui/components/sonner'
import { TooltipProvider } from '@kutup/ui/components/tooltip'
import { Boot } from './app/Boot'
import { MapsShell } from './app/MapsShell'
import { HomePage } from './features/lists/HomePage'
import { ListPage } from './features/lists/ListPage'
import { SettingsPage } from './features/settings/SettingsPage'
import { NotFoundPage } from './NotFoundPage'

/** When the sign-in ends (signed out elsewhere, expired), ask the account app again. */
function UnauthenticatedHandler() {
  useEffect(() => {
    setUnauthenticatedHandler(() => requestFork('maps'))
  }, [])
  return null
}

/** Lists are Drive files: their shares follow the owner's key changes here too. */
function FileSharesUpkeep() {
  useKeepFileSharesCurrent()
  return null
}

export function App() {
  return (
    <BrowserRouter>
      <TooltipProvider delayDuration={300}>
        <Boot>
          <UnauthenticatedHandler />
          <FileSharesUpkeep />
          <Routes>
            {/* A list opens full screen: the map needs the room. */}
            <Route path="/lists/:cid/:fid" element={<ListPage />} />
            <Route path="/shared/:fid" element={<ListPage shared />} />
            <Route element={<MapsShell />}>
              <Route index element={<HomePage />} />
              <Route path="/settings" element={<SettingsPage />} />
              <Route path="*" element={<NotFoundPage />} />
            </Route>
          </Routes>
        </Boot>
        <Toaster />
      </TooltipProvider>
    </BrowserRouter>
  )
}
