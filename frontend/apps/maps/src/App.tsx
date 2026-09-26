import { useEffect } from 'react'
import { BrowserRouter, Route, Routes } from 'react-router-dom'
import { useKeepFileSharesCurrent } from '@kutup/drive-core/fileShares'
import { setUnauthenticatedHandler } from '@kutup/session/client'
import { requestFork } from '@kutup/session/fork'
import { Toaster } from '@kutup/ui/components/sonner'
import { TooltipProvider } from '@kutup/ui/components/tooltip'
import { Boot } from './app/Boot'
import { MapsLayout } from './app/MapsLayout'
import { AtlasProvider } from './features/lists/atlas'
import { HomePanel } from './features/lists/HomePanel'
import { ListPanel } from './features/lists/ListPanel'
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
          <AtlasProvider>
            <Routes>
              {/* One map stays in place; the panel beside it follows the address. */}
              <Route element={<MapsLayout />}>
                <Route index element={<HomePanel />} />
                <Route path="/settings" element={<HomePanel settings />} />
                <Route path="/lists/:cid/:fid" element={<ListPanel />} />
                <Route path="/shared/:fid" element={<ListPanel shared />} />
              </Route>
              <Route path="*" element={<NotFoundPage />} />
            </Routes>
          </AtlasProvider>
        </Boot>
        <Toaster />
      </TooltipProvider>
    </BrowserRouter>
  )
}
