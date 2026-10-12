import { useEffect } from 'react'
import { BrowserRouter, Route, Routes } from 'react-router-dom'
import { setUnauthenticatedHandler } from '@kutup/session/client'
import { requestFork } from '@kutup/session/fork'
import { lockAll } from './sync/openVaults'
import { Toaster } from '@kutup/ui/components/sonner'
import { TooltipProvider } from '@kutup/ui/components/tooltip'
import { Boot } from './app/Boot'
import { PassShell } from './app/PassShell'
import { VaultPage } from './features/VaultPage'
import { VaultsPage } from './features/VaultsPage'
import { NotFoundPage } from './NotFoundPage'

/** When the sign-in ends (signed out elsewhere, expired), ask the account app again. */
function UnauthenticatedHandler() {
  useEffect(() => {
    // The session ended (revoked elsewhere, expired): the vaults lock first.
    // Edits not yet saved stay in the outbox for the next sign-in.
    setUnauthenticatedHandler(() => {
      void lockAll().finally(() => requestFork('pass'))
    })
  }, [])
  return null
}

export function App() {
  return (
    <BrowserRouter>
      <TooltipProvider delayDuration={300}>
        <Boot>
          <UnauthenticatedHandler />
          <Routes>
            <Route element={<PassShell />}>
              <Route index element={<VaultsPage />} />
              <Route path="/v/:fileId" element={<VaultPage />} />
              <Route path="/v/:fileId/e/:entryId" element={<VaultPage />} />
            </Route>
            <Route path="*" element={<NotFoundPage />} />
          </Routes>
        </Boot>
        <Toaster />
      </TooltipProvider>
    </BrowserRouter>
  )
}
