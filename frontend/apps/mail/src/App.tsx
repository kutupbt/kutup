import { useEffect } from 'react'
import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom'
import { setUnauthenticatedHandler } from '@kutup/session/client'
import { requestFork } from '@kutup/session/fork'
import { Toaster } from '@kutup/ui/components/sonner'
import { TooltipProvider } from '@kutup/ui/components/tooltip'
import { Boot } from './app/Boot'
import { MailShell } from './app/MailShell'
import { MailboxPage } from './features/MailboxPage'
import { FiltersSettingsPage } from './features/FiltersSettingsPage'
import { PlacesSettingsPage } from './features/PlacesSettingsPage'
import { SettingsLayout } from './features/SettingsLayout'
import { NotFoundPage } from './NotFoundPage'

/** When the sign-in ends (signed out elsewhere, expired), ask the account app again. */
function UnauthenticatedHandler() {
  useEffect(() => {
    setUnauthenticatedHandler(() => requestFork('mail'))
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
            <Route element={<MailShell />}>
              <Route index element={<Navigate to="/inbox" replace />} />
              <Route path="/:folder" element={<MailboxPage />} />
              <Route path="/:folder/:threadId" element={<MailboxPage />} />
              <Route path="/f/:placeId" element={<MailboxPage />} />
              <Route path="/f/:placeId/:threadId" element={<MailboxPage />} />
              <Route path="/l/:placeId" element={<MailboxPage />} />
              <Route path="/l/:placeId/:threadId" element={<MailboxPage />} />
              <Route path="/settings" element={<SettingsLayout />}>
                <Route index element={<Navigate to="/settings/folders" replace />} />
                <Route path="folders" element={<PlacesSettingsPage />} />
                <Route path="filters" element={<FiltersSettingsPage />} />
              </Route>
            </Route>
            <Route path="*" element={<NotFoundPage />} />
          </Routes>
        </Boot>
        <Toaster />
      </TooltipProvider>
    </BrowserRouter>
  )
}
