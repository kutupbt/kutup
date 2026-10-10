import { useEffect } from 'react'
import { BrowserRouter, Route, Routes } from 'react-router-dom'
import { setUnauthenticatedHandler } from '@kutup/session/client'
import { requestFork } from '@kutup/session/fork'
import { Toaster } from '@kutup/ui/components/sonner'
import { TooltipProvider } from '@kutup/ui/components/tooltip'
import { Boot } from './app/Boot'
import { ContactsShell } from './app/ContactsShell'
import { ContactsPage } from './features/ContactsPage'
import { NotFoundPage } from './NotFoundPage'

/** When the sign-in ends (signed out elsewhere, expired), ask the account app again. */
function UnauthenticatedHandler() {
  useEffect(() => {
    setUnauthenticatedHandler(() => requestFork('contacts'))
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
            <Route element={<ContactsShell />}>
              <Route index element={<ContactsPage />} />
              <Route path="/c/:id" element={<ContactsPage />} />
              <Route path="/groups/:groupId" element={<ContactsPage />} />
              <Route path="/groups/:groupId/c/:id" element={<ContactsPage />} />
            </Route>
            <Route path="*" element={<NotFoundPage />} />
          </Routes>
        </Boot>
        <Toaster />
      </TooltipProvider>
    </BrowserRouter>
  )
}
