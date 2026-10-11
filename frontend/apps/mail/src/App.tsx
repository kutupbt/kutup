import { useEffect } from 'react'
import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom'
import { setUnauthenticatedHandler } from '@kutup/session/client'
import { requestFork } from '@kutup/session/fork'
import { Toaster } from '@kutup/ui/components/sonner'
import { TooltipProvider } from '@kutup/ui/components/tooltip'
import { Boot } from './app/Boot'
import { MailShell } from './app/MailShell'
import { GroupsPage } from './features/GroupsPage'
import { MailboxPage } from './features/MailboxPage'
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
              <Route path="/groups" element={<GroupsPage />} />
              <Route path="/:folder" element={<MailboxPage />} />
              <Route path="/:folder/:threadId" element={<MailboxPage />} />
              {/* A shared mailbox (docs/plans/mail-groups.md). */}
              <Route path="/g/:groupId" element={<Navigate to="inbox" replace />} />
              <Route path="/g/:groupId/:folder" element={<MailboxPage />} />
              <Route path="/g/:groupId/:folder/:threadId" element={<MailboxPage />} />
            </Route>
            <Route path="*" element={<NotFoundPage />} />
          </Routes>
        </Boot>
        <Toaster />
      </TooltipProvider>
    </BrowserRouter>
  )
}
