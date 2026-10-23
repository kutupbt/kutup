import { useEffect } from 'react'
import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom'
import { setUnauthenticatedHandler } from '@kutup/session/client'
import { requestFork } from '@kutup/session/fork'
import { Toaster } from '@kutup/ui/components/sonner'
import { TooltipProvider } from '@kutup/ui/components/tooltip'
import { Boot } from './app/Boot'
import { MailShell } from './app/MailShell'
import { GroupsMoved } from './features/GroupsMoved'
import { MailboxPage } from './features/MailboxPage'
import { FiltersSettingsPage } from './features/FiltersSettingsPage'
import { ForwardingSettingsPage } from './features/ForwardingSettingsPage'
import { DomainsSettingsPage } from './features/domains/DomainsSettingsPage'
import { GeneralSettingsPage } from './features/GeneralSettingsPage'
import { AppearanceSettingsPage } from './features/AppearanceSettingsPage'
import { AutoReplySettingsPage } from './features/AutoReplySettingsPage'
import { IdentitySettingsPage } from './features/IdentitySettingsPage'
import { PlacesSettingsPage } from './features/PlacesSettingsPage'
import { SendersSettingsPage } from './features/SendersSettingsPage'
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
                <Route index element={<Navigate to="/settings/general" replace />} />
                <Route path="general" element={<GeneralSettingsPage />} />
                <Route path="appearance" element={<AppearanceSettingsPage />} />
                <Route path="identity" element={<IdentitySettingsPage />} />
                <Route path="auto-reply" element={<AutoReplySettingsPage />} />
                <Route path="folders" element={<PlacesSettingsPage />} />
                <Route path="filters" element={<FiltersSettingsPage />} />
                <Route path="forwarding" element={<ForwardingSettingsPage />} />
                <Route path="domains" element={<DomainsSettingsPage />} />
                <Route path="senders" element={<SendersSettingsPage />} />
              </Route>
              {/* A shared mailbox (docs/plans/mail-groups.md). */}
              <Route path="/g/:groupId" element={<Navigate to="inbox" replace />} />
              <Route path="/g/:groupId/:folder" element={<MailboxPage />} />
              <Route path="/g/:groupId/:folder/:threadId" element={<MailboxPage />} />
            </Route>
            {/* The Groups page moved to Account settings (Group membership). */}
            <Route path="/groups" element={<GroupsMoved />} />
            <Route path="*" element={<NotFoundPage />} />
          </Routes>
        </Boot>
        <Toaster />
      </TooltipProvider>
    </BrowserRouter>
  )
}
