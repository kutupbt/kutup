import { useEffect } from 'react'
import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom'
import { setUnauthenticatedHandler } from '@kutup/session/client'
import { requestFork } from '@kutup/session/fork'
import { Toaster } from '@kutup/ui/components/sonner'
import { TooltipProvider } from '@kutup/ui/components/tooltip'
import { Boot } from './app/Boot'
import { ChatGate } from './app/ChatGate'
import { ChatJobs } from './app/ChatJobs'
import { ChatShell } from './app/ChatShell'
import { SettingsPage } from './features/settings/SettingsPage'
import { NotFoundPage } from './NotFoundPage'
import { ChatsPage } from './pages/ChatsPage'

/** When the sign-in ends (signed out elsewhere, expired), ask the account app again. */
function UnauthenticatedHandler() {
  useEffect(() => {
    setUnauthenticatedHandler(() => requestFork('chat'))
  }, [])
  return null
}

export function App() {
  return (
    <BrowserRouter>
      <TooltipProvider delayDuration={300}>
        <Boot>
          <UnauthenticatedHandler />
          <ChatGate>
            <ChatJobs />
            <Routes>
              <Route element={<ChatShell />}>
                <Route index element={<ChatsPage />} />
                <Route path="/c/:key" element={<ChatsPage />} />
                <Route path="/settings" element={<Navigate to="/settings/profile" replace />} />
                <Route path="/settings/:section" element={<SettingsPage />} />
                <Route path="*" element={<NotFoundPage />} />
              </Route>
            </Routes>
          </ChatGate>
        </Boot>
        {/* Outside the routes so a toast survives navigation. */}
        <Toaster />
      </TooltipProvider>
    </BrowserRouter>
  )
}
