import { useEffect } from 'react'
import { BrowserRouter, Route, Routes } from 'react-router-dom'
import { setUnauthenticatedHandler } from '@kutup/session/client'
import { requestFork } from '@kutup/session/fork'
import { Toaster } from '@kutup/ui/components/sonner'
import { TooltipProvider } from '@kutup/ui/components/tooltip'
import { Boot } from './app/Boot'
import { CalendarShell } from './app/CalendarShell'
import { CalendarPage } from './features/CalendarPage'
import { PublicCalendarPage } from './features/public/PublicCalendarPage'
import { NotFoundPage } from './NotFoundPage'

/** When the sign-in ends (signed out elsewhere, expired), ask the account app again. */
function UnauthenticatedHandler() {
  useEffect(() => {
    setUnauthenticatedHandler(() => requestFork('calendar'))
  }, [])
  return null
}

/** Everything that needs the account: a session from the account app first. */
function SignedIn() {
  return (
    <Boot>
      <UnauthenticatedHandler />
      <Routes>
        <Route element={<CalendarShell />}>
          <Route index element={<CalendarPage />} />
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
          {/* A calendar link (docs/plans/calendar-e3.md §3): no account, no
              session, nothing asked of the account app. */}
          <Route path="/l/:linkId" element={<PublicCalendarPage />} />
          <Route path="*" element={<SignedIn />} />
        </Routes>
        <Toaster />
      </TooltipProvider>
    </BrowserRouter>
  )
}
