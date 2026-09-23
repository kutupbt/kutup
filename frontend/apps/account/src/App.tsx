import { useEffect } from 'react'
import { BrowserRouter, Route, Routes, useNavigate } from 'react-router-dom'
import { setUnauthenticatedHandler } from '@kutup/session/client'
import { Toaster } from '@kutup/ui/components/sonner'
import { TooltipProvider } from '@kutup/ui/components/tooltip'
import { AccountShell } from './app/AccountShell'
import { Boot } from './app/Boot'
import { RequireSession } from './app/guards'
import { AuthorizePage } from './features/auth/AuthorizePage'
import { FirstLoginPage } from './features/auth/FirstLoginPage'
import { LoginPage } from './features/auth/LoginPage'
import { RecoverPage } from './features/auth/RecoverPage'
import { RegisterPage } from './features/auth/RegisterPage'
import { LauncherPage } from './features/home/LauncherPage'
import { AccountSettingsPage } from './features/settings/AccountSettingsPage'
import { DevicesPage } from './features/settings/DevicesPage'
import { SecurityPage } from './features/settings/SecurityPage'
import { SessionsPage } from './features/settings/SessionsPage'
import { NotFoundPage } from './NotFoundPage'

/** When the server ends this sign-in (revoked elsewhere, expired), go to sign-in. */
function UnauthenticatedRedirect() {
  const navigate = useNavigate()
  useEffect(() => {
    setUnauthenticatedHandler(() => {
      const here = window.location.pathname + window.location.search
      void navigate(`/login?next=${encodeURIComponent(here)}`, { replace: true })
    })
  }, [navigate])
  return null
}

export function App() {
  return (
    <BrowserRouter>
      <TooltipProvider delayDuration={300}>
        <UnauthenticatedRedirect />
        <Boot>
          <Routes>
            <Route path="/login" element={<LoginPage />} />
            <Route path="/register" element={<RegisterPage />} />
            <Route path="/first-login" element={<FirstLoginPage />} />
            <Route path="/recover" element={<RecoverPage />} />
            <Route path="/authorize" element={<AuthorizePage />} />
            <Route
              element={
                <RequireSession>
                  <AccountShell />
                </RequireSession>
              }
            >
              <Route index element={<LauncherPage />} />
              <Route path="/settings/account" element={<AccountSettingsPage />} />
              <Route path="/settings/security" element={<SecurityPage />} />
              <Route path="/settings/sessions" element={<SessionsPage />} />
              <Route path="/settings/devices" element={<DevicesPage />} />
              <Route path="*" element={<NotFoundPage />} />
            </Route>
          </Routes>
        </Boot>
        {/* Outside the routes so a toast survives the navigation after a save. */}
        <Toaster />
      </TooltipProvider>
    </BrowserRouter>
  )
}
