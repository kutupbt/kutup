import { useEffect } from 'react'
import { BrowserRouter, Navigate, Route, Routes, useNavigate } from 'react-router-dom'
import { setUnauthenticatedHandler } from '@kutup/session/client'
import { Toaster } from '@kutup/ui/components/sonner'
import { TooltipProvider } from '@kutup/ui/components/tooltip'
import { AccountShell } from './app/AccountShell'
import { Boot } from './app/Boot'
import { RequireAdmin, RequireSession } from './app/guards'
import { ActivityPage } from './features/admin/ActivityPage'
import { FederationPage } from './features/admin/FederationPage'
import { NewUserPage } from './features/admin/NewUserPage'
import { MapsSettingsPage } from './features/admin/MapsSettingsPage'
import { ServerSettingsPage } from './features/admin/ServerSettingsPage'
import { UserPage } from './features/admin/UserPage'
import { UsersPage } from './features/admin/UsersPage'
import { AuthorizePage } from './features/auth/AuthorizePage'
import { FirstLoginPage } from './features/auth/FirstLoginPage'
import { LoginPage } from './features/auth/LoginPage'
import { RecoverPage } from './features/auth/RecoverPage'
import { RegisterPage } from './features/auth/RegisterPage'
import { LauncherPage } from './features/home/LauncherPage'
import { AccountSettingsPage } from './features/settings/AccountSettingsPage'
import { StoragePage } from './features/settings/StoragePage'
import { EncryptionKeysPage } from './features/keys/EncryptionKeysPage'
import { ProfilePage } from './features/settings/ProfilePage'
import { DevicesSessionsPage } from './features/settings/DevicesSessionsPage'
import { MapsPage } from './features/settings/MapsPage'
import { SecurityPage } from './features/settings/SecurityPage'
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
              <Route path="/settings/profile" element={<ProfilePage />} />
              <Route path="/settings/account" element={<AccountSettingsPage />} />
              <Route path="/settings/storage" element={<StoragePage />} />
              <Route path="/settings/keys" element={<EncryptionKeysPage />} />
              <Route path="/settings/security" element={<SecurityPage />} />
              <Route path="/settings/sessions" element={<Navigate to="/settings/devices" replace />} />
              <Route path="/settings/devices" element={<DevicesSessionsPage />} />
              <Route path="/settings/maps" element={<MapsPage />} />
              <Route path="/admin" element={<Navigate to="/admin/users" replace />} />
              <Route path="/admin/users" element={<RequireAdmin><UsersPage /></RequireAdmin>} />
              <Route path="/admin/users/new" element={<RequireAdmin><NewUserPage /></RequireAdmin>} />
              <Route path="/admin/users/:id" element={<RequireAdmin><UserPage /></RequireAdmin>} />
              <Route path="/admin/activity" element={<RequireAdmin><ActivityPage /></RequireAdmin>} />
              <Route path="/admin/federation" element={<RequireAdmin><FederationPage /></RequireAdmin>} />
              <Route path="/admin/settings" element={<RequireAdmin><ServerSettingsPage /></RequireAdmin>} />
              <Route path="/admin/maps" element={<RequireAdmin><MapsSettingsPage /></RequireAdmin>} />
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
