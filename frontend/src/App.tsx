import { useState, useEffect } from 'react'
import axios from 'axios'
import { Loader2 } from 'lucide-react'
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { Toaster } from '@/components/ui/sonner'
import ProtectedRoute from '@/components/layout/ProtectedRoute'
import AdminRoute from '@/components/layout/AdminRoute'
import RouteErrorBoundary from '@/components/layout/RouteErrorBoundary'
import { useAppDispatch, useAppSelector } from '@/store'
import { store } from '@/store'
import { selectMasterKey, setAuth, updateAccessToken, setColor, logout } from '@/store/authSlice'
import { broadcastSession, requestSession, startSessionResponder, startLogoutListener, startColorListener, type SessionPayload } from '@/lib/sessionSync'
import { isTauri } from '@/lib/isTauri'
import { resolveApiBase } from '@/lib/apiBase'
import { restoreSession, type RestoreRoute } from '@/lib/restoreSession'
import Login from './pages/Login'
import Register from './pages/Register'
import FirstLogin from './pages/FirstLogin'
import Recovery from './pages/Recovery'
import Drive from './pages/Drive'
import Admin from './pages/Admin'
import Settings from './pages/Settings'
import PublicShare from './pages/PublicShare'
import FileEditorPage from './pages/FileEditorPage'
import ServerSelect from './pages/ServerSelect'
import TrashPage from './pages/TrashPage'
import MobileSharedPage from './pages/mobile/MobileSharedPage'
import MobileAccountPage from './pages/mobile/MobileAccountPage'
import MobileProfilePage from './pages/mobile/account/MobileProfilePage'
import MobileEncryptionKeysPage from './pages/mobile/account/MobileEncryptionKeysPage'
import MobileSecurityPage from './pages/mobile/account/MobileSecurityPage'
import MobileNotificationsPage from './pages/mobile/account/MobileNotificationsPage'
import MobileLanguagePage from './pages/mobile/account/MobileLanguagePage'
import MobileAdminPage from './pages/mobile/account/MobileAdminPage'
import MobileAboutPage from './pages/mobile/account/MobileAboutPage'

function snapshotFromState(): SessionPayload | null {
  const { auth } = store.getState()
  if (!auth.userId || !auth.masterKey) return null
  return {
    userId: auth.userId,
    email: auth.email,
    username: auth.username,
    accessToken: auth.accessToken,
    isAdmin: auth.isAdmin,
    storageQuotaBytes: auth.storageQuotaBytes,
    storageUsedBytes: auth.storageUsedBytes,
    totpEnabled: auth.totpEnabled,
    color: auth.color,
    currentDeviceId: auth.currentDeviceId,
    publicKey: auth.publicKey,
    masterKey: auth.masterKey,
    privateKey: auth.privateKey,
  }
}

export default function App() {
  const dispatch = useAppDispatch()
  const masterKey = useAppSelector(selectMasterKey)
  const accessToken = useAppSelector((s) => s.auth.accessToken)
  const [ready, setReady] = useState(false)
  // Tauri-only: where to land on first paint. `/` redirects here after
  // bootstrap completes. Web stays at `/drive` (existing behaviour).
  const [initialRoute, setInitialRoute] = useState<RestoreRoute>('/drive')

  useEffect(() => {
    let cancelled = false

    async function bootstrap() {
      // Warm the api-base cache before any route can mount a component that
      // talks to the API. Cheap on web (sync '/api') and one Store read in
      // Tauri.
      await resolveApiBase()

      if (isTauri) {
        // Tauri owns its own restore path: vault (OS keychain) holds the
        // secrets, Store-plugin holds the profile + serverUrl. No
        // BroadcastChannel — Tauri runs a single webview process.
        const r = await restoreSession()
        if (!cancelled) {
          setInitialRoute(r.route)
          setReady(true)
        }
        return
      }

      if (masterKey && !accessToken) {
        // Keys restored from sessionStorage but no access token — silently refresh
        // using the HTTP-only refresh token cookie (valid for 7 days).
        try {
          const res = await axios.post('/api/auth/refresh', {}, { withCredentials: true })
          if (!cancelled) dispatch(updateAccessToken(res.data.accessToken))
        } catch {
          if (!cancelled) dispatch(logout())
        }
      } else if (!masterKey) {
        // Fresh tab with no keys. Ask any other already-authenticated tab to
        // share its session via BroadcastChannel. Falls back to login if no
        // other tab responds within 500 ms.
        const payload = await requestSession(500)
        if (payload && !cancelled) {
          dispatch(setAuth({
            userId: payload.userId,
            email: payload.email ?? '',
            username: payload.username ?? undefined,
            accessToken: payload.accessToken ?? '',
            masterKey: new Uint8Array(payload.masterKey ?? []),
            privateKey: new Uint8Array(payload.privateKey ?? []),
            publicKey: payload.publicKey ?? '',
            isAdmin: payload.isAdmin,
            storageQuotaBytes: payload.storageQuotaBytes,
            storageUsedBytes: payload.storageUsedBytes,
            totpEnabled: payload.totpEnabled,
            color: payload.color,
          }))
        }
      }
      if (!cancelled) setReady(true)
    }

    bootstrap()
    return () => { cancelled = true }
  }, [])

  // BroadcastChannel responder — replies to other tabs requesting the session.
  useEffect(() => {
    return startSessionResponder(() => snapshotFromState())
  }, [])

  // BroadcastChannel logout listener — when any tab signs out, all tabs do.
  useEffect(() => {
    return startLogoutListener(() => dispatch(logout()))
  }, [dispatch])

  // BroadcastChannel color listener — when any tab updates its presence
  // color, mirror it locally so OO's foreign-cursor renderer picks up the
  // new value via window.APP.getUserColor without a reload.
  useEffect(() => {
    return startColorListener((color) => dispatch(setColor(color)))
  }, [dispatch])

  // Re-broadcast whenever auth state materially changes so passive listeners
  // (e.g. a tab that joined just before we logged in) get the fresh snapshot.
  useEffect(() => {
    if (masterKey && accessToken) {
      const snap = snapshotFromState()
      if (snap) broadcastSession(snap)
    }
  }, [masterKey, accessToken])

  if (!ready) {
    return (
      <div className="flex min-h-screen items-center justify-center">
        <Loader2 className="h-8 w-8 animate-spin text-primary" />
      </div>
    )
  }

  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<Navigate to={initialRoute} replace />} />
        <Route path="/server-select" element={<ServerSelect />} />
        <Route path="/login" element={<Login />} />
        <Route path="/register" element={<Register />} />
        <Route path="/first-login" element={<FirstLogin />} />
        <Route path="/recover" element={<Recovery />} />

        <Route element={<ProtectedRoute />} errorElement={<RouteErrorBoundary />}>
          <Route path="/drive" element={<Drive />} />
          {/* Mobile-only bottom-tab sibling routes — desktop redirects via useIsMobile.
              `/drive/trash` is served on both; the page forks its layout. */}
          <Route path="/drive/shared" element={<MobileSharedPage />} />
          <Route path="/drive/trash" element={<TrashPage />} />
          <Route path="/drive/account" element={<MobileAccountPage />} />
          {/* Mobile Account sub-pages — each row has its own page so
              "Profile" / "Encryption keys" / "Security" / etc. open
              dedicated screens instead of all bouncing to /settings.
              Desktop hits to these redirect to /settings via
              MobileAccountSubPage. */}
          <Route path="/drive/account/profile" element={<MobileProfilePage />} />
          <Route path="/drive/account/encryption-keys" element={<MobileEncryptionKeysPage />} />
          <Route path="/drive/account/security" element={<MobileSecurityPage />} />
          <Route path="/drive/account/notifications" element={<MobileNotificationsPage />} />
          <Route path="/drive/account/language" element={<MobileLanguagePage />} />
          <Route path="/drive/account/admin" element={<MobileAdminPage />} />
          <Route path="/drive/account/about" element={<MobileAboutPage />} />
          <Route path="/file/:cid/:fid" element={<FileEditorPage />} />
          <Route path="/settings" element={<Settings />} />
          <Route element={<AdminRoute />}>
            <Route path="/admin" element={<Admin />} />
          </Route>
        </Route>

        <Route path="/s/:token" element={<PublicShare />} />
      </Routes>
      <Toaster richColors closeButton />
    </BrowserRouter>
  )
}
