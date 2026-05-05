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
import { selectMasterKey, setAuth, updateAccessToken, logout } from '@/store/authSlice'
import { broadcastSession, requestSession, startSessionResponder, type SessionPayload } from '@/lib/sessionSync'
import Login from './pages/Login'
import Register from './pages/Register'
import FirstLogin from './pages/FirstLogin'
import Recovery from './pages/Recovery'
import Drive from './pages/Drive'
import Admin from './pages/Admin'
import Settings from './pages/Settings'
import PublicShare from './pages/PublicShare'
import FileEditorPage from './pages/FileEditorPage'

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

  useEffect(() => {
    let cancelled = false

    async function bootstrap() {
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
        <Route path="/" element={<Navigate to="/drive" replace />} />
        <Route path="/login" element={<Login />} />
        <Route path="/register" element={<Register />} />
        <Route path="/first-login" element={<FirstLogin />} />
        <Route path="/recover" element={<Recovery />} />

        <Route element={<ProtectedRoute />} errorElement={<RouteErrorBoundary />}>
          <Route path="/drive" element={<Drive />} />
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
