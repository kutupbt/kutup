import { useState, useEffect } from 'react'
import axios from 'axios'
import { Loader2 } from 'lucide-react'
import { BrowserRouter, Routes, Route, Navigate, Outlet } from 'react-router-dom'
import { Toaster } from '@/components/ui/sonner'
import ProtectedRoute from '@/components/layout/ProtectedRoute'
import AdminRoute from '@/components/layout/AdminRoute'
import RouteErrorBoundary from '@/components/layout/RouteErrorBoundary'
import { useAppDispatch, useAppSelector } from '@/store'
import { selectMasterKey, updateAccessToken, logout } from '@/store/authSlice'
import Login from './pages/Login'
import Register from './pages/Register'
import FirstLogin from './pages/FirstLogin'
import Recovery from './pages/Recovery'
import Drive from './pages/Drive'
import Admin from './pages/Admin'
import Settings from './pages/Settings'
import PublicShare from './pages/PublicShare'

export default function App() {
  const dispatch = useAppDispatch()
  const masterKey = useAppSelector(selectMasterKey)
  const accessToken = useAppSelector((s) => s.auth.accessToken)
  const [ready, setReady] = useState(false)

  useEffect(() => {
    if (masterKey && !accessToken) {
      // Keys restored from sessionStorage but no access token — silently refresh
      // using the HTTP-only refresh token cookie (valid for 7 days).
      // Use axios directly to avoid the api client's 401 interceptor.
      axios.post('/api/auth/refresh', {}, { withCredentials: true })
        .then((res) => dispatch(updateAccessToken(res.data.accessToken)))
        .catch(() => dispatch(logout()))
        .finally(() => setReady(true))
    } else {
      setReady(true)
    }
  }, [])

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
