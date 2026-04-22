import { BrowserRouter, Routes, Route, Navigate, Outlet } from 'react-router-dom'
import { Toaster } from '@/components/ui/sonner'
import ProtectedRoute from '@/components/layout/ProtectedRoute'
import AdminRoute from '@/components/layout/AdminRoute'
import RouteErrorBoundary from '@/components/layout/RouteErrorBoundary'
import Login from './pages/Login'
import Register from './pages/Register'
import FirstLogin from './pages/FirstLogin'
import Recovery from './pages/Recovery'
import Drive from './pages/Drive'
import Admin from './pages/Admin'
import Settings from './pages/Settings'
import PublicShare from './pages/PublicShare'

export default function App() {
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
