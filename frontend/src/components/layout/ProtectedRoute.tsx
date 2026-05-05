import { Navigate, Outlet, useLocation } from 'react-router-dom'
import { useAppSelector } from '@/store'
import { selectIsLoggedIn } from '@/store/authSlice'

export default function ProtectedRoute() {
  const isLoggedIn = useAppSelector(selectIsLoggedIn)
  const location = useLocation()
  if (!isLoggedIn) {
    const next = location.pathname + location.search
    const target = next === '/' || next === '/drive' ? '/login' : `/login?next=${encodeURIComponent(next)}`
    return <Navigate to={target} replace />
  }
  return <Outlet />
}
