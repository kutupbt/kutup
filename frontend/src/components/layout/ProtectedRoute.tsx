import { Navigate, Outlet } from 'react-router-dom'
import { useAppSelector } from '@/store'
import { selectIsLoggedIn } from '@/store/authSlice'

export default function ProtectedRoute() {
  const isLoggedIn = useAppSelector(selectIsLoggedIn)
  if (!isLoggedIn) return <Navigate to="/login" replace />
  return <Outlet />
}
