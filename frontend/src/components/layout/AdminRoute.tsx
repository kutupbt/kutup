import { Navigate, Outlet } from 'react-router-dom'
import { useAppSelector } from '@/store'
import { selectIsAdmin } from '@/store/authSlice'

export default function AdminRoute() {
  const isAdmin = useAppSelector(selectIsAdmin)
  if (!isAdmin) return <Navigate to="/drive" replace />
  return <Outlet />
}
