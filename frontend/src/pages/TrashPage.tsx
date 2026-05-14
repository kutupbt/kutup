import { Navigate } from 'react-router-dom'
import { useIsMobile } from '@/hooks/useIsMobile'
import MobileTrashPage from '@/pages/mobile/MobileTrashPage'

/**
 * TrashPage — `/drive/trash` route handler.
 *
 * **Mobile (`<md:`)**: renders the design's full mobile page via
 * `MobileTrashPage` (large title + Empty button + empty-state hero).
 *
 * **Desktop (`md:`+)**: trash is an internal `viewMode` of `Drive.tsx` (lives
 * inside the same Sidebar + DriveTopBar chrome as My Files / Shared), so the
 * dedicated `/drive/trash` route is not used. Direct URL hits redirect to
 * `/drive`. The user navigates to trash by clicking the sidebar Trash row;
 * Drive's `viewMode` flips to `'trash'` and the main panel renders the trash
 * content.
 *
 * Keeping the route registered lets bookmark URLs from mobile still resolve
 * on desktop (just bouncing to the main drive view).
 */
export default function TrashPage() {
  const isMobile = useIsMobile()
  // useEffect-based redirect would flash content; render-time <Navigate>
  // bypasses any paint of the wrong shell on desktop.
  if (!isMobile) return <Navigate to="/drive" replace />
  return <MobileTrashPage />
}

