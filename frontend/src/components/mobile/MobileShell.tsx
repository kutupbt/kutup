import type { ReactNode } from 'react'
import { MobileBottomNav } from '@/components/mobile/MobileBottomNav'
import { useTrash } from '@/hooks/useTrash'
import { cn } from '@/lib/utils'

/**
 * MobileShell — page wrapper used by the four mobile-only tab pages.
 *
 * Provides the full-viewport flex column, the bottom nav, and the
 * scroll-padding adjustment so the last list item never sits behind the
 * bottom nav.
 *
 * The page content (header + scroll body) is passed as children. The shell
 * does NOT render the page header itself — that's the page's responsibility
 * (so each page can opt into large-title vs back-button vs search-input
 * variants without prop-tunneling).
 *
 * Mobile pages should structure children like:
 *
 *   <MobileShell>
 *     <MobilePageHeader title="My Files" large />
 *     <div className="flex-1 overflow-auto px-3.5 pt-3 pb-24">
 *       ...content...
 *     </div>
 *     {sheets}
 *   </MobileShell>
 *
 * The `pb-24` (~96px) clears the bottom nav + the iOS home indicator inset.
 */
interface MobileShellProps {
  children: ReactNode
  /** Hide the bottom nav (e.g. inside a modal-shaped flow). Default false. */
  hideNav?: boolean
  className?: string
}

export function MobileShell({ children, hideNav, className }: MobileShellProps) {
  const trash = useTrash()

  return (
    <div
      className={cn(
        'fixed inset-0 flex flex-col bg-background text-text-primary overflow-hidden',
        className,
      )}
    >
      {children}
      {!hideNav && (
        <MobileBottomNav badges={{ trash: trash.count > 0 ? trash.count : null }} />
      )}
    </div>
  )
}
