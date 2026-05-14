import type { ReactNode } from 'react'
import { useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { MobileShell } from '@/components/mobile/MobileShell'
import { MobilePageHeader } from '@/components/mobile/MobilePageHeader'
import { useIsMobile } from '@/hooks/useIsMobile'

/**
 * Shared chrome for every mobile Account sub-page (Profile / Encryption
 * keys / Security / Notifications / Language / Admin / About).
 *
 * Each sub-page wraps its body content in this — title + Back button + safe-
 * area-aware shell + bottom-nav. Desktop redirects to `/settings` (the
 * existing desktop Settings page covers the same surface).
 */
interface MobileAccountSubPageProps {
  title: string
  /** Optional right-slot action (e.g. an info or save button). */
  right?: ReactNode
  children: ReactNode
}

export function MobileAccountSubPage({ title, right, children }: MobileAccountSubPageProps) {
  const navigate = useNavigate()
  const isMobile = useIsMobile()

  useEffect(() => {
    if (!isMobile) navigate('/settings', { replace: true })
  }, [isMobile, navigate])

  if (!isMobile) return null

  return (
    <MobileShell>
      <MobilePageHeader
        title={title}
        back
        onBack={() => navigate('/drive/account')}
        right={right}
      />
      <div className="flex-1 overflow-auto px-3.5 pt-3 pb-24">{children}</div>
    </MobileShell>
  )
}
