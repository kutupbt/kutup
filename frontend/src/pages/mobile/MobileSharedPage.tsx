import { useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { MobileShell } from '@/components/mobile/MobileShell'
import { MobilePageHeader } from '@/components/mobile/MobilePageHeader'
import { Icon, ICONS } from '@/components/mobile/Icon'
import { IconButton } from '@/components/ui/icon-button'
import { EmptyState } from '@/components/ui/empty-state'
import { useIsMobile } from '@/hooks/useIsMobile'

/**
 * MobileSharedPage — mobile-only `/drive/shared` route.
 *
 * PR 2 ships the layout + empty state. The "Shared with me" data wiring uses
 * the existing Drive shared collections API and lands in PR 5 (per the
 * roadmap). For now this page shows the large title + "Recently shared by me"
 * empty hero so the navigation surface is reachable.
 *
 * Desktop redirect: kutup desktop already exposes "Shared with Me" as an
 * internal Drive state via the sidebar — this route bounces back to `/drive`
 * when the viewport is desktop-sized.
 */
export default function MobileSharedPage() {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const isMobile = useIsMobile()

  useEffect(() => {
    if (!isMobile) navigate('/drive', { replace: true })
  }, [isMobile, navigate])

  if (!isMobile) return null

  return (
    <MobileShell>
      <MobilePageHeader
        title={t('nav.shared', 'Shared')}
        subtitle={t('mobile.shared.subtitle', '{{n}} shared with you', { n: 0 })}
        large
        right={
          <IconButton
            icon="search"
            ariaLabel={t('mobile.files.search.placeholder', 'Search in Kutup…')}
          />
        }
      />
      <div className="flex-1 overflow-auto px-3.5 pt-3 pb-24">
        <EmptyState
          icon="users"
          title={t('mobile.shared.empty.title', 'Nothing shared yet')}
          subtitle={t(
            'mobile.shared.empty.subtitle',
            'Send a file to anyone — even without a Kutup account',
          )}
          tint="primary"
        >
          <div className="text-[12px] text-text-tertiary mt-4 flex items-center gap-1">
            <Icon d={ICONS.share} size={12} />
            <span>{t('mobile.shared.empty.hint', 'Open a file and tap Share to start')}</span>
          </div>
        </EmptyState>
      </div>
    </MobileShell>
  )
}
