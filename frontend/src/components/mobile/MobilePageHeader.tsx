import type { ReactNode } from 'react'
import { Icon, ICONS } from '@/components/mobile/Icon'
import { KutupLogo } from '@/components/KutupLogo'
import { useTranslation } from 'react-i18next'
import { cn } from '@/lib/utils'

/**
 * MobilePageHeader — direct port of the design's `PageHeader`.
 *
 * Two layouts:
 *   - **Standard**: sticky 48-tall nav-bar with the Kutup logo on the left
 *     (or a Back chevron when `back` is set), centered title, and a `right`
 *     action slot.
 *   - **Large title**: same nav-bar with the title text hidden; below it a
 *     huge 28px / 700 title plus optional subtitle. The "iOS large title".
 *     Used on root pages (Files / Shared / Trash / Account) when not in
 *     search mode.
 *
 * The safe-area top inset is added via `pt-safe` so the system status bar
 * (clock / battery / Dynamic Island) doesn't overlap.
 */
interface MobilePageHeaderProps {
  title: string
  /** Optional subtitle — only used when `large` is true. */
  subtitle?: string
  /** Render the iOS large-title pattern below the nav-bar. */
  large?: boolean
  /** Show a Back button instead of the Kutup logo. */
  back?: boolean
  onBack?: () => void
  /** Action icons rendered on the right (typically 1-2 `<IconButton>`s). */
  right?: ReactNode
  className?: string
}

export function MobilePageHeader({
  title,
  subtitle,
  large,
  back,
  onBack,
  right,
  className,
}: MobilePageHeaderProps) {
  const { t } = useTranslation()

  return (
    <header
      className={cn(
        'sticky top-0 z-20 bg-surface border-b border-border-light pt-safe',
        className,
      )}
    >
      <div className="flex items-center min-h-12 px-1.5">
        {back ? (
          <button
            type="button"
            onClick={onBack}
            className="flex items-center gap-0.5 bg-transparent border-0 cursor-pointer text-primary py-1.5 px-2 text-[15px] font-medium"
          >
            <Icon d={ICONS.chevronLeft} size={20} />
            <span>{t('mobile.back', 'Back')}</span>
          </button>
        ) : (
          <div className="w-14 pl-3.5 flex items-center gap-1.5">
            <KutupLogo size={20} />
          </div>
        )}
        <div className="flex-1 text-center text-[15px] font-semibold text-text-primary min-w-0 px-2 truncate">
          {large ? '' : title}
        </div>
        <div className="flex items-center gap-0.5 pr-1.5">{right}</div>
      </div>
      {large && (
        <div className="pt-1 px-4.5 pb-3">
          <div className="text-[28px] font-bold text-text-primary tracking-[-0.5px]">
            {title}
          </div>
          {subtitle && (
            <div className="text-[13px] text-text-tertiary mt-0.5">{subtitle}</div>
          )}
        </div>
      )}
    </header>
  )
}
