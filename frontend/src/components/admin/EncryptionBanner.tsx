import { useTranslation } from 'react-i18next'
import { Icon, ICONS } from '@/components/mobile/Icon'

/**
 * EncryptionBanner — green "End-to-end encrypted" reassurance hero shown
 * on the admin Overview tab. Same pattern as the mobile admin's E2E note,
 * scaled up for desktop. The message is the same on every kutup instance:
 * admins can manage accounts but cannot read user data.
 */
export function EncryptionBanner() {
  const { t } = useTranslation()
  return (
    <div className="flex gap-3 p-3 bg-success-faint border border-success/30 rounded-[var(--radius-lg)]">
      <div
        className="w-[34px] h-[34px] rounded-[10px] flex items-center justify-center shrink-0 bg-success/15 text-success"
        aria-hidden="true"
      >
        <Icon d={ICONS.lock} size={16} />
      </div>
      <div className="min-w-0">
        <div className="text-[13px] font-semibold text-success">
          {t('admin.encryption.title', 'End-to-end encrypted')}
        </div>
        <div className="text-[12px] text-success/80 mt-0.5">
          {t(
            'admin.encryption.body',
            'File names and contents are encrypted on every device. Admins can manage accounts but cannot read user data.',
          )}
        </div>
      </div>
    </div>
  )
}
