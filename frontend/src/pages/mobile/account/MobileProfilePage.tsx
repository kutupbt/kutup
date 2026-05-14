import { useTranslation } from 'react-i18next'
import { MobileAccountSubPage } from '@/pages/mobile/account/MobileAccountSubPage'
import { Surface } from '@/components/ui/surface'
import { PressableRow } from '@/components/ui/pressable-row'
import { useAppSelector } from '@/store'

/**
 * MobileProfilePage — `/drive/account/profile`.
 *
 * Read-only summary of the authenticated user: avatar circle, email,
 * username, plan badge. Editing identity fields lives downstream (account-
 * service work is out of scope for PR 2); for now the page is informational.
 */
export default function MobileProfilePage() {
  const { t } = useTranslation()
  const auth = useAppSelector((s) => s.auth)

  const username = auth.username ?? auth.email ?? ''
  const email = auth.email ?? ''
  const initial = (username || '?').slice(0, 1).toUpperCase()

  return (
    <MobileAccountSubPage title={t('mobile.account.profile', 'Profile')}>
      {/* Avatar hero */}
      <div className="flex flex-col items-center text-center py-4">
        <div className="w-20 h-20 rounded-full bg-primary flex items-center justify-center text-[32px] font-bold text-white mb-3">
          {initial}
        </div>
        <div className="text-[17px] font-semibold text-text-primary">{username}</div>
        {email && username !== email && (
          <div className="text-[13px] text-text-tertiary mt-0.5">{email}</div>
        )}
      </div>

      <Surface className="mb-4">
        <PressableRow last={false}>
          <div className="flex-1 min-w-0">
            <div className="text-[12.5px] text-text-tertiary">
              {t('settings.account.email', 'Email')}
            </div>
            <div className="text-sm font-medium text-text-primary truncate">{email || '—'}</div>
          </div>
        </PressableRow>
        <PressableRow last>
          <div className="flex-1 min-w-0">
            <div className="text-[12.5px] text-text-tertiary">
              {t('settings.account.username', 'Username')}
            </div>
            <div className="text-sm font-medium text-text-primary truncate">
              {auth.username ? `@${auth.username}` : '—'}
            </div>
          </div>
        </PressableRow>
      </Surface>

      <p className="text-[12px] text-text-tertiary px-1">
        {t(
          'mobile.account.profile.note',
          'Account details are managed by your Kutup server. Contact your admin to change them.',
        )}
      </p>
    </MobileAccountSubPage>
  )
}
