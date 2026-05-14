import { useTranslation } from 'react-i18next'
import { useNavigate } from 'react-router-dom'
import { Icon, ICONS } from '@/components/mobile/Icon'
import { MobileAccountSubPage } from '@/pages/mobile/account/MobileAccountSubPage'
import { Surface } from '@/components/ui/surface'
import { PressableRow } from '@/components/ui/pressable-row'
import { useAppSelector } from '@/store'

/**
 * MobileSecurityPage — `/drive/account/security`.
 *
 * Surfaces the two-factor (TOTP) status and a link to the devices list. The
 * full setup flow (QR code, recovery codes, revoke devices) lives on the
 * desktop /settings page for now; PR 11 will inline-port the TOTP setup
 * wizard to a mobile-native bottom sheet.
 */
export default function MobileSecurityPage() {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const auth = useAppSelector((s) => s.auth)
  const totpOn = !!auth.totpEnabled

  return (
    <MobileAccountSubPage title={t('mobile.account.security', 'Security')}>
      <Surface className="mb-4">
        <PressableRow
          onClick={() => navigate('/settings')}
          last={false}
          ariaLabel={t('settings.totp.title', 'Two-Factor Authentication')}
        >
          <div className="w-8 h-8 rounded-[10px] bg-surface-sunken text-text-secondary flex items-center justify-center shrink-0">
            <Icon d={ICONS.shield} size={16} />
          </div>
          <div className="flex-1 min-w-0">
            <div className="text-sm font-medium text-text-primary">
              {t('mobile.account.security.totp', 'Two-factor authentication')}
            </div>
            <div className={'text-[12px] mt-0.5 ' + (totpOn ? 'text-success' : 'text-text-tertiary')}>
              {totpOn
                ? t('mobile.account.security.totpOn', 'Enabled')
                : t('mobile.account.security.totpOff', 'Not enabled')}
            </div>
          </div>
          <Icon d={ICONS.chevronRight} size={16} color="var(--text-tertiary)" />
        </PressableRow>
        <PressableRow onClick={() => navigate('/settings')} last>
          <div className="w-8 h-8 rounded-[10px] bg-surface-sunken text-text-secondary flex items-center justify-center shrink-0">
            <Icon d={ICONS.lock} size={16} />
          </div>
          <div className="flex-1 min-w-0">
            <div className="text-sm font-medium text-text-primary">
              {t('mobile.account.security.devices', 'Trusted devices')}
            </div>
            <div className="text-[12px] text-text-tertiary mt-0.5">
              {t('mobile.account.security.devicesSub', 'Browser tabs and CLI sessions')}
            </div>
          </div>
          <Icon d={ICONS.chevronRight} size={16} color="var(--text-tertiary)" />
        </PressableRow>
      </Surface>

      <p className="text-[12px] text-text-tertiary px-1">
        {t(
          'mobile.account.security.note',
          'Full setup (QR code, recovery codes, device revocation) is on the desktop Settings page for now.',
        )}
      </p>
    </MobileAccountSubPage>
  )
}
