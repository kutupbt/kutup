import { useTranslation } from 'react-i18next'
import { useNavigate } from 'react-router-dom'
import { Icon, ICONS } from '@/components/mobile/Icon'
import { MobileAccountSubPage } from '@/pages/mobile/account/MobileAccountSubPage'
import { Surface } from '@/components/ui/surface'
import { PressableRow } from '@/components/ui/pressable-row'

/**
 * MobileEncryptionKeysPage — `/drive/account/encryption-keys`.
 *
 * Surfaces the recovery-phrase flow. Kutup keeps the master key client-side
 * (encrypted with the user's password); the recovery phrase is the only way
 * to recover the account if the password is lost. This page links into the
 * existing /recover route for the rotation flow.
 */
export default function MobileEncryptionKeysPage() {
  const { t } = useTranslation()
  const navigate = useNavigate()

  return (
    <MobileAccountSubPage title={t('mobile.account.encryptionKeys', 'Encryption keys')}>
      <div className="flex flex-col items-center text-center py-4 mb-2">
        <div className="w-16 h-16 rounded-2xl bg-primary-faint flex items-center justify-center text-primary mb-3">
          <Icon d={ICONS.key} size={28} />
        </div>
        <div className="text-[16px] font-semibold text-text-primary">
          {t('mobile.account.encryptionKeys.heroTitle', 'Your keys, your data')}
        </div>
        <p className="text-[13px] text-text-tertiary mt-1.5 max-w-xs">
          {t(
            'mobile.account.encryptionKeys.heroBody',
            'Files are end-to-end encrypted with keys derived from your password. The 24-word recovery phrase is your only fallback if you forget it.',
          )}
        </p>
      </div>

      <Surface className="mb-4">
        <PressableRow
          onClick={() => navigate('/recover')}
          last={false}
          ariaLabel={t('mobile.account.encryptionKeys.viewRecovery', 'View recovery phrase')}
        >
          <div className="w-8 h-8 rounded-[10px] bg-surface-sunken text-text-secondary flex items-center justify-center shrink-0">
            <Icon d={ICONS.key} size={16} />
          </div>
          <div className="flex-1 min-w-0">
            <div className="text-sm font-medium text-text-primary">
              {t('mobile.account.encryptionKeys.viewRecovery', 'View recovery phrase')}
            </div>
            <div className="text-[12px] text-text-tertiary">
              {t('mobile.account.encryptionKeys.viewRecoverySub', 'Write down or print the 24 words')}
            </div>
          </div>
          <Icon d={ICONS.chevronRight} size={16} color="var(--text-tertiary)" />
        </PressableRow>
        <PressableRow
          onClick={() => navigate('/recover')}
          last
          ariaLabel={t('mobile.account.encryptionKeys.rotate', 'Rotate recovery phrase')}
        >
          <div className="w-8 h-8 rounded-[10px] bg-surface-sunken text-text-secondary flex items-center justify-center shrink-0">
            <Icon d={ICONS.rotateCcw} size={16} />
          </div>
          <div className="flex-1 min-w-0">
            <div className="text-sm font-medium text-text-primary">
              {t('mobile.account.encryptionKeys.rotate', 'Rotate recovery phrase')}
            </div>
            <div className="text-[12px] text-text-tertiary">
              {t(
                'mobile.account.encryptionKeys.rotateSub',
                'Generate a new phrase — invalidates the old one',
              )}
            </div>
          </div>
          <Icon d={ICONS.chevronRight} size={16} color="var(--text-tertiary)" />
        </PressableRow>
      </Surface>

      <p className="text-[12px] text-text-tertiary px-1">
        {t(
          'mobile.account.encryptionKeys.footer',
          'Kutup never sees your phrase — it stays on this device and the devices you sync it to.',
        )}
      </p>
    </MobileAccountSubPage>
  )
}
