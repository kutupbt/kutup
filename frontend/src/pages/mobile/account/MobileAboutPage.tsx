import { useTranslation } from 'react-i18next'
import { Icon, ICONS } from '@/components/mobile/Icon'
import { KutupLogo } from '@/components/KutupLogo'
import { MobileAccountSubPage } from '@/pages/mobile/account/MobileAccountSubPage'
import { Surface } from '@/components/ui/surface'
import { PressableRow } from '@/components/ui/pressable-row'

/**
 * MobileAboutPage — `/drive/account/about`.
 *
 * Static info: version, brand tagline, and links to source / privacy /
 * license. The version string comes from the build-time `VITE_APP_VERSION`
 * env (set by Vite); if missing it falls back to "dev".
 */
export default function MobileAboutPage() {
  const { t } = useTranslation()
  // Vite's import.meta.env is typed via vite/client but kutup hasn't added
  // that triple-slash reference; cast through unknown to keep tsc happy.
  const env = (import.meta as unknown as { env?: Record<string, string> }).env
  const version = env?.VITE_APP_VERSION ?? 'dev'

  return (
    <MobileAccountSubPage title={t('mobile.account.about', 'About Kutup')}>
      <div className="flex flex-col items-center text-center py-6 mb-3">
        <KutupLogo size={56} />
        <div className="mt-3 text-[18px] font-semibold text-text-primary">Kutup</div>
        <div className="text-[12px] text-text-tertiary mt-1">
          {t('mobile.account.tagline', 'Kutup · End-to-end encrypted drive')}
        </div>
        <div className="mt-3 inline-flex items-center gap-1.5 px-2.5 py-1 bg-surface-sunken rounded-[10px]">
          <span className="text-[11.5px] font-mono text-text-tertiary">v{version}</span>
        </div>
      </div>

      <Surface>
        <PressableRow
          onClick={() => window.open('https://github.com/kutupbulut/kutup', '_blank', 'noopener')}
          last={false}
          ariaLabel={t('mobile.account.about.source', 'Source code')}
        >
          <div className="w-8 h-8 rounded-[10px] bg-surface-sunken text-text-secondary flex items-center justify-center shrink-0">
            <Icon d={ICONS.globe} size={16} />
          </div>
          <div className="flex-1 min-w-0">
            <div className="text-sm font-medium text-text-primary">
              {t('mobile.account.about.source', 'Source code')}
            </div>
            <div className="text-[12px] text-text-tertiary mt-0.5">github.com/kutupbulut/kutup</div>
          </div>
          <Icon d={ICONS.chevronRight} size={16} color="var(--text-tertiary)" />
        </PressableRow>
        <PressableRow
          onClick={() =>
            window.open(
              'https://github.com/kutupbulut/kutup/blob/master/TRADEMARK.md',
              '_blank',
              'noopener',
            )
          }
          last={false}
          ariaLabel={t('mobile.account.about.trademark', 'Brand policy')}
        >
          <div className="w-8 h-8 rounded-[10px] bg-surface-sunken text-text-secondary flex items-center justify-center shrink-0">
            <Icon d={ICONS.shield} size={16} />
          </div>
          <div className="flex-1 min-w-0">
            <div className="text-sm font-medium text-text-primary">
              {t('mobile.account.about.trademark', 'Brand policy')}
            </div>
            <div className="text-[12px] text-text-tertiary mt-0.5">TRADEMARK.md</div>
          </div>
          <Icon d={ICONS.chevronRight} size={16} color="var(--text-tertiary)" />
        </PressableRow>
        <PressableRow
          onClick={() =>
            window.open(
              'https://github.com/kutupbulut/kutup/blob/master/LICENSE',
              '_blank',
              'noopener',
            )
          }
          last
          ariaLabel={t('mobile.account.about.license', 'License')}
        >
          <div className="w-8 h-8 rounded-[10px] bg-surface-sunken text-text-secondary flex items-center justify-center shrink-0">
            <Icon d={ICONS.info} size={16} />
          </div>
          <div className="flex-1 min-w-0">
            <div className="text-sm font-medium text-text-primary">
              {t('mobile.account.about.license', 'License')}
            </div>
            <div className="text-[12px] text-text-tertiary mt-0.5">AGPL-3.0</div>
          </div>
          <Icon d={ICONS.chevronRight} size={16} color="var(--text-tertiary)" />
        </PressableRow>
      </Surface>
    </MobileAccountSubPage>
  )
}
