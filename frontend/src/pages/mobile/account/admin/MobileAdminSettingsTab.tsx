import { useTranslation } from 'react-i18next'
import { Icon, ICONS } from '@/components/mobile/Icon'
import { Surface } from '@/components/ui/surface'
import { useAdminSettings, useUpdateAdminSettings } from '@/api/hooks/useAdmin'

/**
 * MobileAdminSettingsTab — kutup's admin-settings surface today is just a
 * single boolean (`registrationEnabled`), so this tab is short:
 *
 *   Registration
 *     ▢ Public registration   [switch]
 *
 * The design's other groups (Defaults / Security / Storage backend /
 * Danger zone) need backend additions before we can ship them — see the
 * PR 12 section of the plan file for the full list. They're explicitly
 * NOT rendered here so the page doesn't lie about what the backend can do.
 */
export function MobileAdminSettingsTab() {
  const { t } = useTranslation()
  const { data: settings } = useAdminSettings()
  const update = useUpdateAdminSettings()

  const publicReg = !!settings?.registrationEnabled

  return (
    <div className="px-3.5 pt-4 pb-8">
      <div className="text-[11.5px] font-semibold tracking-[0.06em] uppercase text-text-tertiary px-1 pb-2">
        {t('mobile.admin.settings.registrationGroup', 'Registration')}
      </div>
      <Surface className="mb-4">
        <div className="flex items-center gap-3 px-3.5 py-3">
          <div className="w-[30px] h-[30px] rounded-[9px] bg-surface-sunken text-text-secondary flex items-center justify-center shrink-0">
            <Icon d={ICONS.userPlus} size={15} />
          </div>
          <div className="flex-1 min-w-0">
            <div className="text-[13.5px] font-medium text-text-primary">
              {t('mobile.admin.settings.publicReg', 'Public registration')}
            </div>
            <div className="text-[11.5px] text-text-tertiary mt-0.5">
              {t(
                'mobile.admin.settings.publicRegSub',
                'Anyone can create an account from the sign-up page',
              )}
            </div>
          </div>
          {/* iOS-style toggle */}
          <button
            type="button"
            role="switch"
            aria-checked={publicReg}
            onClick={() => update.mutate({ registrationEnabled: !publicReg })}
            disabled={update.isPending}
            className={
              'w-[42px] h-6 rounded-xl p-0.5 flex items-center transition-colors cursor-pointer shrink-0 ' +
              (publicReg ? 'bg-primary' : 'bg-border')
            }
          >
            <div
              className="w-5 h-5 rounded-full bg-white shadow-sm transition-transform"
              style={{ transform: publicReg ? 'translateX(18px)' : 'translateX(0)' }}
            />
          </button>
        </div>
      </Surface>

      <p className="text-[12px] text-text-tertiary px-1">
        {t(
          'mobile.admin.settings.moreSoonNote',
          'More admin controls — required 2FA, quota defaults, storage backend, danger-zone actions — land as the backend grows. The desktop /admin page covers anything missing here.',
        )}
      </p>
    </div>
  )
}
