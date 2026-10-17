import { useTranslation } from 'react-i18next'
import { appUrl } from '@kutup/session/apps'

/**
 * The account has 20 devices in use, so this browser gets none to edit with
 * (docs/plans/device-registration.md): the user removes one themselves under
 * Account → Devices. Nothing is removed for them.
 */
export function DeviceLimitNotice() {
  const { t } = useTranslation()
  return (
    <div role="alert" className="flex flex-wrap items-center gap-2 border-b border-border bg-muted px-4 py-2 text-sm">
      <span>{t('editor.devices.tooMany')}</span>
      <a className="font-medium underline underline-offset-2" href={appUrl('account', '/settings/devices')}>
        {t('editor.devices.manage')}
      </a>
    </div>
  )
}
