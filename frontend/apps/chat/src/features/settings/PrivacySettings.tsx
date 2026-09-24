import { useTranslation } from 'react-i18next'
import { Checkbox } from '@kutup/ui/components/checkbox'
import { setReadReceipts, useReadReceipts } from '../../state/prefs'
import { SettingsSection } from './SettingsPage'

/** Read receipts (off unless turned on; delivery receipts are automatic). */
export function PrivacySettings() {
  const { t } = useTranslation()
  const enabled = useReadReceipts()
  return (
    <SettingsSection title={t('chat.settings.privacy')}>
      <label className="flex max-w-xl cursor-pointer items-start gap-3 rounded-lg border border-border p-4">
        <Checkbox
          checked={enabled}
          onCheckedChange={(value) => setReadReceipts(value === true)}
          className="mt-0.5"
          data-testid="chat-read-receipts-toggle"
        />
        <span>
          <span className="block text-sm font-medium">{t('chat.receipts.setting')}</span>
          <span className="mt-1 block text-sm text-muted-foreground">{t('chat.receipts.settingDescription')}</span>
        </span>
      </label>
    </SettingsSection>
  )
}
