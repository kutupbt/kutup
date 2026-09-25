import { useTranslation } from 'react-i18next'
import { useChat } from '../../app/chatStore'
import { setLinkPreviews, setReadReceipts, useLinkPreviews, useReadReceipts } from '../../state/prefs'
import { SettingsSection } from './SettingsPage'
import { Toggle } from './Toggle'

/**
 * Read receipts (off unless turned on; delivery receipts are automatic) and
 * link previews (on, when the server offers them).
 */
export function PrivacySettings() {
  const { t } = useTranslation()
  const { capabilities } = useChat()
  const readReceipts = useReadReceipts()
  const linkPreviews = useLinkPreviews()
  return (
    <SettingsSection title={t('chat.settings.privacy')}>
      <div className="max-w-xl space-y-3">
        <Toggle
          checked={readReceipts}
          onChange={setReadReceipts}
          title={t('chat.receipts.setting')}
          description={t('chat.receipts.settingDescription')}
          testId="chat-read-receipts-toggle"
        />
        {capabilities?.linkPreviews ? (
          <Toggle
            checked={linkPreviews}
            onChange={setLinkPreviews}
            title={t('chat.linkPreviews.setting')}
            description={t('chat.linkPreviews.settingDescription')}
            testId="chat-link-previews-toggle"
          />
        ) : null}
      </div>
    </SettingsSection>
  )
}
