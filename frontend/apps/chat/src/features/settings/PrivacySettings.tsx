import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useChat } from '../../app/chatStore'
import {
  setAlwaysRelayCalls,
  setLinkPreviews,
  setReadReceipts,
  useAlwaysRelayCalls,
  useLinkPreviews,
  useReadReceipts,
} from '../../state/prefs'
import { SettingsSection } from './SettingsPage'
import { Toggle } from './Toggle'

/**
 * Read receipts (off unless turned on; delivery receipts are automatic) and
 * link previews (on, when the server offers them).
 */
export function PrivacySettings() {
  const { t } = useTranslation()
  const { capabilities, service } = useChat()
  const readReceipts = useReadReceipts()
  const linkPreviews = useLinkPreviews()
  const alwaysRelay = useAlwaysRelayCalls()
  const [relay, setRelay] = useState(false)
  useEffect(() => {
    let cancelled = false
    service
      ?.callServers()
      .then((servers) => !cancelled && setRelay(servers.relay))
      .catch(() => undefined)
    return () => {
      cancelled = true
    }
  }, [service])
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
        {relay ? (
          <Toggle
            checked={alwaysRelay}
            onChange={setAlwaysRelayCalls}
            title={t('chat.calls.alwaysRelay')}
            description={t('chat.calls.alwaysRelayDescription')}
            testId="chat-always-relay-toggle"
          />
        ) : null}
      </div>
    </SettingsSection>
  )
}
