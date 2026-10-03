import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useChat } from '../../app/chatStore'
import { cn } from '@kutup/ui/lib/cn'
import { DISAPPEARING_PRESETS } from '../../lib/disappearing'
import {
  setAlwaysRelayCalls,
  setDefaultTimerSeconds,
  setLinkPreviews,
  setReadReceipts,
  setTypingIndicators,
  useAlwaysRelayCalls,
  useDefaultTimerSeconds,
  useLinkPreviews,
  useReadReceipts,
  useTypingIndicators,
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
  const typingIndicators = useTypingIndicators()
  const defaultTimer = useDefaultTimerSeconds()
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
        <Toggle
          checked={typingIndicators}
          onChange={setTypingIndicators}
          title={t('chat.typing.setting')}
          description={t('chat.typing.settingDescription')}
          testId="chat-typing-indicators-toggle"
        />
        <fieldset className="rounded-lg border border-border p-4" data-testid="chat-default-timer">
          <legend className="px-1 text-sm font-medium">{t('chat.disappearing.defaultTitle')}</legend>
          <p className="mb-3 text-sm text-muted-foreground">{t('chat.disappearing.defaultDescription')}</p>
          <div className="grid grid-cols-2 gap-2 sm:grid-cols-3">
            {DISAPPEARING_PRESETS.map((option) => {
              const seconds = option.seconds ?? 0
              return (
                <button
                  key={option.id}
                  type="button"
                  onClick={() => setDefaultTimerSeconds(seconds)}
                  aria-pressed={defaultTimer === seconds}
                  className={cn(
                    'rounded-md border px-3 py-2 text-left text-sm transition-colors',
                    defaultTimer === seconds ? 'border-primary bg-accent font-medium' : 'border-border hover:bg-muted',
                  )}
                  data-testid={`chat-default-timer-${option.id}`}
                >
                  {t(`chat.disappearing.presets.${option.id}`)}
                </button>
              )
            })}
          </div>
        </fieldset>
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
