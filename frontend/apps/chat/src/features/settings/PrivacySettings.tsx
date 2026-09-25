import type { ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import { Checkbox } from '@kutup/ui/components/checkbox'
import { useChat } from '../../app/chatStore'
import { setLinkPreviews, setReadReceipts, useLinkPreviews, useReadReceipts } from '../../state/prefs'
import { SettingsSection } from './SettingsPage'

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

function Toggle({
  checked,
  onChange,
  title,
  description,
  testId,
}: {
  checked: boolean
  onChange: (value: boolean) => void
  title: string
  description: ReactNode
  testId: string
}) {
  return (
    <label className="flex cursor-pointer items-start gap-3 rounded-lg border border-border p-4">
      <Checkbox checked={checked} onCheckedChange={(value) => onChange(value === true)} className="mt-0.5" data-testid={testId} />
      <span>
        <span className="block text-sm font-medium">{title}</span>
        <span className="mt-1 block text-sm text-muted-foreground">{description}</span>
      </span>
    </label>
  )
}
