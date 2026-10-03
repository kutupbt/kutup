import { useTranslation } from 'react-i18next'
import { PageBody, PageHeader } from '@kutup/ui/components/page'
import { ChatDevicesSection } from './ChatDevicesSection'
import { EditorKeysSection } from './EditorKeysSection'
import { SessionsSection } from './SessionsSection'

/**
 * Everything this account is signed in with, in one place
 * (docs/plans/unified-profile.md): browsers and the CLI, the browsers with
 * Chat, and the keys that sign collaborative edits.
 */
export function DevicesSessionsPage() {
  const { t } = useTranslation()
  return (
    <PageBody width="prose">
      <PageHeader title={t('settings.devicesSessions.title')} description={t('settings.devicesSessions.description')} />
      <div className="space-y-10">
        <SessionsSection />
        <ChatDevicesSection />
        <EditorKeysSection />
      </div>
    </PageBody>
  )
}
