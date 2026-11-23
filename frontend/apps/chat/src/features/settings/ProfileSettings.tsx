import { Copy, ExternalLink, Lock } from 'lucide-react'
import { QRCodeSVG } from 'qrcode.react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { contactUri } from '@kutup/chat-core/identity'
import { appUrl } from '@kutup/session/apps'
import { Avatar } from '@kutup/ui/components/avatar'
import { Button } from '@kutup/ui/components/button'
import { useChat } from '../../app/chatStore'
import { SettingsSection } from './SettingsPage'

/**
 * Your profile as your contacts see it, and your address to give out. The
 * profile is the account's one profile, edited in the account app
 * (docs/plans/unified-profile.md); this tab takes a new version as soon as
 * it regains focus.
 */
export function ProfileSettings() {
  const { t } = useTranslation()
  const { snapshot, self } = useChat()
  const profile = snapshot.profile
  const address = self!.address

  return (
    <div className="space-y-10">
      <SettingsSection title={t('chat.profile.title')} description={t('chat.profile.description')}>
        <div className="flex max-w-xl items-center gap-4 rounded-lg border border-border p-4" data-testid="chat-profile-preview">
          <Avatar name={profile?.displayName || address} image={profile?.avatar} contentType={profile?.avatarContentType} size={48} />
          <div className="min-w-0 flex-1">
            <p className="truncate font-medium" data-testid="chat-profile-name">{profile?.displayName || address}</p>
            {profile?.about ? <p className="truncate text-sm text-muted-foreground">{profile.about}</p> : null}
          </div>
          <Button asChild variant="outline" size="sm">
            <a href={appUrl('account', '/settings/profile')} data-testid="chat-profile-edit">
              <ExternalLink />
              {t('chat.profile.edit')}
            </a>
          </Button>
        </div>
        <p className="flex max-w-xl items-start gap-2 text-sm text-muted-foreground">
          <Lock className="mt-0.5 size-4 shrink-0" aria-hidden />
          {t('chat.profile.visibility')}
        </p>
      </SettingsSection>

      <SettingsSection title={t('chat.contact.title')} description={t('chat.contact.description')}>
        <div className="flex flex-col items-start gap-4 sm:flex-row sm:items-center">
          <div className="rounded-xl border border-border bg-white p-3">
            <QRCodeSVG value={contactUri(self!.account)} size={168} aria-label={t('chat.contact.qr')} />
          </div>
          <div className="space-y-3">
            <code className="block break-all rounded-md bg-muted px-3 py-2 font-mono text-sm">{address}</code>
            <Button
              type="button"
              variant="outline"
              onClick={() => {
                void navigator.clipboard
                  .writeText(address)
                  .then(() => toast.success(t('chat.contact.copied')))
                  .catch(() => toast.error(t('chat.message.copyFailed')))
              }}
            >
              <Copy />
              {t('chat.contact.copy')}
            </Button>
          </div>
        </div>
      </SettingsSection>
    </div>
  )
}
