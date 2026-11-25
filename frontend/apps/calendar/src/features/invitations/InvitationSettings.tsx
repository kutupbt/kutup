import { useQuery, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { loadInviteSettings, saveInviteSettings, type InviteSettings } from '@kutup/calendar-core/invitations'
import { Checkbox } from '@kutup/ui/components/checkbox'
import { Label } from '@kutup/ui/components/label'
import { apiErrorMessage } from '@kutup/ui/lib/apiError'
import { toast } from 'sonner'
import { Choice } from '../Choice'

/**
 * Proton's `CalendarInvitationsSection`: the language invitations and
 * replies are sent in ("Send in"), and "Add to calendar and mark as
 * pending" for invitations received. Kept on the account (the server's
 * `calendar_invite_settings`), so every device sends alike.
 */
export function InvitationSettings() {
  const { t } = useTranslation()
  const queryClient = useQueryClient()
  const settings = useQuery({ queryKey: ['calendar', 'invite-settings'], queryFn: loadInviteSettings, staleTime: 60_000 })
  const change = async (next: Partial<InviteSettings>) => {
    if (!settings.data) return
    try {
      await saveInviteSettings({ ...settings.data, ...next })
      await queryClient.invalidateQueries({ queryKey: ['calendar', 'invite-settings'] })
      toast.success(t('invitations.settings.saved'))
    } catch (error) {
      toast.error(apiErrorMessage(error, t('invitations.settings.failed')))
    }
  }
  if (!settings.data) return null
  return (
    <div className="space-y-4" data-testid="settings-invitations">
      <div className="space-y-1.5">
        <Label htmlFor="settings-invite-locale">{t('invitations.settings.sendIn')}</Label>
        <Choice
          id="settings-invite-locale"
          value={settings.data.inviteLocale ?? 'app'}
          options={[
            { value: 'app', label: t('invitations.settings.appLanguage') },
            { value: 'en', label: 'English' },
            { value: 'tr', label: 'Türkçe' },
          ]}
          onChange={(value) => void change({ inviteLocale: value === 'app' ? null : (value as 'en' | 'tr') })}
          testId="settings-invite-locale"
        />
        <p className="text-xs text-muted-foreground">{t('invitations.settings.sendInHint')}</p>
      </div>
      <div className="flex items-start gap-2">
        <Checkbox
          id="settings-auto-add"
          checked={settings.data.autoAdd}
          onCheckedChange={(checked) => void change({ autoAdd: checked === true })}
          data-testid="settings-auto-add"
        />
        <div className="space-y-0.5">
          <Label htmlFor="settings-auto-add">{t('invitations.settings.autoAdd')}</Label>
          <p className="text-xs text-muted-foreground">{t('invitations.settings.autoAddHint')}</p>
        </div>
      </div>
    </div>
  )
}
