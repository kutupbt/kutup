import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { useMailSettings, useUpdateMailSettings, type MailSettings } from '@kutup/mail-core/api'
import { Alert } from '@kutup/ui/components/alert'
import { Checkbox } from '@kutup/ui/components/checkbox'
import { PageBody, PageHeader } from '@kutup/ui/components/page'
import { LoadingPanel } from '@kutup/ui/components/states'
import { apiErrorMessage } from '@kutup/ui/lib/apiError'

function Setting({ label, hint, checked, onChange }: { label: string; hint: string; checked: boolean; onChange: (on: boolean) => void }) {
  return (
    <label className="flex items-start gap-3 rounded-lg border border-border p-4">
      <Checkbox className="mt-0.5" checked={checked} onCheckedChange={(on) => onChange(on === true)} />
      <span>
        <span className="block text-sm font-medium">{label}</span>
        <span className="block text-sm text-muted-foreground">{hint}</span>
      </span>
    </label>
  )
}

/** Settings → General (Proton's Messages section): auto-delete, All mail, Sign outside mail. */
export function GeneralSettingsPage() {
  const { t } = useTranslation()
  const settings = useMailSettings()
  const update = useUpdateMailSettings()
  if (settings.isPending) return <LoadingPanel label={t('common.loading')} />
  if (settings.isError) return <Alert variant="error">{apiErrorMessage(settings.error, t('common.tryAgain'))}</Alert>
  const save = (change: Partial<MailSettings>) =>
    update.mutate(change, {
      onSuccess: () => toast.success(t('general.saved')),
      onError: (error) => toast.error(apiErrorMessage(error, t('common.tryAgain'))),
    })
  return (
    <PageBody>
      <PageHeader title={t('general.title')} />
      <div className="space-y-3">
        <Setting
          label={t('general.autoDelete')}
          hint={t('general.autoDeleteHint')}
          checked={settings.data.autoDeleteDays === 30}
          onChange={(on) => save({ autoDeleteDays: on ? 30 : 0 })}
        />
        <Setting
          label={t('general.almostAllMail')}
          hint={t('general.almostAllMailHint')}
          checked={settings.data.almostAllMail}
          onChange={(on) => save({ almostAllMail: on })}
        />
        <Setting
          label={t('general.signOutside')}
          hint={t('general.signOutsideHint')}
          checked={settings.data.signOutside}
          onChange={(on) => save({ signOutside: on })}
        />
      </div>
    </PageBody>
  )
}
