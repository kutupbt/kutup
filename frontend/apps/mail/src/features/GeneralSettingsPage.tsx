import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { PAGE_SIZES, useMailSettings, useUpdateMailSettings, type MailSettings } from '@kutup/mail-core/api'
import { Alert } from '@kutup/ui/components/alert'
import { Checkbox } from '@kutup/ui/components/checkbox'
import { PageBody, PageHeader } from '@kutup/ui/components/page'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@kutup/ui/components/select'
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

/** Settings → General (Proton's Messages section, and its External PGP settings): conversation grouping, page size, auto-delete, All mail; signing, the attached key and the PGP scheme for outside mail. */
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
          label={t('general.conversations')}
          hint={t('general.conversationsHint')}
          checked={settings.data.viewMode === 'conversation'}
          onChange={(on) => save({ viewMode: on ? 'conversation' : 'message' })}
        />
        <div className="flex flex-col gap-3 rounded-lg border border-border p-4 sm:flex-row sm:items-center sm:justify-between">
          <label htmlFor="page-size" className="block text-sm font-medium">
            {settings.data.viewMode === 'conversation' ? t('general.pageSizeConversations') : t('general.pageSizeMessages')}
          </label>
          <Select value={String(settings.data.pageSize)} onValueChange={(size) => save({ pageSize: Number(size) })}>
            <SelectTrigger id="page-size" className="sm:w-48">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {PAGE_SIZES.map((size) => (
                <SelectItem key={size} value={String(size)}>
                  {size}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
        <Setting
          label={t('general.confirmLink')}
          hint={t('general.confirmLinkHint')}
          checked={settings.data.confirmLink}
          onChange={(on) => save({ confirmLink: on })}
        />
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
      </div>
      <section className="mt-8 space-y-3" aria-labelledby="pgp-heading">
        <h2 id="pgp-heading" className="text-sm font-medium">
          {t('general.pgpTitle')}
        </h2>
        <p className="text-sm text-muted-foreground">{t('general.pgpHint')}</p>
        <Setting
          label={t('general.signOutside')}
          hint={t('general.signOutsideHint')}
          checked={settings.data.signOutside}
          onChange={(on) => save({ signOutside: on })}
        />
        <Setting
          label={t('general.attachPublicKey')}
          hint={t('general.attachPublicKeyHint')}
          checked={settings.data.attachPublicKey}
          onChange={(on) => save({ attachPublicKey: on })}
        />
        <div className="flex flex-col gap-3 rounded-lg border border-border p-4 sm:flex-row sm:items-center sm:justify-between">
          <span>
            <label htmlFor="pgp-scheme" className="block text-sm font-medium">
              {t('general.pgpScheme')}
            </label>
            <span className="block text-sm text-muted-foreground">{t('general.pgpSchemeHint')}</span>
          </span>
          <Select value={settings.data.pgpScheme} onValueChange={(pgpScheme) => save({ pgpScheme: pgpScheme as MailSettings['pgpScheme'] })}>
            <SelectTrigger id="pgp-scheme" className="sm:w-48" aria-label={t('general.pgpScheme')}>
              <SelectValue placeholder={t('general.pgpScheme')} />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="pgp_mime">PGP/MIME</SelectItem>
              <SelectItem value="inline">{t('general.inline')}</SelectItem>
            </SelectContent>
          </Select>
        </div>
      </section>
    </PageBody>
  )
}
