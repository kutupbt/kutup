import { zodResolver } from '@hookform/resolvers/zod'
import { useEffect } from 'react'
import { Controller, useForm } from 'react-hook-form'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { z } from 'zod'
import { Alert } from '@kutup/ui/components/alert'
import { Button } from '@kutup/ui/components/button'
import { Card, CardContent } from '@kutup/ui/components/card'
import { Checkbox } from '@kutup/ui/components/checkbox'
import { Field } from '@kutup/ui/components/field'
import { Input } from '@kutup/ui/components/input'
import { Label } from '@kutup/ui/components/label'
import { PageBody, PageHeader, Section } from '@kutup/ui/components/page'
import { LoadingPanel } from '@kutup/ui/components/states'
import { apiErrorMessage } from '@kutup/ui/lib/apiError'
import { useAdminSettings, useUpdateAdminSettings } from './api'
import { bytesToGib, gibToBytes } from './helpers'

/** The server's bounds (site_settings::validate_chat_delivery_retention_days). */
const MAX_RETENTION_DAYS = 3650

export function ServerSettingsPage() {
  const { t } = useTranslation()
  const settings = useAdminSettings()
  const update = useUpdateAdminSettings()

  const days = z.coerce.number<number>().int(t('admin.settings.wholeDays')).min(0, t('admin.settings.retentionRange')).max(MAX_RETENTION_DAYS, t('admin.settings.retentionRange'))
  const schema = z.object({
    registrationEnabled: z.boolean(),
    quotaGib: z.coerce.number<number>().positive(t('admin.quota.positive')),
    mailboxDays: days,
    mediaDays: days,
  })
  const { register, control, handleSubmit, reset, formState: { errors, isDirty } } = useForm<z.infer<typeof schema>>({
    resolver: zodResolver(schema),
  })
  useEffect(() => {
    if (!settings.data) return
    reset({
      registrationEnabled: settings.data.registrationEnabled,
      quotaGib: bytesToGib(settings.data.defaultStorageQuotaBytes),
      mailboxDays: settings.data.chatMailboxRetentionDays,
      mediaDays: settings.data.chatMediaDeliveryRetentionDays,
    })
  }, [settings.data, reset])

  if (settings.isPending) return <LoadingPanel label={t('common.loading')} />
  if (settings.isError) {
    return <PageBody width="prose"><Alert variant="error">{apiErrorMessage(settings.error, t('common.tryAgain'))}</Alert></PageBody>
  }

  const onSubmit = handleSubmit((v) =>
    update.mutate(
      {
        registrationEnabled: v.registrationEnabled,
        defaultStorageQuotaBytes: gibToBytes(v.quotaGib),
        chatMailboxRetentionDays: v.mailboxDays,
        chatMediaDeliveryRetentionDays: v.mediaDays,
      },
      { onSuccess: () => toast.success(t('admin.settings.saved')) },
    ),
  )

  return (
    <PageBody width="prose">
      <PageHeader title={t('admin.settings.title')} description={t('admin.settings.description')} />
      <form className="space-y-6" onSubmit={(e) => void onSubmit(e)} noValidate>
        <Section title={t('admin.settings.accounts')}>
          <Card>
            <CardContent className="p-5">
              <div className="flex items-start gap-3">
                <Controller
                  control={control}
                  name="registrationEnabled"
                  render={({ field }) => (
                    <Checkbox id="registration" checked={field.value} onCheckedChange={(v) => field.onChange(v === true)} />
                  )}
                />
                <div className="space-y-1">
                  <Label htmlFor="registration">{t('admin.settings.registration')}</Label>
                  <p className="text-sm text-muted-foreground">{t('admin.settings.registrationHint')}</p>
                </div>
              </div>
              <div className="mt-5 max-w-xs">
                <Field label={t('admin.settings.defaultQuota')} error={errors.quotaGib?.message} description={t('admin.settings.defaultQuotaHint')} required>
                  {(field) => <Input {...field} {...register('quotaGib')} type="number" min={0.01} step="any" inputMode="decimal" />}
                </Field>
              </div>
            </CardContent>
          </Card>
        </Section>
        <Section title={t('admin.settings.chat')} description={t('admin.settings.chatHint')}>
          <Card>
            <CardContent className="grid gap-4 p-5 sm:grid-cols-2">
              <Field label={t('admin.settings.mailboxDays')} error={errors.mailboxDays?.message} description={t('admin.settings.mailboxDaysHint')} required>
                {(field) => <Input {...field} {...register('mailboxDays')} type="number" min={0} max={MAX_RETENTION_DAYS} step={1} inputMode="numeric" />}
              </Field>
              <Field label={t('admin.settings.mediaDays')} error={errors.mediaDays?.message} description={t('admin.settings.mediaDaysHint')} required>
                {(field) => <Input {...field} {...register('mediaDays')} type="number" min={0} max={MAX_RETENTION_DAYS} step={1} inputMode="numeric" />}
              </Field>
            </CardContent>
          </Card>
        </Section>
        {update.isError ? <Alert variant="error">{apiErrorMessage(update.error, t('admin.settings.saveFailed'))}</Alert> : null}
        <div className="flex justify-end">
          <Button type="submit" loading={update.isPending} disabled={!isDirty}>{t('common.save')}</Button>
        </div>
      </form>
    </PageBody>
  )
}
