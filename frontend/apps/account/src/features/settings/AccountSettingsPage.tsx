import { useTranslation } from 'react-i18next'
import { useRequiredSession } from '@kutup/session/store'
import { Alert } from '@kutup/ui/components/alert'
import { Card, CardContent } from '@kutup/ui/components/card'
import { Mono } from '@kutup/ui/components/mono'
import { Fact, PageBody, PageHeader, Section } from '@kutup/ui/components/page'
import { Skeleton } from '@kutup/ui/components/skeleton'
import { apiErrorMessage } from '@kutup/ui/lib/apiError'
import { formatBytes } from '@kutup/ui/lib/format'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@kutup/ui/components/select'
import { useMe, useUpdateVersionRetention, VERSION_RETENTION_DAYS } from './api'

export function AccountSettingsPage() {
  const { t, i18n } = useTranslation()
  const session = useRequiredSession()
  const me = useMe()
  const retention = useUpdateVersionRetention()

  return (
    <PageBody width="prose">
      <PageHeader title={t('settings.account.title')} description={t('settings.account.description')} />

      <Section title={t('settings.account.details')}>
        <Card>
          <CardContent className="grid gap-5 p-5 sm:grid-cols-2">
            <Fact label={t('auth.fields.email')}>{session.email}</Fact>
            <Fact label={t('auth.fields.username')}>
              {session.username ? <Mono>{session.username}</Mono> : t('settings.account.noUsername')}
            </Fact>
            <Fact label={t('settings.account.driveStorage')}>
              {me.data ? (
                t('settings.account.usage', {
                  used: formatBytes(me.data.storageUsedBytes, i18n.language),
                  total: formatBytes(me.data.storageQuotaBytes, i18n.language),
                })
              ) : (
                <Skeleton className="h-4 w-32" />
              )}
            </Fact>
            <Fact label={t('settings.account.chatStorage')}>
              {me.data ? (
                t('settings.account.usage', {
                  used: formatBytes(me.data.chatStorageUsedBytes, i18n.language),
                  total: formatBytes(me.data.chatStorageQuotaBytes, i18n.language),
                })
              ) : (
                <Skeleton className="h-4 w-32" />
              )}
            </Fact>
          </CardContent>
        </Card>
        {me.isError ? <Alert variant="error">{apiErrorMessage(me.error, t('common.tryAgain'))}</Alert> : null}
      </Section>

      <Section title={t('settings.account.versions')} description={t('settings.account.versionsDescription')}>
        <div className="flex flex-wrap items-center gap-3">
          <span id="version-retention" className="text-sm">
            {t('settings.account.versionsKeep')}
          </span>
          {me.data ? (
            <Select
              value={String(me.data.versionRetentionDays)}
              onValueChange={(v) => retention.mutate(Number(v))}
              disabled={retention.isPending}
            >
              <SelectTrigger aria-labelledby="version-retention" className="w-44">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {VERSION_RETENTION_DAYS.map((days) => (
                  <SelectItem key={days} value={String(days)}>
                    {t(`settings.account.retention.d${days}`)}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          ) : (
            <Skeleton className="h-9 w-44" />
          )}
        </div>
        {retention.isError ? (
          <Alert variant="error">{apiErrorMessage(retention.error, t('settings.account.versionsFailed'))}</Alert>
        ) : null}
      </Section>
    </PageBody>
  )
}
