import { useQuery, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import api from '@kutup/session/client'
import type { AccountLimits as Limits, AccountRateLimitLimit, AccountSettingLimit, SettingSection, ValueSource } from '@kutup/session/api-types'
import { Alert } from '@kutup/ui/components/alert'
import { Card, CardContent } from '@kutup/ui/components/card'
import { LoadingPanel } from '@kutup/ui/components/states'
import { apiErrorMessage } from '@kutup/ui/lib/apiError'
import { adminKey } from './api'
import { countsText, RateLimitRow } from './RateLimitsPage'

/** Where each section's settings are named in Server settings. */
export const SETTING_LABELS: Record<SettingSection, string> = {
  chatMulti: 'admin.settings.multi',
  calendar: 'admin.settings.calendarLimits',
  chatLinking: 'admin.settings.chatLinkingLimits',
  twoFactor: 'admin.settings.twoFactorLimits',
  drive: 'admin.settings.driveLimits',
}

/**
 * One account's own values of the settings and rate limits that limit one
 * account (docs/plans/settings-registry.md), on its page under
 * Administration: each with the value in effect and where it comes from.
 */
export function AccountLimits({ userId }: { userId: string }) {
  const { t } = useTranslation()
  const queryClient = useQueryClient()
  const key = [...adminKey, 'users', userId, 'limits'] as const
  const limits = useQuery({
    queryKey: key,
    queryFn: async () => (await api.get<Limits>(`/admin/users/${userId}/limits`)).data,
  })
  if (limits.isError) return <Alert variant="error">{apiErrorMessage(limits.error, t('common.tryAgain'))}</Alert>
  if (limits.isPending) return <LoadingPanel label={t('common.loading')} />

  const source = (from: ValueSource, site: number) =>
    from === 'account' ? t('admin.limits.source.account', { site }) : t(`admin.limits.source.${from}`)
  const save = async (limitKey: string, value: number | null) =>
    (await api.put<AccountSettingLimit | AccountRateLimitLimit>(`/admin/users/${userId}/limits/${limitKey}`, { value })).data
  const saved = (next: AccountSettingLimit | AccountRateLimitLimit) =>
    queryClient.setQueryData<Limits>(key, (all) =>
      all && {
        settings: all.settings.map((each) => (each.key === next.key ? (next as AccountSettingLimit) : each)),
        rateLimits: all.rateLimits.map((each) => (each.key === next.key ? (next as AccountRateLimitLimit) : each)),
      },
    )

  return (
    <div className="space-y-4">
      <Card>
        <CardContent className="divide-y divide-border p-0">
          <p className="p-4 text-sm font-medium">{t('admin.limits.settings')}</p>
          {limits.data.settings.map((limit) => (
            <RateLimitRow
              key={limit.key}
              limitKey={limit.key}
              label={t(`${SETTING_LABELS[limit.section]}.${limit.field}`)}
              about={t(`${SETTING_LABELS[limit.section]}.${limit.field}Hint`)}
              counts={t(`admin.limits.unit.${limit.unit}`)}
              bytes={limit.unit === 'bytes'}
              note={source(limit.source, limit.siteValue)}
              value={limit.value}
              min={limit.min}
              max={limit.max}
              resettable={limit.source === 'account'}
              resetLabel={t('admin.limits.reset')}
              save={(value) => save(limit.key, value)}
              onSaved={saved}
            />
          ))}
        </CardContent>
      </Card>
      <Card>
        <CardContent className="divide-y divide-border p-0">
          <p className="p-4 text-sm font-medium">{t('admin.limits.rateLimits')}</p>
          {limits.data.rateLimits.map((limit) => (
            <RateLimitRow
              key={limit.key}
              limitKey={limit.limit}
              label={t(`admin.rateLimits.limit.${limit.limit}`)}
              about={t(`admin.rateLimits.about.${limit.limit}`)}
              counts={countsText({ ...limit, per: 'account' }, t)}
              bytes={limit.unit === 'bytes' || limit.unit === 'bytesAtOnce'}
              note={source(limit.source, limit.siteValue)}
              value={limit.value}
              min={limit.min}
              max={limit.max}
              resettable={limit.source === 'account'}
              resetLabel={t('admin.limits.reset')}
              save={(value) => save(limit.key, value)}
              onSaved={saved}
            />
          ))}
        </CardContent>
      </Card>
    </div>
  )
}
