import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import api from '@kutup/session/client'
import { Alert } from '@kutup/ui/components/alert'
import { Checkbox } from '@kutup/ui/components/checkbox'
import { PageBody, PageHeader, Section } from '@kutup/ui/components/page'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@kutup/ui/components/select'
import { Skeleton } from '@kutup/ui/components/skeleton'
import { apiErrorMessage } from '@kutup/ui/lib/apiError'
import { cn } from '@kutup/ui/lib/cn'
import { readDefaultView, writeDefaultView, type DefaultView } from '../explorer/prefs'

/** The retention periods the server accepts (docs/plans/drive-versions-v2.md). */
const VERSION_RETENTION_DAYS = [7, 30, 90, 180, 365, 3650] as const

/**
 * How Drive behaves: how long file versions are kept (for the account), and
 * how folders open in this browser. The account's profile and security live
 * in the account app (docs/plans/unified-profile.md).
 */
export function DriveSettingsPage() {
  const { t } = useTranslation()
  const queryClient = useQueryClient()
  const me = useQuery({
    queryKey: ['me'],
    queryFn: async () => (await api.get<{ versionRetentionDays: number }>('/user/me')).data,
  })
  const retention = useMutation({
    mutationFn: async (days: number) => {
      await api.patch('/user/me', { versionRetentionDays: days })
    },
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['me'] }),
  })
  const [view, setView] = useState<DefaultView>(readDefaultView)
  const change = (patch: Partial<DefaultView>) => {
    writeDefaultView(patch)
    setView((current) => ({ ...current, ...patch }))
  }

  return (
    <PageBody width="prose">
      <PageHeader title={t('settings.title')} description={t('settings.description')} />

      <Section title={t('settings.versions.title')} description={t('settings.versions.description')}>
        <div className="flex flex-wrap items-center gap-3">
          <span id="version-retention" className="text-sm">{t('settings.versions.keep')}</span>
          {me.data ? (
            <Select
              value={String(me.data.versionRetentionDays)}
              onValueChange={(value) => retention.mutate(Number(value))}
              disabled={retention.isPending}
            >
              <SelectTrigger aria-labelledby="version-retention" className="w-44" data-testid="drive-version-retention">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {VERSION_RETENTION_DAYS.map((days) => (
                  <SelectItem key={days} value={String(days)}>
                    {t(`settings.versions.retention.d${days}`)}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          ) : (
            <Skeleton className="h-9 w-44" />
          )}
        </div>
        {retention.isError ? (
          <Alert variant="error">{apiErrorMessage(retention.error, t('settings.versions.failed'))}</Alert>
        ) : null}
        {me.isError ? <Alert variant="error">{apiErrorMessage(me.error, t('common.tryAgain'))}</Alert> : null}
      </Section>

      <Section title={t('settings.view.title')} description={t('settings.view.description')}>
        <div className="flex gap-2" role="radiogroup" aria-label={t('settings.view.title')}>
          {(['list', 'grid'] as const).map((mode) => (
            <button
              key={mode}
              type="button"
              role="radio"
              aria-checked={view.view === mode}
              onClick={() => change({ view: mode })}
              className={cn(
                'rounded-md border px-4 py-2 text-sm transition-colors',
                view.view === mode ? 'border-primary bg-accent font-medium' : 'border-border hover:bg-muted',
              )}
              data-testid={`drive-default-view-${mode}`}
            >
              {t(`settings.view.${mode}`)}
            </button>
          ))}
        </div>
        <label className="flex cursor-pointer items-center gap-3 text-sm">
          <Checkbox checked={view.foldersFirst} onCheckedChange={(value) => change({ foldersFirst: value === true })} />
          {t('explorer.foldersFirst')}
        </label>
        <label className="flex cursor-pointer items-center gap-3 text-sm">
          <Checkbox checked={view.showPreviews} onCheckedChange={(value) => change({ showPreviews: value === true })} />
          {t('explorer.showPreviews')}
        </label>
      </Section>
    </PageBody>
  )
}
