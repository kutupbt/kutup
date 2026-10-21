import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import api from '@kutup/session/client'
import { Alert } from '@kutup/ui/components/alert'
import { Button } from '@kutup/ui/components/button'
import { Card, CardContent } from '@kutup/ui/components/card'
import { Input } from '@kutup/ui/components/input'
import { PageBody, PageHeader, Section } from '@kutup/ui/components/page'
import { LoadingPanel } from '@kutup/ui/components/states'
import { apiErrorMessage } from '@kutup/ui/lib/apiError'
import { formatBytes } from '@kutup/ui/lib/format'
import { adminKey } from './api'
import { windowUnit } from './helpers'

export interface AccountRateLimit {
  key: string
  section: string
  unit: RateLimit['unit']
  windowSeconds: number | null
  value: number
  siteValue: number
  override: boolean
  min: number
  max: number
}

export interface RateLimit {
  key: string
  section: string
  per: string
  unit: 'events' | 'attempts' | 'minutes' | 'bytes' | 'atOnce' | 'bytesAtOnce'
  windowSeconds: number | null
  value: number
  firstValue: number
  firstFrom: 'default' | 'environment' | 'testStack'
  env: string | null
  set: boolean
  min: number
  max: number
}

const rateLimitsKey = [...adminKey, 'rate-limits'] as const

/** The order sections are listed in, as the server groups them. */
const SECTIONS = ['accounts', 'drive', 'chat', 'groups', 'mail', 'callsAndMaps', 'pass', 'federation', 'administration'] as const

/**
 * Administration → Rate limits (docs/plans/admin-rate-limits.md §6): every
 * limit the server keeps, what it counts and per what, its value and its
 * first value. A change applies at once on this server and within 30
 * seconds on every other backend; a reset returns to the first value.
 */
export function RateLimitsPage() {
  const { t } = useTranslation()
  const limits = useQuery({
    queryKey: rateLimitsKey,
    queryFn: async () => (await api.get<{ limits: RateLimit[] }>('/admin/rate-limits')).data.limits,
  })

  if (limits.isError) {
    return (
      <PageBody width="prose">
        <Alert variant="error">{apiErrorMessage(limits.error, t('common.tryAgain'))}</Alert>
      </PageBody>
    )
  }
  if (limits.isPending) return <LoadingPanel label={t('common.loading')} />

  return (
    <PageBody width="prose">
      <PageHeader title={t('admin.rateLimits.title')} description={t('admin.rateLimits.description')} />
      <div className="space-y-6">
        {SECTIONS.map((section) => {
          const rows = limits.data.filter((limit) => limit.section === section)
          if (rows.length === 0) return null
          return (
            <Section key={section} title={t(`admin.rateLimits.section.${section}`)}>
              <Card>
                <CardContent className="divide-y divide-border p-0">
                  {rows.map((limit) => (
                    <SiteRateLimitRow key={limit.key} limit={limit} />
                  ))}
                </CardContent>
              </Card>
            </Section>
          )
        })}
      </div>
    </PageBody>
  )
}

type TFunction = ReturnType<typeof useTranslation>['t']

/** What a limit counts, per what and over which window, in words. */
function countsText(limit: Pick<RateLimit, 'unit' | 'windowSeconds' | 'per'>, t: TFunction): string {
  const per = t(`admin.rateLimits.per.${limit.per}`)
  if ((limit.unit === 'events' || limit.unit === 'bytes') && limit.windowSeconds) {
    const unit = windowUnit(limit.windowSeconds)
    const window = t(`admin.rateLimits.window.${unit.unit}`, { count: unit.count })
    return t(limit.unit === 'bytes' ? 'admin.rateLimits.countsBytes' : 'admin.rateLimits.countsEvents', { per, window })
  }
  if (limit.unit === 'attempts') return t('admin.rateLimits.countsAttempts', { per })
  if (limit.unit === 'atOnce') return t('admin.rateLimits.countsAtOnce', { per })
  if (limit.unit === 'bytesAtOnce') return t('admin.rateLimits.countsBytesAtOnce', { per })
  return t('admin.rateLimits.countsMinutes')
}

function SiteRateLimitRow({ limit }: { limit: RateLimit }) {
  const { t } = useTranslation()
  const queryClient = useQueryClient()
  const first = t(`admin.rateLimits.firstFrom.${limit.firstFrom}`, { value: limit.firstValue, env: limit.env ?? '' })
  return (
    <RateLimitRow
      limitKey={limit.key}
      counts={countsText(limit, t)}
      bytes={limit.unit === 'bytes' || limit.unit === 'bytesAtOnce'}
      note={limit.set ? t('admin.rateLimits.setHere', { first }) : first}
      value={limit.value}
      min={limit.min}
      max={limit.max}
      resettable={limit.set}
      resetLabel={t('admin.rateLimits.resetAction')}
      save={async (value) => (await api.put<RateLimit>(`/admin/rate-limits/${limit.key}`, { value })).data}
      onSaved={(saved) => {
        queryClient.setQueryData<RateLimit[]>(rateLimitsKey, (all) => all?.map((each) => (each.key === saved.key ? saved : each)))
        // The lockout's length is the ceiling's window too.
        if (saved.key === 'login_lockout_minutes') void queryClient.invalidateQueries({ queryKey: rateLimitsKey })
      }}
    />
  )
}

/**
 * One account's own values of the limits counted per account
 * (docs/plans/admin-rate-limits.md §4), on its page under Administration.
 */
export function AccountRateLimits({ userId }: { userId: string }) {
  const { t } = useTranslation()
  const queryClient = useQueryClient()
  const key = [...adminKey, 'users', userId, 'rate-limits'] as const
  const limits = useQuery({
    queryKey: key,
    queryFn: async () => (await api.get<{ limits: AccountRateLimit[] }>(`/admin/users/${userId}/rate-limits`)).data.limits,
  })
  if (limits.isError) return <Alert variant="error">{apiErrorMessage(limits.error, t('common.tryAgain'))}</Alert>
  if (limits.isPending) return <LoadingPanel label={t('common.loading')} />
  return (
    <Card>
      <CardContent className="divide-y divide-border p-0">
        {limits.data.map((limit) => (
          <RateLimitRow
            key={limit.key}
            limitKey={limit.key}
            counts={countsText({ ...limit, per: 'account' }, t)}
            bytes={limit.unit === 'bytes' || limit.unit === 'bytesAtOnce'}
            note={
              limit.override
                ? t('admin.rateLimits.accountOwn', { site: limit.siteValue })
                : t('admin.rateLimits.accountSite')
            }
            value={limit.value}
            min={limit.min}
            max={limit.max}
            resettable={limit.override}
            resetLabel={t('admin.rateLimits.accountResetAction')}
            save={async (value) =>
              (await api.put<AccountRateLimit>(`/admin/users/${userId}/rate-limits/${limit.key}`, { value })).data
            }
            onSaved={(saved) =>
              queryClient.setQueryData<AccountRateLimit[]>(key, (all) => all?.map((each) => (each.key === saved.key ? saved : each)))
            }
          />
        ))}
      </CardContent>
    </Card>
  )
}

interface RowProps<T> {
  limitKey: string
  counts: string
  /** The value is a number of bytes: its size is shown beside it. */
  bytes: boolean
  note: string
  value: number
  min: number
  max: number
  resettable: boolean
  resetLabel: string
  save: (value: number | null) => Promise<T>
  onSaved: (saved: T) => void
}

/** One limit: its name, what it counts, its value with save and reset. */
function RateLimitRow<T>({ limitKey, counts, bytes, note, value, min, max, resettable, resetLabel, save, onSaved }: RowProps<T>) {
  const { t, i18n } = useTranslation()
  const [draft, setDraft] = useState(String(value))
  useEffect(() => setDraft(String(value)), [value])
  const mutation = useMutation({
    mutationFn: save,
    onSuccess: (saved, next) => {
      onSaved(saved)
      toast.success(next === null ? t('admin.rateLimits.reset') : t('admin.rateLimits.saved'))
    },
  })

  const parsed = /^\d+$/.test(draft.trim()) ? Number(draft.trim()) : NaN
  const valid = Number.isSafeInteger(parsed) && parsed >= min && parsed <= max
  const changed = draft.trim() !== String(value)
  const inputId = `rate-limit-${limitKey}`

  return (
    <form
      className="flex flex-wrap items-end gap-3 p-4"
      noValidate
      data-testid={`admin-rate-limit-${limitKey}`}
      onSubmit={(event) => {
        event.preventDefault()
        if (valid && changed) mutation.mutate(parsed)
      }}
    >
      <div className="min-w-0 flex-1 basis-56 space-y-1">
        <label htmlFor={inputId} className="text-sm font-medium">{t(`admin.rateLimits.limit.${limitKey}`)}</label>
        <p className="text-sm text-muted-foreground">{t(`admin.rateLimits.about.${limitKey}`)}</p>
        <p className="text-xs text-muted-foreground">
          {counts}
          {bytes && valid ? ` (${t('admin.rateLimits.bytesHint', { size: formatBytes(parsed, i18n.language) })})` : ''}
        </p>
        <p className="text-xs text-muted-foreground">{note}</p>
        {!valid && draft.trim() !== '' ? (
          <p className="text-xs text-destructive" role="alert">{t('admin.rateLimits.bounds', { min, max })}</p>
        ) : null}
        {mutation.isError ? (
          <p className="text-xs text-destructive" role="alert">{apiErrorMessage(mutation.error, t('admin.rateLimits.saveFailed'))}</p>
        ) : null}
      </div>
      <div className="flex items-center gap-2">
        <Input
          id={inputId}
          className="w-28"
          type="number"
          min={min}
          max={max}
          step={1}
          inputMode="numeric"
          value={draft}
          aria-invalid={!valid}
          onChange={(event) => setDraft(event.target.value)}
          data-testid={`admin-rate-limit-${limitKey}-value`}
        />
        <Button type="submit" size="sm" loading={mutation.isPending && mutation.variables !== null} disabled={!valid || !changed}>
          {t('common.save')}
        </Button>
        {resettable ? (
          <Button
            type="button"
            size="sm"
            variant="ghost"
            loading={mutation.isPending && mutation.variables === null}
            onClick={() => mutation.mutate(null)}
            data-testid={`admin-rate-limit-${limitKey}-reset`}
          >
            {resetLabel}
          </Button>
        ) : null}
      </div>
    </form>
  )
}
