import { Check } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { useRequiredSession } from '@kutup/session/store'
import { Alert } from '@kutup/ui/components/alert'
import { Card, CardContent } from '@kutup/ui/components/card'
import { Mono } from '@kutup/ui/components/mono'
import { Fact, PageBody, PageHeader, Section } from '@kutup/ui/components/page'
import { Skeleton } from '@kutup/ui/components/skeleton'
import { apiErrorMessage } from '@kutup/ui/lib/apiError'
import { cn } from '@kutup/ui/lib/cn'
import { formatBytes } from '@kutup/ui/lib/format'
import { useMe, useUpdateColor } from './api'

/**
 * Presence colours for collaborative editing: saturated enough to read as a
 * cursor on both themes' paper. These are user data (the server stores the
 * hex), not UI tokens, which is why they are literal values.
 */
const PRESENCE_COLOURS = [
  '#e11d48',
  '#ea580c',
  '#ca8a04',
  '#16a34a',
  '#0d9488',
  '#0284c7',
  '#4f46e5',
  '#9333ea',
  '#db2777',
  '#475569',
]

export function AccountSettingsPage() {
  const { t, i18n } = useTranslation()
  const session = useRequiredSession()
  const me = useMe()
  const colour = useUpdateColor()

  return (
    <PageBody width="prose">
      <PageHeader title={t('settings.account.title')} description={t('settings.account.description')} />

      <Section title={t('settings.account.profile')}>
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

      <Section title={t('settings.account.colour')} description={t('settings.account.colourDescription')}>
        <div className="flex flex-wrap items-center gap-2" role="radiogroup" aria-label={t('settings.account.colour')}>
          <button
            type="button"
            role="radio"
            aria-checked={!session.color}
            disabled={colour.isPending}
            onClick={() => colour.mutate('')}
            className={cn(
              'h-9 rounded-full border border-border px-3 text-sm transition-colors hover:bg-accent',
              !session.color && 'border-primary bg-accent font-medium',
            )}
          >
            {t('settings.account.colourAuto')}
          </button>
          {PRESENCE_COLOURS.map((value) => {
            const selected = session.color?.toLowerCase() === value
            return (
              <button
                key={value}
                type="button"
                role="radio"
                aria-checked={selected}
                aria-label={value}
                disabled={colour.isPending}
                onClick={() => colour.mutate(value)}
                style={{ backgroundColor: value }}
                className={cn(
                  'flex size-9 items-center justify-center rounded-full text-white ring-offset-2 ring-offset-background transition-shadow',
                  'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring',
                  selected && 'ring-2 ring-foreground',
                )}
              >
                {selected ? <Check className="size-4" /> : null}
              </button>
            )
          })}
        </div>
        {colour.isError ? (
          <Alert variant="error">{apiErrorMessage(colour.error, t('settings.account.colourFailed'))}</Alert>
        ) : null}
      </Section>
    </PageBody>
  )
}
