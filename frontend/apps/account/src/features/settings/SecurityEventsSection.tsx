import { isAxiosError } from 'axios'
import { useEffect } from 'react'
import { useTranslation } from 'react-i18next'
import { Alert } from '@kutup/ui/components/alert'
import { Badge } from '@kutup/ui/components/badge'
import { Button } from '@kutup/ui/components/button'
import { Card, CardContent } from '@kutup/ui/components/card'
import { Section } from '@kutup/ui/components/page'
import { LoadingPanel } from '@kutup/ui/components/states'
import { formatInstant } from '@kutup/ui/lib/format'
import { useSecurityEvents } from './api'
import { securityEventDevice, securityEventLabel } from './securityEvents'

/**
 * Changes to how this account signs in (docs/plans/opaque.md), newest
 * first: a password changed or reset, a refreshed sign-in, an administrator's
 * reset. No addresses are kept, so none are shown.
 */
export function SecurityEventsSection() {
  const { t, i18n } = useTranslation()
  const events = useSecurityEvents()
  const list = events.data?.pages.flatMap((page) => page.events) ?? []
  // A cursor the server no longer knows (400): start again from the newest.
  const staleCursor =
    events.isFetchNextPageError && isAxiosError(events.error) && events.error.response?.status === 400
  const { refetch } = events
  useEffect(() => {
    // Refetching an infinite query starts from its first page.
    if (staleCursor) void refetch({ cancelRefetch: false })
  }, [staleCursor, refetch])
  const device = (event: (typeof list)[number]) => {
    const where = securityEventDevice(event)
    return where ? t(where.key, where.values) : null
  }

  return (
    <Section title={t('settings.security.events.title')} description={t('settings.security.events.description')}>
      <Card>
        <CardContent className="p-5">
          {events.isPending ? (
            <LoadingPanel label={t('common.loading')} />
          ) : events.isError && !staleCursor ? (
            <Alert variant="error">{t('settings.security.events.failed')}</Alert>
          ) : list.length === 0 ? (
            <p className="text-sm text-muted-foreground">{t('settings.security.events.none')}</p>
          ) : (
            <ul className="divide-y divide-border" aria-label={t('settings.security.events.title')}>
              {list.map((event) => (
                <li key={event.id} className="flex flex-wrap items-center gap-x-3 gap-y-1 py-2.5 text-sm first:pt-0 last:pb-0">
                  <span className="font-medium">{t(securityEventLabel(event))}</span>
                  {device(event) ? <span className="text-muted-foreground">{device(event)}</span> : null}
                  {event.byAdmin ? <Badge variant="warn">{t('settings.security.events.byAdmin')}</Badge> : null}
                  {event.thisSession ? <Badge variant="neutral">{t('settings.security.events.thisDevice')}</Badge> : null}
                  <time className="ml-auto text-muted-foreground" dateTime={event.at}>
                    {formatInstant(event.at, i18n.language)}
                  </time>
                </li>
              ))}
            </ul>
          )}
          {events.hasNextPage ? (
            <Button variant="outline" size="sm" className="mt-3" loading={events.isFetchingNextPage} onClick={() => void events.fetchNextPage()}>
              {t('settings.security.events.older')}
            </Button>
          ) : null}
        </CardContent>
      </Card>
    </Section>
  )
}
