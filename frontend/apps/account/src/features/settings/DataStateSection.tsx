import { useQuery } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { accountHead } from '@kutup/session/accountHead'
import { useRequiredSession } from '@kutup/session/store'
import { Card, CardContent } from '@kutup/ui/components/card'
import { Section } from '@kutup/ui/components/page'
import { LoadingPanel } from '@kutup/ui/components/states'
import { formatInstant } from '@kutup/ui/lib/format'
import { describeHeadEvent } from './dataState'

/**
 * "Data state" (docs/plans/rollback-protection.md, section 5): the number of
 * the account's latest change to contacts, labels, saved keys and vault
 * passwords, as this app has verified it, and who made it. Comparing it
 * between devices is the hand check for anyone who doubts the server. The
 * date is when this app saw it (the head itself holds no time).
 */
export function DataStateSection() {
  const { t, i18n } = useTranslation()
  const session = useRequiredSession()
  const state = useQuery({
    queryKey: ['account-head', 'data-state', session.userId],
    queryFn: async () => {
      const client = await accountHead(session)
      // A blocked head still has a state to show; the banner says the rest.
      await client.verifiedHead().catch(() => undefined)
      return client.dataState()
    },
  })

  return (
    <Section title={t('accountHead.dataState')} description={t('accountHead.dataStateDescription')}>
      <Card>
        <CardContent className="space-y-3 p-5 text-sm">
          {state.isPending ? (
            <LoadingPanel label={t('common.loading')} />
          ) : !state.data || state.data.sequence === null ? (
            <p className="text-muted-foreground">{t('accountHead.dataStateNone')}</p>
          ) : (
            <>
              <p className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
                <span className="font-mono text-base font-medium">{t('accountHead.dataStateLine', { sequence: state.data.sequence })}</span>
                {state.data.lastByThisApp !== null ? (
                  <span>{t(state.data.lastByThisApp ? 'accountHead.lastByThisApp' : 'accountHead.lastByAnother')}</span>
                ) : null}
                {state.data.anchoredAtMs ? (
                  <span className="text-muted-foreground">
                    {t('accountHead.since', { when: formatInstant(new Date(state.data.anchoredAtMs).toISOString(), i18n.language) })}
                  </span>
                ) : null}
              </p>
              <details>
                <summary className="cursor-pointer text-muted-foreground">{t('accountHead.history')}</summary>
                {state.data.log.length === 0 ? (
                  <p className="mt-2 text-muted-foreground">{t('accountHead.historyEmpty')}</p>
                ) : (
                  <ul className="mt-2 space-y-1">
                    {[...state.data.log].reverse().map((event, i) => {
                      const line = describeHeadEvent(event, t)
                      return (
                        <li key={i} className="flex flex-wrap gap-x-3">
                          <span>{line.text}</span>
                          <time className="text-muted-foreground" dateTime={new Date(line.atMs).toISOString()}>
                            {formatInstant(new Date(line.atMs).toISOString(), i18n.language)}
                          </time>
                        </li>
                      )
                    })}
                  </ul>
                )}
              </details>
            </>
          )}
        </CardContent>
      </Card>
    </Section>
  )
}
