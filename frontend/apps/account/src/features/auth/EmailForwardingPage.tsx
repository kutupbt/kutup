import { useMutation, useQuery } from '@tanstack/react-query'
import { isAxiosError } from 'axios'
import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useLocation } from 'react-router-dom'
import api from '@kutup/session/client'
import { Alert } from '@kutup/ui/components/alert'
import { Button } from '@kutup/ui/components/button'
import { Skeleton } from '@kutup/ui/components/skeleton'
import { AuthLayout } from './AuthLayout'

interface ExternalForwarding {
  state: 'pending' | 'active' | 'outdated' | 'paused' | 'rejected'
  forwarderEmail: string
  forwardeeEmail: string
}

/** Why a link can't be used, as the server says it. */
function linkProblem(error: unknown): 'invalid' | 'rateLimited' | null {
  if (!isAxiosError(error)) return null
  const status = error.response?.status
  if (status === 404) return 'invalid'
  if (status === 429) return 'rateLimited'
  return null
}

/**
 * The page an outside forwarding's code email links to
 * (`/email-forwarding#<token>`): no account is needed. It can only stop the
 * forwarding, pending or active; only the code the forwarder enters starts
 * one. The token stays in the fragment, so no server log holds it, and goes
 * to the server in a request body (docs/plans/mail-forwarding.md).
 */
export function EmailForwardingPage() {
  const { t } = useTranslation()
  const location = useLocation()
  // Read once: the token then leaves the address bar and the history entry.
  const [token] = useState(() => location.hash.replace(/^#/, '').trim())
  useEffect(() => {
    if (window.location.hash) window.history.replaceState(window.history.state, '', window.location.pathname + window.location.search)
  }, [])
  const [done, setDone] = useState(false)
  const forwarding = useQuery({
    queryKey: ['email-forwarding', token],
    enabled: token !== '',
    retry: false,
    queryFn: async () => (await api.post<ExternalForwarding>('/mail/forwardings/external', { token })).data,
  })
  const answer = useMutation({
    mutationFn: async () => {
      await api.post('/mail/forwardings/external/decline', { token })
    },
    onSuccess: () => setDone(true),
  })

  const problem = token === '' ? 'invalid' : linkProblem(forwarding.error ?? answer.error)
  return (
    <AuthLayout title={t('emailForwarding.title')}>
      {forwarding.isPending && token !== '' ? (
        <Skeleton className="h-24 w-full" />
      ) : problem ? (
        <Alert variant="error" data-testid="email-forwarding-problem">
          {t(`emailForwarding.${problem}`)}
        </Alert>
      ) : forwarding.isError || answer.isError ? (
        <Alert variant="error">{t('common.tryAgain')}</Alert>
      ) : done ? (
        <Alert data-testid="email-forwarding-done">
          {t('emailForwarding.declined', { from: forwarding.data?.forwarderEmail ?? '' })}
        </Alert>
      ) : forwarding.data ? (
        <div className="space-y-4">
          <p className="text-sm" data-testid="email-forwarding-request">
            {t('emailForwarding.request', { from: forwarding.data.forwarderEmail, to: forwarding.data.forwardeeEmail })}
          </p>
          <p className="text-sm text-muted-foreground">{t('emailForwarding.notEncrypted', { from: forwarding.data.forwarderEmail })}</p>
          {forwarding.data.state === 'rejected' ? (
            <Alert>{t('emailForwarding.alreadyDeclined')}</Alert>
          ) : (
            <Button variant="outline" onClick={() => answer.mutate()} loading={answer.isPending} data-testid="email-forwarding-decline">
              {t('emailForwarding.decline')}
            </Button>
          )}
        </div>
      ) : null}
    </AuthLayout>
  )
}
