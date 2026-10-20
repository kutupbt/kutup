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
function linkProblem(error: unknown): 'invalid' | 'expired' | 'rateLimited' | null {
  if (!isAxiosError(error)) return null
  const status = error.response?.status
  if (status === 404) return 'invalid'
  if (status === 410) return 'expired'
  if (status === 429) return 'rateLimited'
  return null
}

/**
 * The page an outside forwardee's confirmation email links to
 * (`/email-forwarding#<token>`, Proton's accept/decline page): no account is
 * needed. The token stays in the fragment, so no server log holds it, and
 * goes to the server in a request body. Accepting or declining spends the
 * link (docs/plans/mail-forwarding.md).
 */
export function EmailForwardingPage() {
  const { t } = useTranslation()
  const location = useLocation()
  // Read once: the token then leaves the address bar and the history entry.
  const [token] = useState(() => location.hash.replace(/^#/, '').trim())
  useEffect(() => {
    if (window.location.hash) window.history.replaceState(window.history.state, '', window.location.pathname + window.location.search)
  }, [])
  const [done, setDone] = useState<'accepted' | 'declined' | null>(null)
  const forwarding = useQuery({
    queryKey: ['email-forwarding', token],
    enabled: token !== '',
    retry: false,
    queryFn: async () => (await api.post<ExternalForwarding>('/mail/forwardings/external', { token })).data,
  })
  const answer = useMutation({
    mutationFn: async (choice: 'accept' | 'decline') => {
      await api.post(`/mail/forwardings/external/${choice}`, { token })
      return choice
    },
    onSuccess: (choice) => setDone(choice === 'accept' ? 'accepted' : 'declined'),
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
          {t(`emailForwarding.${done}`, { from: forwarding.data?.forwarderEmail ?? '' })}
        </Alert>
      ) : forwarding.data ? (
        <div className="space-y-4">
          <p className="text-sm" data-testid="email-forwarding-request">
            {t('emailForwarding.request', { from: forwarding.data.forwarderEmail, to: forwarding.data.forwardeeEmail })}
          </p>
          <p className="text-sm text-muted-foreground">{t('emailForwarding.notEncrypted', { from: forwarding.data.forwarderEmail })}</p>
          {forwarding.data.state === 'pending' ? (
            <div className="flex gap-2">
              <Button onClick={() => answer.mutate('accept')} loading={answer.isPending && answer.variables === 'accept'} disabled={answer.isPending} data-testid="email-forwarding-accept">
                {t('emailForwarding.accept')}
              </Button>
              <Button variant="outline" onClick={() => answer.mutate('decline')} loading={answer.isPending && answer.variables === 'decline'} disabled={answer.isPending}>
                {t('emailForwarding.decline')}
              </Button>
            </div>
          ) : (
            <Alert>{t(forwarding.data.state === 'rejected' ? 'emailForwarding.alreadyDeclined' : 'emailForwarding.alreadyAnswered')}</Alert>
          )}
        </div>
      ) : null}
    </AuthLayout>
  )
}
