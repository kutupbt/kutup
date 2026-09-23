import { useEffect, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Link, Navigate, useLocation, useSearchParams } from 'react-router-dom'
import { isForkChild, produceFork } from '@kutup/session/fork'
import { useSession } from '@kutup/session/store'
import { Alert } from '@kutup/ui/components/alert'
import { Spinner } from '@kutup/ui/components/states'
import { AuthLayout } from './AuthLayout'
import { authErrorMessage } from './errors'

/**
 * `/authorize?app=drive&state=…` — Drive or Chat asked for a session. Signed
 * out: sign in first and come back here. Signed in: hand the app a session
 * fork and leave for it. The destination origin comes from the server's
 * fork response, never from this URL.
 */
export function AuthorizePage() {
  const { t } = useTranslation()
  const location = useLocation()
  const [params] = useSearchParams()
  const session = useSession()
  const app = params.get('app')
  const state = params.get('state') ?? ''
  const started = useRef(false)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    if (!session || !isForkChild(app) || started.current) return
    // Once per page: StrictMode re-runs effects, and each run would mint a fork.
    started.current = true
    produceFork(app, state)
      .then((url) => window.location.replace(url))
      .catch((err: unknown) => setError(authErrorMessage(err, t, 'authorize.failed')))
  }, [session, app, state, t])

  if (!isForkChild(app)) {
    return (
      <AuthLayout title={t('authorize.invalidTitle')} description={t('authorize.invalidDescription')}>
        <Link to="/" className="block text-center text-sm font-medium text-primary hover:underline">
          {t('authorize.home')}
        </Link>
      </AuthLayout>
    )
  }
  if (!session) {
    const here = location.pathname + location.search
    return <Navigate to={`/login?next=${encodeURIComponent(here)}`} replace />
  }

  return (
    <AuthLayout title={t('authorize.title', { app: t(`apps.${app}`) })}>
      {error ? (
        <Alert variant="error">{error}</Alert>
      ) : (
        <div className="flex items-center justify-center gap-3 py-4 text-sm text-muted-foreground">
          <Spinner label={t('authorize.opening')} className="size-5" />
          {t('authorize.opening')}
        </div>
      )}
    </AuthLayout>
  )
}
