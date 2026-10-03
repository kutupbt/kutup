import { useCallback, useEffect, useState, type ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import { loadAppDirectory } from '@kutup/session/apps'
import { restoreSession } from '@kutup/session/persist'
import { Alert } from '@kutup/ui/components/alert'
import { Button } from '@kutup/ui/components/button'
import { LoadingPanel } from '@kutup/ui/components/states'

type State = { kind: 'loading' } | { kind: 'ready' } | { kind: 'error' }

/**
 * Before any route renders: learn where the other apps live, and restore this
 * origin's session from its encrypted blob if there is one. An unreachable
 * server is an error with a retry, never a silent sign-out.
 */
export function Boot({ children }: { children: ReactNode }) {
  const { t } = useTranslation()
  const [state, setState] = useState<State>({ kind: 'loading' })

  const run = useCallback(() => {
    setState({ kind: 'loading' })
    Promise.all([loadAppDirectory(), restoreSession()])
      .then(() => setState({ kind: 'ready' }))
      .catch(() => setState({ kind: 'error' }))
  }, [])

  useEffect(run, [run])

  if (state.kind === 'loading') return <LoadingPanel label={t('common.loading')} />
  if (state.kind === 'error') {
    return (
      <div className="mx-auto flex min-h-svh max-w-md flex-col justify-center gap-4 p-6">
        <Alert variant="error" title={t('boot.failedTitle')}>
          {t('boot.failedDescription')}
        </Alert>
        <Button onClick={run}>{t('common.retry')}</Button>
      </div>
    )
  }
  return <>{children}</>
}
