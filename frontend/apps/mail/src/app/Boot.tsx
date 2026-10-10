import { useCallback, useEffect, useRef, useState, type ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import { useNavigate } from 'react-router-dom'
import { bootChildApp } from '@kutup/session/childBoot'
import { Alert } from '@kutup/ui/components/alert'
import { Button } from '@kutup/ui/components/button'
import { LoadingPanel } from '@kutup/ui/components/states'

type State = { kind: 'loading' } | { kind: 'ready' } | { kind: 'error' }

/**
 * Mail gets its session from the account app: consume a fork, restore this
 * origin's blob, or go and ask for one. Nothing renders until one of those
 * has happened.
 */
export function Boot({ children }: { children: ReactNode }) {
  const { t } = useTranslation()
  // A new function whenever the location changes: read through a ref, so
  // moving between pages never starts the app over (which would remount
  // everything below).
  const navigateNow = useNavigate()
  const navigate = useRef(navigateNow)
  navigate.current = navigateNow
  const [state, setState] = useState<State>({ kind: 'loading' })

  const run = useCallback(() => {
    setState({ kind: 'loading' })
    bootChildApp('mail')
      .then((result) => {
        if (result.kind === 'redirecting') return
        if (result.next) void navigate.current(result.next, { replace: true })
        setState({ kind: 'ready' })
      })
      .catch(() => setState({ kind: 'error' }))
  }, [])

  useEffect(run, [run])

  if (state.kind === 'loading') return <LoadingPanel label={t('boot.opening')} />
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
