import type { ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import { Navigate, useLocation } from 'react-router-dom'
import { useSession } from '@kutup/session/store'
import { Alert } from '@kutup/ui/components/alert'
import { PageBody } from '@kutup/ui/components/page'

/** Signed-out visitors go to sign-in and come back here afterwards. */
export function RequireSession({ children }: { children: ReactNode }) {
  const session = useSession()
  const location = useLocation()
  if (!session) {
    const here = location.pathname + location.search
    return <Navigate to={`/login?next=${encodeURIComponent(here)}`} replace />
  }
  return <>{children}</>
}

/** Hiding admin pages is a courtesy; the server enforces the admin role. */
export function RequireAdmin({ children }: { children: ReactNode }) {
  const { t } = useTranslation()
  const session = useSession()
  if (!session?.isAdmin) {
    return (
      <PageBody>
        <Alert variant="error" title={t('admin.forbiddenTitle')}>
          {t('admin.forbidden')}
        </Alert>
      </PageBody>
    )
  }
  return <>{children}</>
}
