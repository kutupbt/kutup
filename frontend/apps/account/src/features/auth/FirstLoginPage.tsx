import { useTranslation } from 'react-i18next'
import { Navigate, useNavigate, useSearchParams } from 'react-router-dom'
import { sanitizeNext } from '@kutup/session/sessionSync'
import { completeSetup } from './flows'
import { NewKeysWizard } from './NewKeysWizard'
import { getPendingSetup, setPendingSetup } from './pendingSetup'

/**
 * An administrator created this account with a temporary password. Its keys
 * are made here, on the user's device: a new password, a recovery phrase,
 * then the first real session.
 */
export function FirstLoginPage() {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const [params] = useSearchParams()
  const next = sanitizeNext(params.get('next')) ?? '/'
  const setup = getPendingSetup()
  if (!setup) return <Navigate to="/login" replace />

  return (
    <NewKeysWizard
      title={t('firstLogin.title')}
      description={t('firstLogin.description', { email: setup.email })}
      email={() => setup.email}
      onKeysConfirmed={async (keys) => {
        await completeSetup(setup, keys)
        setPendingSetup(null)
        void navigate(next, { replace: true })
      }}
    />
  )
}
