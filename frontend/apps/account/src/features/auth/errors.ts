import type { useTranslation } from 'react-i18next'
import { isAxiosError } from 'axios'
import { OpaqueAuthFailed, OpaqueWorkerClosed } from '@kutup/crypto/opaqueWorker'
import { KeyBindingMismatchError } from '@kutup/session/profile'
import { apiErrorCode, apiErrorMessage } from '@kutup/ui/lib/apiError'
import { RegistrationConflictError } from './flows'

type TFunction = ReturnType<typeof useTranslation>['t']

/**
 * A sign-in failure worth showing. 429 gets its own words: retrying extends a
 * lockout. Rejected credentials read the same whether the account exists or
 * not, in the person's language; the server's English is never shown. A
 * registration conflict on the username says so.
 */
export function authErrorMessage(error: unknown, t: TFunction, fallbackKey: string): string {
  if (error instanceof KeyBindingMismatchError) return t('auth.errors.keysChanged')
  // A wrong password fails in this browser (OPAQUE), before the server answers.
  if (error instanceof OpaqueAuthFailed) return t(fallbackKey)
  if (error instanceof OpaqueWorkerClosed) return t('auth.errors.signInAgain')
  // Made again once and still refused: the server's key changed twice, or
  // the bindings drawn were taken twice.
  if (error instanceof RegistrationConflictError) {
    return t(error.code === 'opaqueKeyStale' ? 'auth.errors.serverKeyChanged' : 'auth.errors.keyBindingTaken')
  }
  const code = apiErrorCode(error)
  if (code === 'too_many_requests') {
    // The address's limiter (a minute) or the account's lockout (a while).
    return t(bodyCode(error) === 'rateLimited' ? 'auth.errors.slowDown' : 'auth.errors.locked')
  }
  if (code === 'network') return t('auth.errors.network')
  if (code === 'unauthenticated') return t(fallbackKey)
  if (code === 'conflict') {
    const message = apiErrorMessage(error, '')
    if (message.includes('username')) return t('auth.errors.usernameTaken')
    return t(fallbackKey)
  }
  return apiErrorMessage(error, t(fallbackKey))
}

function bodyCode(error: unknown): string | undefined {
  return isAxiosError(error) ? (error.response?.data as { code?: string } | undefined)?.code : undefined
}
