import type { useTranslation } from 'react-i18next'
import { apiErrorCode, apiErrorMessage } from '@kutup/ui/lib/apiError'

type TFunction = ReturnType<typeof useTranslation>['t']

/**
 * A sign-in failure worth showing. 429 gets its own words: retrying extends a
 * lockout. Rejected credentials read the same whether the account exists or
 * not, in the person's language; the server's English is never shown. A
 * registration conflict on the username says so.
 */
export function authErrorMessage(error: unknown, t: TFunction, fallbackKey: string): string {
  const code = apiErrorCode(error)
  if (code === 'too_many_requests') return t('auth.errors.locked')
  if (code === 'network') return t('auth.errors.network')
  if (code === 'unauthenticated') return t(fallbackKey)
  if (code === 'conflict') {
    const message = apiErrorMessage(error, '')
    if (message.includes('username')) return t('auth.errors.usernameTaken')
    return t(fallbackKey)
  }
  return apiErrorMessage(error, t(fallbackKey))
}
