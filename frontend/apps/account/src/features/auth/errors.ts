import type { useTranslation } from 'react-i18next'
import { apiErrorCode, apiErrorMessage } from '@kutup/ui/lib/apiError'

type TFunction = ReturnType<typeof useTranslation>['t']

/** A sign-in failure worth showing. 429 gets its own words: retrying extends a lockout. */
export function authErrorMessage(error: unknown, t: TFunction, fallbackKey: string): string {
  if (apiErrorCode(error) === 'too_many_requests') return t('auth.errors.locked')
  if (apiErrorCode(error) === 'network') return t('auth.errors.network')
  return apiErrorMessage(error, t(fallbackKey))
}
