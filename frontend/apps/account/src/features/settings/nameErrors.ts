import type { useTranslation } from 'react-i18next'
import { ReauthLockedError, WrongPasswordError } from '@kutup/session/reauth'
import { formatInstant } from '@kutup/ui/lib/format'
import { NameRefusedError } from './rename'

type TFunction = ReturnType<typeof useTranslation>['t']

/** What to say about an error of a rename or a drop. */
export function nameErrorMessage(t: TFunction, error: unknown, locale: string, fallback: string): string {
  if (error instanceof WrongPasswordError) return t('settings.security.wrongCurrentPassword')
  if (error instanceof ReauthLockedError) return t(error.reason === 'rateLimited' ? 'auth.errors.slowDown' : 'auth.errors.locked')
  if (!(error instanceof NameRefusedError)) return fallback
  const date = formatInstant(error.retryAt, locale)
  switch (error.code) {
    case 'renameTooSoon':
      return date ? t('settings.account.rename.errors.tooSoon', { date }) : t('settings.account.rename.errors.tooSoonNoDate')
    case 'dropTooSoon':
      return date ? t('settings.account.names.errors.tooSoon', { date }) : t('settings.account.names.errors.tooSoonNoDate')
    case 'nameTaken':
      return t('settings.account.rename.reason.taken')
    case 'nameReserved':
      return t('settings.account.rename.reason.reserved')
    case 'tooManyHeldNames':
      return t('settings.account.rename.errors.tooManyHeld')
    case 'breakGlassAccount':
      return t('settings.account.rename.errors.breakGlass')
    case 'setupRequired':
      return t('settings.account.rename.errors.setupRequired')
    case 'renameConflict':
      return t('settings.account.rename.errors.conflict')
    case 'notHeld':
      return t('settings.account.names.errors.notHeld')
    default:
      return fallback
  }
}
