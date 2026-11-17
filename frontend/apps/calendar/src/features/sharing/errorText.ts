import type { useTranslation } from 'react-i18next'
import { apiErrorMessage } from '@kutup/ui/lib/apiError'
import { AlreadyShared, OtherServer, RecipientNotFound, SelfShare, TooManyMembers } from './client'

type Translate = ReturnType<typeof useTranslation>['t']

/** What went wrong with an invitation, in words. */
export function inviteErrorText(error: unknown, t: Translate): string {
  if (error instanceof RecipientNotFound) return t('sharing.errors.notFound', { address: error.address })
  if (error instanceof SelfShare) return t('sharing.errors.self')
  if (error instanceof OtherServer) return t('sharing.errors.otherServer', { address: error.address })
  if (error instanceof AlreadyShared) return t('sharing.errors.already', { address: error.address })
  if (error instanceof TooManyMembers) return t('sharing.errors.tooMany', { count: error.limit })
  return apiErrorMessage(error, t('sharing.errors.inviteFailed'))
}
