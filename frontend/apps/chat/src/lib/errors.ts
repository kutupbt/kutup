import type { TFunction } from 'i18next'
import { InviteLinkError } from '@kutup/chat-core/invite-links'
import { MlsSendError } from '@kutup/chat-core/mls-service'
import { ChatServiceError } from '@kutup/chat-core/service'

/**
 * What to tell someone when a chat action fails. Service failures have
 * their own sentence; a failed group send says so (the step it failed at
 * goes to the console for diagnosis); everything else is "temporarily
 * unavailable" rather than a raw error.
 */
export function chatErrorMessage(error: unknown, t: TFunction): string {
  if (error instanceof ChatServiceError) return t(`chat.errors.${error.code}`)
  if (error instanceof InviteLinkError) return t(`chat.groupLink.errors.${error.kind}`)
  if (error instanceof MlsSendError) {
    console.warn('chat: group send failed at', error.stage, error.cause)
    return t('chat.errors.groupSend')
  }
  return t('chat.errors.unavailable')
}
