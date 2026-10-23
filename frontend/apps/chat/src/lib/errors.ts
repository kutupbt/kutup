import type { TFunction } from 'i18next'
import { ChatServiceError } from '@kutup/chat-core/service'

/**
 * What to tell someone when a chat action fails. Service failures have
 * their own sentence; everything else is "temporarily unavailable" rather
 * than a raw error.
 */
export function chatErrorMessage(error: unknown, t: TFunction): string {
  if (error instanceof ChatServiceError) return t(`chat.errors.${error.code}`)
  return t('chat.errors.unavailable')
}
