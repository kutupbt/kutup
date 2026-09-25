import { useCallback } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { uploadChatMediaV1 } from '@kutup/chat-core/media'
import type { ChatReactionEmoji } from '@kutup/chat-core/reactions'
import type { ConversationId, SendSummary } from '@kutup/chat-core/types'
import { freshAccessToken } from '@kutup/session/client'
import { formatBytes } from '@kutup/ui/lib/format'
import { refreshChat, useChat } from '../../app/chatStore'
import { chatErrorMessage } from '../../lib/errors'

/**
 * What can be done in one conversation, each followed by a reload so the
 * result shows at once. A send whose recipient's device identity changed
 * warns about it (verify the safety number). Failures say what happened
 * and are rethrown for the caller to keep the draft.
 */
export function useConversationActions(conversation: ConversationId, timerSeconds: number | undefined) {
  const { t, i18n } = useTranslation()
  const { service, capabilities } = useChat()

  const after = useCallback(
    async (summary: SendSummary) => {
      if (summary.safetyNumberChanges.length > 0) toast.warning(t('chat.safetyNumberChanged'))
      await refreshChat()
    },
    [t],
  )

  const run = useCallback(
    async <T,>(work: () => Promise<T>): Promise<T> => {
      try {
        return await work()
      } catch (error) {
        toast.error(chatErrorMessage(error, t))
        throw error
      }
    },
    [t],
  )

  const send = useCallback(
    (text: string, replyTo?: string) =>
      run(async () => after(await service!.send(conversation, text, replyTo, timerSeconds))),
    [run, after, service, conversation, timerSeconds],
  )

  const edit = useCallback(
    (messageId: string, text: string) =>
      run(async () => after(await service!.mutateMessage(conversation, messageId, 'edit', text))),
    [run, after, service, conversation],
  )

  const remove = useCallback(
    (messageId: string) => run(async () => after(await service!.mutateMessage(conversation, messageId, 'delete'))),
    [run, after, service, conversation],
  )

  /** Gone from this account's devices only. */
  const deleteForMe = useCallback(
    (messageId: string) =>
      run(async () => {
        await service!.deleteForMe(conversation, [messageId])
        await refreshChat()
      }),
    [run, service, conversation],
  )

  const react = useCallback(
    (messageId: string, emoji: ChatReactionEmoji, active: boolean) =>
      run(async () => after(await service!.sendReaction(conversation, messageId, emoji, active))),
    [run, after, service, conversation],
  )

  const setTimer = useCallback(
    (seconds: number | undefined) =>
      run(async () => after(await service!.sendDisappearingTimer(conversation, seconds))),
    [run, after, service, conversation],
  )

  /** Encrypt, upload and send one file (a voice note carries its length). */
  const sendFile = useCallback(
    async (file: File, options: { durationMs?: number; onProgress?: (sent: number, total: number) => void; signal?: AbortSignal } = {}) => {
      const media = capabilities?.media
      if (media && file.size > media.maximumPlaintextBytes) {
        const message = t('chat.attachments.tooLarge', { limit: formatBytes(media.maximumPlaintextBytes, i18n.language) })
        toast.error(message)
        throw new Error(message)
      }
      return run(async () => {
        if (!media || !capabilities?.serverName) throw new Error('media is not available')
        const uploaded = await uploadChatMediaV1({
          file,
          originDomain: capabilities.serverName,
          accessToken: await freshAccessToken(),
          ...options,
        })
        await after(await service!.sendAttachment(conversation, uploaded.descriptor, uploaded.storageReferenceId, timerSeconds))
      })
    },
    [run, after, service, capabilities, conversation, timerSeconds, t, i18n.language],
  )

  return { send, edit, remove, deleteForMe, react, setTimer, sendFile }
}
