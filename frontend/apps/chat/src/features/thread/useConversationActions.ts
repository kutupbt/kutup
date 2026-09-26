import { useCallback } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import type { ChatReactionEmoji } from '@kutup/chat-core/reactions'
import type { ChatLocationV1, ChatMessageExtras, ChatPollV1, ConversationId, SendSummary } from '@kutup/chat-core/types'
import { formatBytes } from '@kutup/ui/lib/format'
import { refreshChat, useChat } from '../../app/chatStore'
import { chatErrorMessage } from '../../lib/errors'
import { uploadAndSend } from '../../lib/sendMedia'
import { getDefaultTimerSeconds } from '../../state/prefs'
import { owePendingDefaultTimer, pendingDefaultTimer } from '../../lib/pendingTimers'
import { conversationKey } from '@kutup/chat-core/identity'

/**
 * What can be done in one conversation, each followed by a reload so the
 * result shows at once. A send whose recipient's device identity changed
 * warns about it (verify the safety number). Failures say what happened
 * and are rethrown for the caller to keep the draft.
 */
export function useConversationActions(
  conversation: ConversationId,
  timerSeconds: number | undefined,
  options: {
    /** Nothing was said here yet: the default timer for new chats applies. */
    fresh?: boolean
    /** A timer can be set now (a group, or an accepted direct chat). */
    established?: boolean
  } = {},
) {
  const { t, i18n } = useTranslation()
  const { service, capabilities, self } = useChat()
  const { fresh = false, established = true } = options

  /**
   * The timer for the next message. A fresh chat takes the default: set at
   * once where it can be, otherwise owed until the chat is accepted (the
   * messages carry it meanwhile).
   */
  const timerFor = useCallback(async (): Promise<number | undefined> => {
    if (timerSeconds !== undefined) return timerSeconds
    const account = self?.address ?? ''
    const key = conversationKey(conversation)
    const owed = pendingDefaultTimer(account, key)
    if (owed !== undefined) return owed
    if (!fresh) return undefined
    const seconds = getDefaultTimerSeconds()
    if (!seconds) return undefined
    if (established) await service!.sendDisappearingTimer(conversation, seconds)
    else owePendingDefaultTimer(account, key, seconds)
    return seconds
  }, [fresh, established, timerSeconds, service, conversation, self])

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
    (text: string, replyTo?: string, extras?: ChatMessageExtras) =>
      run(async () => after(await service!.send(conversation, text, replyTo, await timerFor(), extras))),
    [run, after, service, conversation, timerFor],
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
    async (
      file: File,
      options: {
        durationMs?: number
        withoutPreview?: boolean
        extras?: ChatMessageExtras
        onProgress?: (sent: number, total: number) => void
        signal?: AbortSignal
      } = {},
    ) => {
      const media = capabilities?.media
      if (media && file.size > media.maximumPlaintextBytes) {
        const message = t('chat.attachments.tooLarge', { limit: formatBytes(media.maximumPlaintextBytes, i18n.language) })
        toast.error(message)
        throw new Error(message)
      }
      return run(async () => {
        if (!capabilities) throw new Error('media is not available')
        await after(await uploadAndSend(service!, capabilities, conversation, file, { ...options, timerSeconds: await timerFor() }))
      })
    },
    [run, after, service, capabilities, conversation, timerFor, t, i18n.language],
  )

  const sendPoll = useCallback(
    (poll: ChatPollV1) => run(async () => after(await service!.sendPoll(conversation, poll, await timerFor()))),
    [run, after, service, conversation, timerFor],
  )

  const sendLocation = useCallback(
    (location: ChatLocationV1) => run(async () => after(await service!.sendLocation(conversation, location, await timerFor()))),
    [run, after, service, conversation, timerFor],
  )

  const votePoll = useCallback(
    (pollId: string, options: number[]) => run(async () => after(await service!.votePoll(conversation, pollId, options))),
    [run, after, service, conversation],
  )

  const endPoll = useCallback(
    (pollId: string) => run(async () => after(await service!.endPoll(conversation, pollId))),
    [run, after, service, conversation],
  )

  return { send, edit, remove, deleteForMe, react, setTimer, sendFile, sendPoll, sendLocation, votePoll, endPoll }
}
