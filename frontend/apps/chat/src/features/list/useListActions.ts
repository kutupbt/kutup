import { useCallback, useMemo } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { isAccountControl, isVisibleChatMessage } from '@kutup/chat-core/disappearing'
import { conversationKey } from '@kutup/chat-core/identity'
import { MUTED_FOREVER_MS, type ChatHistoryEntry, type ConversationId } from '@kutup/chat-core/types'
import { refreshChat, useChat } from '../../app/chatStore'
import { chatErrorMessage } from '../../lib/errors'
import { MAX_PINNED, isArchived, nextListState, type ListState } from '../../state/accountState'
import { markRead } from '../../state/readState'
import { useAccountState } from '../../state/useAccountState'

/** Signal's mute choices. */
export const MUTE_PRESETS = [
  { id: 'hour', ms: 60 * 60 * 1000 },
  { id: 'eightHours', ms: 8 * 60 * 60 * 1000 },
  { id: 'day', ms: 24 * 60 * 60 * 1000 },
  { id: 'week', ms: 7 * 24 * 60 * 60 * 1000 },
  { id: 'always', ms: null },
] as const

export type MutePreset = (typeof MUTE_PRESETS)[number]['id']

/**
 * What can be done to a conversation from the list (and the thread's
 * menu): pin, mark read or unread, mute, archive, delete for me. Every
 * change goes to this account's other devices too.
 */
export function useListActions() {
  const { t } = useTranslation()
  const { service, snapshot } = useChat()
  const { lists } = useAccountState()

  const pinnedCount = useMemo(() => [...lists.values()].filter((state) => state.pinned).length, [lists])

  const run = useCallback(
    async (work: () => Promise<void>) => {
      try {
        await work()
        await refreshChat()
      } catch (error) {
        toast.error(chatErrorMessage(error, t))
      }
    },
    [t],
  )

  const update = useCallback(
    (conversation: ConversationId, patch: Partial<Pick<ListState, 'pinned' | 'archived' | 'mutedUntilMs' | 'markedUnread'>>) =>
      run(() => service!.setConversationState(nextListState(conversation, lists.get(conversationKey(conversation)), patch))),
    [run, service, lists],
  )

  const newestIncoming = useCallback(
    (key: string): ChatHistoryEntry | null => {
      const nowMs = Date.now()
      let newest: ChatHistoryEntry | null = null
      for (const message of snapshot.history) {
        if (
          message.direction === 'incoming' &&
          message.content.messageId &&
          conversationKey(message.conversation) === key &&
          isVisibleChatMessage(message, nowMs)
        ) {
          newest = message
        }
      }
      return newest
    },
    [snapshot.history],
  )

  return useMemo(
    () => ({
      state: (conversation: ConversationId) => lists.get(conversationKey(conversation)),

      pin: (conversation: ConversationId, pinned: boolean) => {
        if (pinned && pinnedCount >= MAX_PINNED) {
          toast.error(t('chat.list.pinLimit', { count: MAX_PINNED }))
          return Promise.resolve()
        }
        // A pinned chat is never archived.
        return update(conversation, pinned ? { pinned, archived: false } : { pinned })
      },

      markUnread: (conversation: ConversationId) => update(conversation, { markedUnread: true }),

      markRead: (conversation: ConversationId) => {
        const key = conversationKey(conversation)
        const newest = newestIncoming(key)
        const state = lists.get(key)
        return run(async () => {
          if (newest) {
            markRead(key, newest.timestampMs)
            await service!.markReadThrough(newest.conversation, newest.content.messageId!, newest.timestampMs)
          }
          if (state?.markedUnread) {
            await service!.setConversationState(nextListState(conversation, state, { markedUnread: false }))
          }
        })
      },

      mute: (conversation: ConversationId, preset: MutePreset) => {
        const ms = MUTE_PRESETS.find((option) => option.id === preset)?.ms
        return update(conversation, { mutedUntilMs: ms === null || ms === undefined ? MUTED_FOREVER_MS : Date.now() + ms })
      },

      unmute: (conversation: ConversationId) => update(conversation, { mutedUntilMs: undefined }),

      // Archiving unpins, as in Signal.
      archive: (conversation: ConversationId, archived: boolean) =>
        update(conversation, archived ? { archived, pinned: false } : { archived }),

      isArchived: (conversation: ConversationId, last: ChatHistoryEntry | null, nowMs: number) =>
        isArchived(lists.get(conversationKey(conversation)), last, nowMs),

      /** Remove every message of the conversation from this account's history. */
      deleteChat: (conversation: ConversationId) => {
        const key = conversationKey(conversation)
        const ids = snapshot.history.flatMap((message) =>
          conversationKey(message.conversation) === key && message.content.messageId && !isAccountControl(message)
            ? [message.content.messageId]
            : [],
        )
        return run(async () => {
          if (ids.length > 0) await service!.deleteForMe(conversation, ids)
          const state = lists.get(key)
          if (state?.pinned || state?.archived) {
            await service!.setConversationState(nextListState(conversation, state, { pinned: false, archived: false }))
          }
        })
      },
    }),
    [lists, pinnedCount, t, update, newestIncoming, run, service, snapshot.history],
  )
}
