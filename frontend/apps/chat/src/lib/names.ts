import type { TFunction } from 'i18next'
import type { ChatHistoryEntry, ConversationId, MlsGroupInfo, PeerChatProfile } from '@kutup/chat-core/types'
import type { MessageMutationState } from '../state/views'
import { groupUpdateSentences } from './groupUpdate'

/** A group's name; one never named shows "Group" and the start of its id. */
export function groupTitle(groupId: string, t: TFunction, info?: MlsGroupInfo | null): string {
  return info?.name || t('chat.group.untitled', { id: groupId.slice(0, 8) })
}

/** What to call a person: "You", their profile name, else their address. */
export function personName(
  address: string,
  profiles: ReadonlyMap<string, PeerChatProfile>,
  selfAddress: string,
  t: TFunction,
): string {
  if (address === selfAddress) return t('chat.you')
  return profiles.get(address)?.displayName || address
}

/** A conversation's title. */
export function conversationTitle(
  conversation: ConversationId,
  address: string | null,
  profile: PeerChatProfile | null,
  selfAddress: string,
  t: TFunction,
  groupInfo?: MlsGroupInfo | null,
): string {
  if (conversation.kind === 'group') return groupTitle(conversation.groupId, t, groupInfo)
  if (address === selfAddress) return t('chat.noteToSelf')
  return profile?.displayName || address || ''
}

/**
 * One line for a message: its (edited) text, or what it carries. A group
 * change notice reads as its first sentence (`self` and `nameOf` word it).
 */
export function messagePreview(
  entry: ChatHistoryEntry,
  mutation: MessageMutationState | null | undefined,
  t: TFunction,
  notice?: { self: string; nameOf: (address: string) => string },
): string {
  if (entry.content.groupUpdate && entry.conversation.kind === 'group' && notice) {
    return groupUpdateSentences(entry.content.groupUpdate, notice.self, notice.nameOf, t)[0] ?? ''
  }
  if (mutation?.deleted) {
    return entry.direction === 'outgoing' ? t('chat.mutations.youDeleted') : t('chat.mutations.deleted')
  }
  const text = mutation?.editedText ?? entry.content.text
  if (text) return text
  const attachment = entry.content.attachment
  if (attachment && entry.content.sticker) return t('chat.preview.sticker', { emoji: entry.content.sticker.emoji ?? '' }).trim()
  if (attachment) {
    if (attachment.durationMs !== undefined && attachment.mediaClass === 'audio') return t('chat.preview.voice')
    if (attachment.mediaClass === 'photo') return attachment.caption || t('chat.preview.photo')
    if (attachment.mediaClass === 'video') return attachment.caption || t('chat.preview.video')
    return attachment.filename
  }
  if (entry.content.disappearingTimer) return t('chat.preview.timer')
  if (entry.content.poll) return t('chat.preview.poll', { question: entry.content.poll.question })
  return t('chat.newerClient')
}
