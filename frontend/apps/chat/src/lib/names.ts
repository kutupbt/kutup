import type { TFunction } from 'i18next'
import type { ChatHistoryEntry, ConversationId, PeerChatProfile } from '@kutup/chat-core/types'
import type { MessageMutationState } from '../state/views'

/** A group has no name of its own yet: "Group" and the start of its id. */
export function groupTitle(groupId: string, t: TFunction): string {
  return t('chat.group.untitled', { id: groupId.slice(0, 8) })
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
): string {
  if (conversation.kind === 'group') return groupTitle(conversation.groupId, t)
  if (address === selfAddress) return t('chat.noteToSelf')
  return profile?.displayName || address || ''
}

/** One line for a message: its (edited) text, or what it carries. */
export function messagePreview(
  entry: ChatHistoryEntry,
  mutation: MessageMutationState | null | undefined,
  t: TFunction,
): string {
  if (mutation?.deleted) {
    return entry.direction === 'outgoing' ? t('chat.mutations.youDeleted') : t('chat.mutations.deleted')
  }
  const text = mutation?.editedText ?? entry.content.text
  if (text) return text
  const attachment = entry.content.attachment
  if (attachment) {
    if (attachment.durationMs !== undefined && attachment.mediaClass === 'audio') return t('chat.preview.voice')
    if (attachment.mediaClass === 'photo') return attachment.caption || t('chat.preview.photo')
    if (attachment.mediaClass === 'video') return attachment.caption || t('chat.preview.video')
    return attachment.filename
  }
  if (entry.content.disappearingTimer) return t('chat.preview.timer')
  return t('chat.newerClient')
}
