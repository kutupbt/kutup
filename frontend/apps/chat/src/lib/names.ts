import type { TFunction } from 'i18next'
import type { ChatHistoryEntry, ConversationId, MlsGroupInfo, PeerChatProfile } from '@kutup/chat-core/types'
import { undecryptableState, type MessageMutationState } from '../state/views'
import { callLogText } from './callText'
import { groupUpdateSentences } from './groupUpdate'
import { accountName } from '../state/accountNames'

/** A group's name; one never named shows "Group" and the start of its id. */
export function groupTitle(groupId: string, t: TFunction, info?: Pick<MlsGroupInfo, 'name'> | { name?: string | null } | null): string {
  return info?.name || t('chat.group.untitled', { id: groupId.slice(0, 8) })
}

/**
 * What to call a person (`key`: their account): "You", their profile name,
 * else an address for the account (`accountName`), never the key itself.
 */
export function personName(
  key: string,
  profiles: ReadonlyMap<string, Pick<PeerChatProfile, 'displayName'>>,
  selfKey: string,
  t: TFunction,
): string {
  if (key === selfKey) return t('chat.you')
  return profiles.get(key)?.displayName || accountName(key) || t('chat.someone')
}

/** A conversation's title. */
export function conversationTitle(
  conversation: ConversationId,
  key: string | null,
  profile: PeerChatProfile | null,
  selfKey: string,
  t: TFunction,
  groupInfo?: Pick<MlsGroupInfo, 'name'> | { name?: string | null } | null,
): string {
  if (conversation.kind === 'group') return groupTitle(conversation.groupId, t, groupInfo)
  if (key === selfKey) return t('chat.noteToSelf')
  return profile?.displayName || (key && accountName(key)) || t('chat.someone')
}

/**
 * One line for a message: its (edited) text, or what it carries. A group
 * change notice reads as its first sentence (`self` and `nameOf` word it).
 */
export function messagePreview(
  entry: ChatHistoryEntry,
  mutation: MessageMutationState | null | undefined,
  t: TFunction,
  notice?: { self: string; nameOf: (key: string) => string },
): string {
  if (entry.content.groupUpdate && entry.conversation.kind === 'group' && notice) {
    return groupUpdateSentences(entry.content.groupUpdate, notice.self, notice.nameOf, t)[0] ?? ''
  }
  if (entry.content.callLog) return callLogText(entry.content.callLog, t)
  if (entry.content.undecryptable) return t(undecryptableState(entry) === 'waiting' ? 'chat.undecryptable.waitingPreview' : 'chat.undecryptable.preview')
  if (entry.content.groupCall) {
    return entry.content.groupCall.event === 'started' ? t('chat.calls.groupStartedPreview') : t('chat.calls.groupEndedPreview')
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
  if (entry.content.liveLocation) return t('chat.preview.liveLocation')
  if (entry.content.location) {
    return entry.content.location.label
      ? t('chat.preview.location', { label: entry.content.location.label })
      : t('chat.preview.locationUnnamed')
  }
  return t('chat.newerClient')
}
