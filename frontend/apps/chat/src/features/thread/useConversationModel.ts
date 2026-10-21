import { useMemo } from 'react'
import { useTranslation } from 'react-i18next'
import { mlsGroupInvitationReadiness, type MlsGroupInvitationReadiness } from '@kutup/chat-core/group-readiness'
import { accountKey, conversationKey, directKey } from '@kutup/chat-core/identity'
import type { ChatGroupCall, ChatGroupSummary, ChatHistoryEntry, ContactRecord, ConversationId, LocalMlsConversationRecord, PeerChatProfile } from '@kutup/chat-core/types'
import { useChat } from '../../app/chatStore'
import { conversationTitle } from '../../lib/names'
import { activeGroupCall } from '../calls/groupCallController'
import { activeTimers, groupIdOf, threadView, type MessageView } from '../../state/views'
import { useThreadPages } from '../../state/threadPages'
import { accountName } from '../../state/accountNames'

/** Why nothing can be written here (the composer's place shows it). */
export type ReadOnlyReason =
  | 'request'
  | 'blocked'
  | 'history'
  | 'left'
  | 'closed'
  | 'adminsOnly'
  | 'pendingInvitations'
  /** Invited to a pairwise group: join or decline first. */
  | 'invitation'
  /** Asked to join a pairwise group; an administrator decides. */
  | 'requesting'
  /** No longer in a pairwise group (left, removed or declined). */
  | 'notMember'

export interface ConversationModel {
  key: string
  /** Read older messages in (scrolled to the top). */
  loadOlder: () => void
  /** Every message back to the start is read in. */
  complete: boolean
  /** Back at the newest messages: let go of the older ones read in. */
  trim: () => void
  conversation: ConversationId
  title: string
  /** Direct conversations and notes: the other account's key (never shown). */
  peer: string | null
  /** An address to show for that account (`accountName`), once known. */
  address: string | null
  note: boolean
  profile: PeerChatProfile | null
  contact: ContactRecord | null
  group: LocalMlsConversationRecord | null
  /** A pairwise group (docs/plans/pairwise-groups.md), this account's standing in it. */
  chatGroup: ChatGroupSummary | null
  /** Who invited this account to `chatGroup`, and whether they aren't a contact (a request). */
  groupInviter: string | null
  groupInviteRequest: boolean
  /** Only text and replies can be sent here (a pairwise group, slice 1). */
  textOnly: boolean
  /** Group messages this account wrote before losing the live group. */
  historyOnly: boolean
  isAdmin: boolean
  readiness: MlsGroupInvitationReadiness
  views: MessageView[]
  timerSeconds: number | undefined
  readOnly: ReadOnlyReason | null
  canSendMedia: boolean
  canSetTimer: boolean
  canSendTyping: boolean
  canCall: boolean
  /** The group call in progress here, if any. */
  groupCall: ChatGroupCall | null
  /** This account can start a group call here (its server hosts them). */
  canStartGroupCall: boolean
  canEditGroupInfo: boolean
}

const noReadiness: MlsGroupInvitationReadiness = { pending: [], refused: [], blocksSending: false }

/** Everything a conversation's screen needs, derived from the chat state. */
export function useConversationModel(conversation: ConversationId, now: number): ConversationModel {
  const { t } = useTranslation()
  const { snapshot, self, capabilities, namesRevision } = useChat()
  const selfKey = self!.key
  const thread = useThreadPages(conversationKey(conversation))
  // The live window and the conversation's pages read in so far.
  const history = useMemo(() => mergeHistory(snapshot.history, thread.entries), [snapshot.history, thread.entries])

  return useMemo(() => {
    const key = conversationKey(conversation)
    const peer = directKey(conversation)
    const note = peer === selfKey
    const profile = peer ? (snapshot.profiles.find((p) => p.peer === peer) ?? null) : null
    const contact = peer ? (snapshot.contacts.find((c) => c.peer === peer) ?? null) : null
    const group =
      conversation.kind === 'group' ? (snapshot.groups.find((g) => groupIdOf(g) === conversation.groupId) ?? null) : null
    const chatGroup =
      conversation.kind === 'group' ? (snapshot.chatGroups.find((g) => g.groupId === conversation.groupId) ?? null) : null
    const historyOnly = conversation.kind === 'group' && !group && !chatGroup
    const groupInviter = chatGroup?.status === 'invited' ? (chatGroup.inviter ?? null) : null
    const inviterContact = groupInviter ? snapshot.contacts.find((c) => c.peer === groupInviter) : undefined
    const groupInviteRequest =
      groupInviter !== null && inviterContact?.state !== 'accepted' && inviterContact?.state !== 'pendingOutgoing'
    const me = group?.currentRoster.find((m) => accountKey(m.account) === selfKey)
    const isAdmin = me?.isAdmin === true
    const readiness = group ? mlsGroupInvitationReadiness(group, snapshot.invitationFeedback, selfKey) : noReadiness

    let readOnly: ReadOnlyReason | null = null
    if (contact?.state === 'pendingIncoming') readOnly = 'request'
    else if (contact?.state === 'blocked') readOnly = 'blocked'
    else if (historyOnly) readOnly = 'history'
    else if (chatGroup?.status === 'invited') readOnly = 'invitation'
    else if (chatGroup?.status === 'requesting') readOnly = 'requesting'
    else if (chatGroup?.status === 'gone') readOnly = 'notMember'
    else if (chatGroup?.terminated) readOnly = 'closed'
    else if (chatGroup && !chatGroup.maySend) readOnly = 'adminsOnly'
    else if (group?.left) readOnly = 'left'
    else if (group?.status === 'closed') readOnly = 'closed'
    else if (group && group.currentAuthorizationPolicy.applicationSenders !== 1 && !isAdmin) readOnly = 'adminsOnly'
    else if (readiness.blocksSending) readOnly = 'pendingInvitations'

    const established = conversation.kind === 'group' || note || contact?.state === 'accepted'
    return {
      key,
      conversation,
      title: conversationTitle(
        conversation,
        peer,
        profile,
        selfKey,
        t,
        group?.currentGroupInfo ?? (chatGroup ? { name: chatGroup.title } : null),
      ),
      peer,
      address: note ? self!.address : peer ? accountName(peer) : null,
      note,
      profile,
      contact,
      group,
      chatGroup,
      groupInviter,
      groupInviteRequest,
      textOnly: chatGroup !== null,
      historyOnly,
      isAdmin,
      readiness,
      views: threadView(history, key, selfKey, now),
      timerSeconds: activeTimers(history).get(key),
      loadOlder: thread.loadOlder,
      complete: thread.complete,
      trim: thread.trim,
      readOnly,
      canSendMedia: !readOnly && established && !chatGroup,
      canSetTimer: !readOnly && established && !chatGroup,
      // Rename the group, change its picture or description (Signal's "Edit group").
      canEditGroupInfo:
        group !== null &&
        group.status === 'active' &&
        !group.left &&
        (isAdmin || group.currentAuthorizationPolicy.groupInfoEditors === 1),
      canSendTyping:
        !readOnly && !note && !chatGroup &&
        (conversation.kind === 'group' || contact?.state === 'accepted' || contact?.state === 'pendingOutgoing'),
      // Signal rings only for accepted contacts; group calls come later.
      canCall: !readOnly && !note && conversation.kind === 'direct' && contact?.state === 'accepted',
      groupCall: group
        ? activeGroupCall(
            history.flatMap((entry) =>
              entry.content.groupCall && conversationKey(entry.conversation) === key
                ? [{ call: entry.content.groupCall, atMs: entry.timestampMs }]
                : []),
            now,
          )
        : null,
      canStartGroupCall: group !== null && !readOnly && capabilities?.groupCalls === true,
    }
    // `self` only for its shown address; a name that arrives later raises `namesRevision`.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [conversation, snapshot, history, thread.loadOlder, thread.complete, thread.trim, selfKey, now, t, capabilities, namesRevision])
}

/** Two histories as one, oldest first, each entry once (the first wins). */
function mergeHistory(
  window: readonly ChatHistoryEntry[],
  pages: readonly ChatHistoryEntry[],
): ChatHistoryEntry[] {
  if (pages.length === 0) return window as ChatHistoryEntry[]
  const byId = new Map<string, ChatHistoryEntry>()
  for (const entry of window) byId.set(entry.id, entry)
  for (const entry of pages) if (!byId.has(entry.id)) byId.set(entry.id, entry)
  return [...byId.values()].sort((left, right) => left.timestampMs - right.timestampMs || left.id.localeCompare(right.id))
}
