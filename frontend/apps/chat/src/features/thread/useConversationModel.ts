import { useMemo } from 'react'
import { useTranslation } from 'react-i18next'
import { mlsGroupInvitationReadiness, type MlsGroupInvitationReadiness } from '@kutup/chat-core/group-readiness'
import { canonicalAccountAddress, conversationKey, directAddress } from '@kutup/chat-core/identity'
import type { ContactRecord, ConversationId, LocalMlsConversationRecord, PeerChatProfile } from '@kutup/chat-core/types'
import { useChat } from '../../app/chatStore'
import { conversationTitle } from '../../lib/names'
import { activeTimers, groupIdOf, threadView, type MessageView } from '../../state/views'

/** Why nothing can be written here (the composer's place shows it). */
export type ReadOnlyReason =
  | 'request'
  | 'blocked'
  | 'history'
  | 'closed'
  | 'adminsOnly'
  | 'pendingInvitations'

export interface ConversationModel {
  key: string
  conversation: ConversationId
  title: string
  /** Direct conversations and notes: the peer's canonical address. */
  address: string | null
  note: boolean
  profile: PeerChatProfile | null
  contact: ContactRecord | null
  group: LocalMlsConversationRecord | null
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
  canEditGroupInfo: boolean
}

const noReadiness: MlsGroupInvitationReadiness = { pending: [], refused: [], blocksSending: false }

/** Everything a conversation's screen needs, derived from the chat state. */
export function useConversationModel(conversation: ConversationId, now: number): ConversationModel {
  const { t } = useTranslation()
  const { snapshot, self } = useChat()
  const selfAddress = self!.address

  return useMemo(() => {
    const key = conversationKey(conversation)
    const address = directAddress(conversation)
    const note = address === selfAddress
    const profile = address ? (snapshot.profiles.find((p) => p.peer === address) ?? null) : null
    const contact = address ? (snapshot.contacts.find((c) => c.peer === address) ?? null) : null
    const group =
      conversation.kind === 'group' ? (snapshot.groups.find((g) => groupIdOf(g) === conversation.groupId) ?? null) : null
    const historyOnly = conversation.kind === 'group' && !group
    const me = group?.currentRoster.find((m) => canonicalAccountAddress(m.address) === selfAddress)
    const isAdmin = me?.isAdmin === true
    const readiness = group ? mlsGroupInvitationReadiness(group, snapshot.invitationFeedback, selfAddress) : noReadiness

    let readOnly: ReadOnlyReason | null = null
    if (contact?.state === 'pendingIncoming') readOnly = 'request'
    else if (contact?.state === 'blocked') readOnly = 'blocked'
    else if (historyOnly) readOnly = 'history'
    else if (group?.status === 'closed') readOnly = 'closed'
    else if (group && group.currentAuthorizationPolicy.applicationSenders !== 1 && !isAdmin) readOnly = 'adminsOnly'
    else if (readiness.blocksSending) readOnly = 'pendingInvitations'

    const established = conversation.kind === 'group' || note || contact?.state === 'accepted'
    return {
      key,
      conversation,
      title: conversationTitle(conversation, address, profile, selfAddress, t, group?.currentGroupInfo),
      address,
      note,
      profile,
      contact,
      group,
      historyOnly,
      isAdmin,
      readiness,
      views: threadView(snapshot.history, key, selfAddress, now),
      timerSeconds: activeTimers(snapshot.history).get(key),
      readOnly,
      canSendMedia: !readOnly && established,
      canSetTimer: !readOnly && established,
      // Rename the group, change its picture or description (Signal's "Edit group").
      canEditGroupInfo:
        group !== null &&
        group.status === 'active' &&
        (isAdmin || group.currentAuthorizationPolicy.groupInfoEditors === 1),
      canSendTyping:
        !readOnly && !note && (conversation.kind === 'group' || contact?.state === 'accepted' || contact?.state === 'pendingOutgoing'),
    }
  }, [conversation, snapshot, selfAddress, now, t])
}
