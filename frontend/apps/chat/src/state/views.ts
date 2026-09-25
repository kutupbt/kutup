import {
  canonicalAccountAddress,
  conversationKey,
  directAddress,
  directConversation,
  parseAccountAddress,
} from '@kutup/chat-core/identity'
import { isVisibleChatMessage, reduceDisappearingTimers } from '@kutup/chat-core/disappearing'
import { compareContentOperations } from '@kutup/chat-core/ordering'
import {
  aggregateLatestReactions,
  type ReactionAggregate,
  type ReactionOperation,
} from '@kutup/chat-core/reactions'
import type {
  ChatGroupUpdate,
  ChatViewOnceOpenedV1,
  ChatHistoryEntry,
  ContactRecord,
  ConversationId,
  LocalMlsConversationRecord,
  MlsGroupInfo,
  PeerChatProfile,
} from '@kutup/chat-core/types'

// What the screens show, derived from the service's flat history. The
// service keeps every entry (messages, edits, deletes, reactions, receipts,
// timer changes) in one list; these functions fold them together. Pure, so
// the rules are tested once instead of living inside components.

/** Who wrote an entry: this account for outgoing ones, else the peer. */
export function messageActor(message: ChatHistoryEntry, selfAddress: string): string | null {
  if (message.direction === 'outgoing') return selfAddress
  return message.conversation.kind === 'direct' ? directAddress(message.conversation) : message.peer
}

/** The id other entries (replies, reactions, edits) point at. */
export function messageIdOf(message: ChatHistoryEntry): string {
  return message.content.messageId ?? message.id
}

export interface MessageMutationState {
  /** The latest edit's text, when the author edited it. */
  editedText?: string
  deleted: boolean
}

/**
 * Edits and deletes, per target message id. Only the author's own count;
 * the latest edit wins; a delete wins over any edit.
 */
export function foldMutations(
  history: readonly ChatHistoryEntry[],
  selfAddress: string,
): Map<string, MessageMutationState> {
  const targets = new Map<string, ChatHistoryEntry>()
  for (const message of history) {
    if (message.content.messageId && !message.content.mutation) targets.set(message.content.messageId, message)
  }
  const edits = new Map<string, ChatHistoryEntry>()
  const deleted = new Set<string>()
  for (const message of history) {
    const mutation = message.content.mutation
    if (!mutation) continue
    const target = targets.get(mutation.targetMessageId)
    if (!target || conversationKey(message.conversation) !== conversationKey(target.conversation)) continue
    const actor = messageActor(message, selfAddress)
    if (!actor || actor !== messageActor(target, selfAddress)) continue
    if (mutation.operation === 'delete') {
      deleted.add(mutation.targetMessageId)
      continue
    }
    const previous = edits.get(mutation.targetMessageId)
    if (!previous || compareContentOperations(previous, message) < 0) edits.set(mutation.targetMessageId, message)
  }
  const result = new Map<string, MessageMutationState>()
  for (const id of targets.keys()) {
    const editedText = edits.get(id)?.content.mutation?.replacementText
    if (editedText !== undefined || deleted.has(id)) result.set(id, { editedText, deleted: deleted.has(id) })
  }
  return result
}

/** Reactions on the messages of one conversation, latest per reactor. */
export function foldReactions(
  history: readonly ChatHistoryEntry[],
  key: string,
  targetIds: ReadonlySet<string>,
  selfAddress: string,
): Map<string, ReactionAggregate[]> {
  const operations: ReactionOperation[] = []
  for (const message of history) {
    const reaction = message.content.reaction
    if (!reaction || conversationKey(message.conversation) !== key || !targetIds.has(reaction.targetMessageId)) continue
    const reactor = messageActor(message, selfAddress)
    if (reactor) operations.push({ message, reaction, reactor })
  }
  return aggregateLatestReactions(operations, targetIds, selfAddress)
}

export interface ReceiptState {
  /** How many other people have it (delivered) and have read it. */
  delivered: number
  read: number
}

/** Receipts for this account's own messages, counted per other person. */
export function foldReceipts(
  history: readonly ChatHistoryEntry[],
  selfAddress: string,
): Map<string, ReceiptState> {
  const own = new Map<string, ChatHistoryEntry>()
  for (const message of history) {
    if (message.direction === 'outgoing' && message.content.messageId) own.set(message.content.messageId, message)
  }
  const states = new Map<string, 'delivered' | 'read'>()
  for (const message of history) {
    const receipt = message.content.receipt
    if (!receipt || message.direction !== 'incoming') continue
    const actor = messageActor(message, selfAddress)
    if (!actor || actor === selfAddress) continue
    for (const id of receipt.messageIds) {
      const target = own.get(id)
      if (!target || conversationKey(target.conversation) !== conversationKey(message.conversation)) continue
      const slot = `${id}\u0000${actor}`
      if (receipt.state === 'read' || !states.has(slot)) states.set(slot, receipt.state)
    }
  }
  const result = new Map<string, ReceiptState>()
  for (const [slot, state] of states) {
    const id = slot.slice(0, slot.indexOf('\u0000'))
    const current = result.get(id) ?? { delivered: 0, read: 0 }
    current.delivered += 1
    if (state === 'read') current.read += 1
    result.set(id, current)
  }
  return result
}

/** The inputs every view is derived from: one load of the service. */
export interface ChatData {
  history: ChatHistoryEntry[]
  contacts: ContactRecord[]
  profiles: PeerChatProfile[]
  groups: LocalMlsConversationRecord[]
}

export type ConversationKind = 'direct' | 'note' | 'group' | 'history'

export interface ConversationSummary {
  key: string
  conversation: ConversationId
  kind: ConversationKind
  /** The peer's canonical address, for direct conversations and notes. */
  address: string | null
  /** The newest visible message, if any. */
  last: ChatHistoryEntry | null
  /** When it last changed, for ordering (newest first). */
  activityMs: number
  contact: ContactRecord | null
  profile: PeerChatProfile | null
  /** A live group's name, description and picture. */
  groupInfo: MlsGroupInfo | null
}

/** When a group was made, in milliseconds (genesis records seconds or ms). */
function groupCreatedMs(group: LocalMlsConversationRecord): number {
  const at = group.request.genesis.createdAt
  return at < 1e12 ? at * 1000 : at
}

/** A group's conversation id. */
export function groupIdOf(group: LocalMlsConversationRecord): string {
  return group.request.genesis.conversationId
}

/**
 * The conversation list: direct chats (message requests included, as Signal
 * shows them; rejected ones left out), the note to self, live groups, and
 * groups whose history survives without a live group ("protected
 * history"), newest first.
 */
export function conversationList(data: ChatData, selfAddress: string, nowMs: number): ConversationSummary[] {
  const contacts = new Map(data.contacts.map((c) => [c.peer, c]))
  const profiles = new Map(data.profiles.map((p) => [p.peer, p]))
  const latest = new Map<string, ChatHistoryEntry>()
  for (const message of data.history) {
    // A group change notice counts as the latest activity (Signal shows it
    // as the preview), though it is not a message.
    if (isVisibleChatMessage(message, nowMs) || isGroupNotice(message)) latest.set(conversationKey(message.conversation), message)
  }
  const liveGroups = new Set(data.groups.map(groupIdOf))
  const items = new Map<string, ConversationSummary>()

  for (const [key, message] of latest) {
    const conversation = message.conversation
    if (conversation.kind === 'direct') {
      const address = directAddress(conversation)
      if (!address) continue
      const contact = contacts.get(address) ?? null
      if (contact?.state === 'rejected') continue
      items.set(key, {
        key,
        conversation,
        kind: address === selfAddress ? 'note' : 'direct',
        address,
        last: message,
        activityMs: message.timestampMs,
        contact,
        profile: profiles.get(address) ?? null,
        groupInfo: null,
      })
    } else if (!liveGroups.has(conversation.groupId)) {
      items.set(key, {
        key,
        conversation,
        kind: 'history',
        address: null,
        last: message,
        activityMs: message.timestampMs,
        contact: null,
        profile: null,
        groupInfo: null,
      })
    }
  }
  // A request whose messages are not here (yet) still shows.
  for (const contact of data.contacts) {
    if (contact.state !== 'pendingIncoming') continue
    const address = parseAccountAddress(contact.peer)
    if (!address) continue
    const conversation = directConversation(address)
    const key = conversationKey(conversation)
    if (items.has(key)) continue
    items.set(key, {
      key,
      conversation,
      kind: 'direct',
      address: canonicalAccountAddress(address),
      last: null,
      activityMs: contact.updatedAtMs,
      contact,
      profile: profiles.get(contact.peer) ?? null,
      groupInfo: null,
    })
  }
  for (const group of data.groups) {
    const conversation: ConversationId = { kind: 'group', groupId: groupIdOf(group) }
    const key = conversationKey(conversation)
    const last = latest.get(key) ?? null
    items.set(key, {
      key,
      conversation,
      kind: 'group',
      address: null,
      last,
      activityMs: last?.timestampMs ?? groupCreatedMs(group),
      contact: null,
      profile: null,
      groupInfo: group.currentGroupInfo ?? null,
    })
  }
  return [...items.values()].sort((a, b) => (b.activityMs || 0) - (a.activityMs || 0))
}

export interface MessageRequest {
  key: string
  conversation: ConversationId
  address: string
  contact: ContactRecord
  profile: PeerChatProfile | null
  last: ChatHistoryEntry | null
}

/** People who wrote first and are waiting for an answer, newest first. */
export function messageRequests(data: ChatData, nowMs: number): MessageRequest[] {
  const profiles = new Map(data.profiles.map((p) => [p.peer, p]))
  return data.contacts
    .filter((contact) => contact.state === 'pendingIncoming')
    .flatMap((contact) => {
      const address = parseAccountAddress(contact.peer)
      if (!address) return []
      const conversation = directConversation(address)
      const key = conversationKey(conversation)
      const last =
        data.history.filter((m) => conversationKey(m.conversation) === key && isVisibleChatMessage(m, nowMs)).at(-1) ?? null
      return [{ key, conversation, address: canonicalAccountAddress(address), contact, profile: profiles.get(contact.peer) ?? null, last }]
    })
    .sort((a, b) => b.contact.updatedAtMs - a.contact.updatedAtMs)
}

export interface MessageView {
  entry: ChatHistoryEntry
  id: string
  /** Who wrote it (canonical address). */
  author: string
  outgoing: boolean
  mutation: MessageMutationState | null
  /** The message this one replies to, when it is still here. */
  replyTo: ChatHistoryEntry | null
  replyToMutation: MessageMutationState | null
  reactions: ReactionAggregate[]
  receipt: ReceiptState | null
  /** A timer change shown as a notice rather than a bubble. */
  timerChange: { seconds?: number } | null
  /** A group change (renamed, member added…) shown as a notice. */
  groupUpdate: ChatGroupUpdate | null
  /** A view-once photo or video already opened: only "Viewed" is left. */
  viewedOnce: { video: boolean } | null
}

/** A group change notice: only the engine writes these, into group history. */
export function isGroupNotice(message: ChatHistoryEntry): boolean {
  return message.conversation.kind === 'group' && message.content.groupUpdate !== undefined
}

/** One conversation's timeline: visible messages and timer changes, in order. */
export function threadView(
  history: readonly ChatHistoryEntry[],
  key: string,
  selfAddress: string,
  nowMs: number,
): MessageView[] {
  const inThread = history.filter((m) => conversationKey(m.conversation) === key)
  // Opened view-once media, from this account's own controls.
  const opened = new Map<string, ChatViewOnceOpenedV1>()
  for (const message of history) {
    const body = message.content.viewOnceOpened
    if (
      body &&
      message.direction === 'outgoing' &&
      message.conversation.kind === 'direct' &&
      directAddress(message.conversation) === selfAddress &&
      conversationKey(body.conversation) === key
    ) {
      opened.set(body.messageId, body)
    }
  }
  const shown = inThread.filter(
    (m) =>
      (m.content.disappearingTimer || isGroupNotice(m) || isVisibleChatMessage(m, nowMs)) &&
      !(m.content.messageId && opened.has(m.content.messageId)),
  )
  const byId = new Map(shown.map((m) => [messageIdOf(m), m]))
  const mutations = foldMutations(inThread, selfAddress)
  const targetIds = new Set(shown.flatMap((m) => (m.content.messageId ? [m.content.messageId] : [])))
  const reactions = foldReactions(inThread, key, targetIds, selfAddress)
  const receipts = foldReceipts(inThread, selfAddress)
  const views = shown.map((entry): MessageView => {
    const id = messageIdOf(entry)
    const replyTo = entry.content.replyTo ? (byId.get(entry.content.replyTo) ?? null) : null
    return {
      entry,
      id,
      author: messageActor(entry, selfAddress) ?? entry.peer,
      outgoing: entry.direction === 'outgoing',
      mutation: mutations.get(id) ?? null,
      replyTo,
      replyToMutation: replyTo ? (mutations.get(messageIdOf(replyTo)) ?? null) : null,
      reactions: reactions.get(id) ?? [],
      receipt: receipts.get(id) ?? null,
      timerChange: entry.content.disappearingTimer ? { seconds: entry.content.disappearingTimer.durationSeconds } : null,
      groupUpdate: isGroupNotice(entry) ? entry.content.groupUpdate! : null,
      viewedOnce: null,
    }
  })
  if (opened.size === 0) return views
  const placeholders = [...opened.values()].map((body): MessageView => {
    const outgoing = body.sender === selfAddress
    return {
      entry: {
        id: `viewed:${body.messageId}`,
        conversation: body.conversation,
        peer: body.sender,
        direction: outgoing ? 'outgoing' : 'incoming',
        timestampMs: body.timestampMs,
        delivered: true,
        deduplicated: false,
        content: { version: 1, kind: 'viewOnceViewed', sentAt: '', seq: '0', body: null },
      },
      id: body.messageId,
      author: body.sender,
      outgoing,
      mutation: null,
      replyTo: null,
      replyToMutation: null,
      reactions: [],
      receipt: null,
      timerChange: null,
      groupUpdate: null,
      viewedOnce: { video: body.video },
    }
  })
  return [...views, ...placeholders].sort((a, b) => a.entry.timestampMs - b.entry.timestampMs)
}

/** The disappearing-messages timer in force in each conversation, in seconds. */
export function activeTimers(history: readonly ChatHistoryEntry[]): Map<string, number | undefined> {
  return new Map([...reduceDisappearingTimers([...history])].map(([key, timer]) => [key, timer.durationSeconds]))
}

/**
 * Incoming messages newer than `readUpTo` in each conversation (what the
 * list's badge counts): only real messages, not reactions, receipts or
 * expired ones.
 */
export function unreadCounts(
  history: readonly ChatHistoryEntry[],
  readUpTo: Readonly<Record<string, number>>,
  nowMs: number,
): Map<string, number> {
  const counts = new Map<string, number>()
  for (const message of history) {
    if (message.direction !== 'incoming' || !isVisibleChatMessage(message, nowMs)) continue
    const key = conversationKey(message.conversation)
    if (message.timestampMs > (readUpTo[key] ?? 0)) counts.set(key, (counts.get(key) ?? 0) + 1)
  }
  return counts
}

/** Conversations with an unread incoming message that mentions `selfAddress`. */
export function unreadMentions(
  history: readonly ChatHistoryEntry[],
  readUpTo: Readonly<Record<string, number>>,
  selfAddress: string,
  nowMs: number,
): Set<string> {
  const keys = new Set<string>()
  for (const message of history) {
    if (message.direction !== 'incoming' || !message.content.mentions?.length) continue
    if (!message.content.mentions.some((mention) => mention.member === selfAddress)) continue
    if (!isVisibleChatMessage(message, nowMs)) continue
    const key = conversationKey(message.conversation)
    if (message.timestampMs > (readUpTo[key] ?? 0)) keys.add(key)
  }
  return keys
}
