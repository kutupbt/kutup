import { useEffect, useMemo, useRef } from 'react'
import { disappearingMessageExpiresAt, isVisibleChatMessage } from '@kutup/chat-core/disappearing'
import { conversationKey, directAddress } from '@kutup/chat-core/identity'
import type { ConversationId } from '@kutup/chat-core/types'
import { useNow } from '../lib/useNow'
import { useViewedConversation } from '../state/openConversation'
import { useReadReceipts } from '../state/prefs'
import { markRead, startFreshMarks } from '../state/readState'
import { refreshChat, useChat } from './chatStore'

const RECEIPT_BATCH = 64

/**
 * The work that runs whatever is on screen:
 *
 * - Receipts. Direct chats with accepted contacts get "delivered" for every
 *   incoming message automatically; the conversation being looked at gets
 *   "read" when read receipts are on. Groups send only "read" (each group
 *   receipt spends one-time key packages for every member device, so
 *   automatic delivery receipts would double that). A receipt is attempted
 *   once: the engine owns it from then on.
 * - The read mark of the conversation being looked at (unread counts).
 * - Expiry: when a disappearing message's time is up, the history is
 *   reloaded, which purges it.
 */
export function ChatJobs() {
  const chat = useChat()
  const viewed = useViewedConversation()
  const readReceipts = useReadReceipts()
  const now = useNow(1_000)
  const attempted = useRef(new Set<string>())
  const purging = useRef(false)
  const { service, self, snapshot } = chat

  const ownReceipts = useMemo(() => {
    const states = new Map<string, 'delivered' | 'read'>()
    for (const message of snapshot.history) {
      const receipt = message.content.receipt
      if (!receipt || message.direction !== 'outgoing') continue
      for (const id of receipt.messageIds) {
        if (receipt.state === 'read' || !states.has(id)) states.set(id, receipt.state)
      }
    }
    return states
  }, [snapshot.history])

  // Receipts.
  useEffect(() => {
    if (!service || !self) return
    const contacts = new Map(snapshot.contacts.map((c) => [c.peer, c]))
    const activeGroups = new Set(
      snapshot.groups.filter((g) => g.status === 'active').map((g) => g.request.genesis.conversationId),
    )
    const batches = new Map<string, { conversation: ConversationId; state: 'delivered' | 'read'; ids: string[] }>()
    const nowMs = Date.now()
    for (const message of snapshot.history) {
      const id = message.content.messageId
      if (message.direction !== 'incoming' || !id || !isVisibleChatMessage(message, nowMs)) continue
      if (message.conversation.kind === 'direct') {
        const peer = directAddress(message.conversation)
        const state = peer ? contacts.get(peer)?.state : undefined
        if (!peer || (peer !== self.address && state !== 'accepted' && state !== 'pendingOutgoing')) continue
      } else if (!activeGroups.has(message.conversation.groupId)) {
        continue
      }
      const key = conversationKey(message.conversation)
      const read = readReceipts && viewed === key
      if (message.conversation.kind === 'group' && !read) continue
      const state = read ? 'read' : 'delivered'
      const existing = ownReceipts.get(id)
      if (existing === 'read' || existing === state) continue
      const flight = `${state}:${id}`
      if (attempted.current.has(flight)) continue
      attempted.current.add(flight)
      const slot = `${key}\u0000${state}`
      const batch = batches.get(slot) ?? { conversation: message.conversation, state, ids: [] }
      batch.ids.push(id)
      batches.set(slot, batch)
    }
    if (batches.size === 0) return
    void (async () => {
      let sent = false
      for (const batch of batches.values()) {
        for (let offset = 0; offset < batch.ids.length; offset += RECEIPT_BATCH) {
          try {
            await service.sendReceipt(batch.conversation, batch.ids.slice(offset, offset + RECEIPT_BATCH), batch.state)
            sent = true
          } catch (error) {
            console.warn('chat: receipt not sent', error)
          }
        }
      }
      if (sent) await refreshChat()
    })()
  }, [service, self, snapshot, ownReceipts, readReceipts, viewed])

  // A first open on this device: what is already here counts as read.
  useEffect(() => {
    if (!chat.loaded) return
    const newest = new Map<string, number>()
    for (const message of snapshot.history) {
      const key = conversationKey(message.conversation)
      newest.set(key, Math.max(newest.get(key) ?? 0, message.timestampMs))
    }
    startFreshMarks(newest)
  }, [chat.loaded, snapshot.history])

  // The read mark of what is being looked at.
  useEffect(() => {
    if (!viewed) return
    let newest = 0
    for (const message of snapshot.history) {
      if (conversationKey(message.conversation) === viewed && message.timestampMs > newest) newest = message.timestampMs
    }
    if (newest) markRead(viewed, newest)
  }, [viewed, snapshot.history])

  // Expired messages leave as soon as their time is up.
  useEffect(() => {
    if (purging.current) return
    const due = snapshot.history.some((message) => {
      const at = disappearingMessageExpiresAt(message)
      return at !== undefined && now >= at
    })
    if (!due) return
    purging.current = true
    void refreshChat().finally(() => {
      purging.current = false
    })
  }, [now, snapshot.history])

  return null
}
