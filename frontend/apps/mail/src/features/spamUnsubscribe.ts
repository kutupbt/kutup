import { useSyncExternalStore } from 'react'
import { emptyDraft, openMessage, sendDraft, useMailAccount, useMailRefresh, usePinnedKeys, useUnsubscribe, type MailMessage } from '@kutup/mail-core/api'
import { unsubscribeMethods } from '@kutup/mail-core/unsubscribe'
import api from '@kutup/session/client'
import { useGroupScope, useMailboxScope } from './mailboxScope'

// Proton's SpamAction (GlobalUnsubscribeModal, "Auto-unsubscribe"): moving
// mail from a list to Spam may unsubscribe from the list too.

/** What the ask dialog needs: how many rows, and what to do with the answer. */
export interface SpamAsk {
  count: number
  conversations: boolean
  onChoice: (unsubscribe: boolean, remember: boolean) => void
}

let asking: SpamAsk | null = null
const listeners = new Set<() => void>()
const emit = () => listeners.forEach((listener) => listener())

/** Opens Proton's "Move to spam" question. */
export function askSpamUnsubscribe(ask: SpamAsk) {
  asking = ask
  emit()
}

export function closeSpamAsk() {
  asking = null
  emit()
}

export function useSpamAsk(): SpamAsk | null {
  return useSyncExternalStore(
    (listener) => {
      listeners.add(listener)
      return () => listeners.delete(listener)
    },
    () => asking,
  )
}

/** A row moved to Spam, as far as unsubscribing needs it. */
export interface ListedRow {
  id: string
  threadId?: string
  direction: MailMessage['direction']
  unsubscribable?: boolean
  conversation?: { members: { id: string; unsubscribable?: boolean }[] }
}

/** Whether a row (or a member of its conversation) came from a list. */
export function fromList(row: ListedRow): boolean {
  return row.direction === 'inbound' && (row.unsubscribable === true || (row.conversation?.members.some((m) => m.unsubscribable) ?? false))
}

/** What unsubscribing did: done, needing a web page (the reader's to open), failed. */
export interface Unsubscribed {
  done: number
  manual: number
  failed: number
}

/**
 * Unsubscribes, without asking each time, from the lists the rows came
 * from: the newest list message of each sender is opened on the device for
 * its ways out (they stay encrypted on the server); one click is sent by the
 * server, an email from the reader's address. A list that only names a web
 * page is left to the reader, as Proton's server does.
 */
export function useQuietUnsubscribe() {
  const account = useMailAccount()
  const pinned = usePinnedKeys()
  const { group } = useMailboxScope()
  const scope = useGroupScope(account.data)
  const unsubscribe = useUnsubscribe(group)
  const refresh = useMailRefresh()

  return async (rows: ListedRow[]): Promise<Unsubscribed> => {
    const result: Unsubscribed = { done: 0, manual: 0, failed: 0 }
    const me = account.data
    if (!me) return result
    // The rows' list messages: the row itself, or its conversation's.
    const messages: MailMessage[] = []
    const threads = new Set<string>()
    for (const row of rows.filter(fromList)) {
      // A whole message row is enough; a conversation (or a dragged member) is read from its thread, once.
      if (!row.conversation && 'subject' in row) messages.push(row as unknown as MailMessage)
      else if (row.threadId && !threads.has(row.threadId)) {
        threads.add(row.threadId)
        const thread = (await api.get<MailMessage[]>(`/mail/threads/${row.threadId}`, { params: group ? { group } : {} })).data
        messages.push(...thread.filter((m) => m.direction === 'inbound' && m.unsubscribable))
      }
    }
    // One list per sender, by its newest message.
    const newest = new Map<string, MailMessage>()
    for (const m of messages) {
      const sender = m.from?.address.toLowerCase() ?? m.id
      const known = newest.get(sender)
      if (!known || known.receivedAt < m.receivedAt) newest.set(sender, m)
    }
    for (const message of newest.values()) {
      try {
        const opened = await openMessage(me, message, pinned ?? (() => undefined), scope ?? undefined)
        const methods = unsubscribeMethods(opened.raw)
        if (methods?.oneClick) {
          await unsubscribe.mutateAsync({ id: message.id, oneClickUrl: methods.oneClick })
          result.done++
        } else if (methods?.mailto) {
          const { to, subject, body } = methods.mailto
          const html = `<p>${body.replace(/[&<>]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' })[c]!)}</p>`
          await sendDraft(me, emptyDraft(me, { to: [{ address: to, name: '' }], subject, text: body, html }), [], pinned ?? (() => undefined))
          await unsubscribe.mutateAsync({ id: message.id })
          result.done++
        } else result.manual++
      } catch {
        result.failed++
      }
    }
    refresh()
    return result
  }
}
