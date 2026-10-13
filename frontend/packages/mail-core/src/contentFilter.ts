import type { ConversationMember, ListFilter, ListSort, ListView, MailMessage, Page, PlaceKey } from './api'

// Body search's list, made in the browser (docs/plans/mail-body-search.md),
// as Proton's encrypted search filters and pages its own results: the index
// keeps each message's list row, so a keyword search never tells the server
// which messages matched. The rules are the server's list rules
// (crates/kutup-server/src/handlers/mail.rs, PLACE_WHERE and CRITERIA_WHERE),
// with Spam and Trash always left out of All mail, as a search does there.

type Criteria = NonNullable<ListView['criteria']>

const UNWANTED = new Set<MailMessage['folder']>(['spam', 'trash'])

/** Whether a row is listed in a place. */
export function inPlace(row: MailMessage, place: PlaceKey): boolean {
  if (place === 'starred') return row.starred && !UNWANTED.has(row.folder)
  if (place === 'all') return !UNWANTED.has(row.folder)
  if (place.startsWith('folder:')) return row.folder === 'custom' && row.customFolder === place.slice('folder:'.length)
  if (place.startsWith('label:')) return !UNWANTED.has(row.folder) && row.labels.includes(place.slice('label:'.length))
  return row.folder === place
}

const holds = (value: string | null | undefined, part: string) => !!value && value.toLowerCase().includes(part)

/**
 * Advanced search beyond the keyword: sender and recipient contain the text
 * (address or name), the time range, and the address it came to (`own`, the
 * account's: every message of its mailbox) or the list it came through.
 */
export function matchesCriteria(row: MailMessage, criteria: Criteria | undefined, own: string): boolean {
  if (!criteria) return true
  const from = criteria.from?.trim().toLowerCase()
  if (from && !(holds(row.from?.address, from) || holds(row.from?.name, from))) return false
  const to = criteria.to?.trim().toLowerCase()
  if (to && ![...row.to, ...row.cc, ...row.bcc].some((m) => holds(m.address, to) || holds(m.name, to))) return false
  const at = Date.parse(row.receivedAt)
  if (criteria.since && at < Date.parse(criteria.since)) return false
  if (criteria.until && at >= Date.parse(criteria.until)) return false
  const address = criteria.address?.trim().toLowerCase()
  if (address && address !== own.toLowerCase() && address !== row.groupAddress?.toLowerCase()) return false
  return true
}

export function matchesFilter(row: MailMessage, filter: ListFilter | null | undefined): boolean {
  if (filter === 'unread') return !row.seen
  if (filter === 'read') return row.seen
  if (filter === 'attachments') return row.attachmentCount > 0
  return true
}

const member = (row: MailMessage): ConversationMember => ({
  id: row.id,
  folder: row.folder,
  direction: row.direction,
  customFolder: row.customFolder,
  ...(row.unsubscribable ? { unsubscribable: true } : {}),
})

/**
 * One row per conversation, as the server's: the thread's newest message
 * found, standing for the messages found in it (oldest first).
 */
export function byConversation(rows: MailMessage[]): Listed[] {
  const threads = new Map<string, MailMessage[]>()
  for (const row of rows) {
    const thread = threads.get(row.threadId)
    if (thread) thread.push(row)
    else threads.set(row.threadId, [row])
  }
  return [...threads.values()].map((found) => {
    const oldest = [...found].sort((a, b) => Date.parse(a.receivedAt) - Date.parse(b.receivedAt) || a.id.localeCompare(b.id))
    const newest = oldest[oldest.length - 1]
    const senders = new Map<string, NonNullable<MailMessage['from']>>()
    for (const row of oldest) if (row.from?.address && !senders.has(row.from.address)) senders.set(row.from.address, row.from)
    return {
      ...newest,
      totalSize: oldest.reduce((sum, row) => sum + row.size, 0),
      conversation: {
        members: oldest.map(member),
        unread: oldest.filter((row) => !row.seen).length,
        starred: oldest.some((row) => row.starred),
        senders: [...senders.values()],
        attachmentCount: oldest.reduce((sum, row) => sum + row.attachmentCount, 0),
        attachments: oldest.flatMap((row) => (row.attachments ?? []).map((file) => ({ ...file, message: row.id }))),
      },
    }
  })
}

/** A listed row; a conversation sorts by its messages' size together. */
type Listed = MailMessage & { totalSize?: number }

/** In the list's order (Proton's sort options); ties newest id first, as the server's. */
export function sortRows<T extends Listed>(rows: T[], sort: ListSort = 'newest'): T[] {
  const time = (row: Listed) => Date.parse(row.receivedAt)
  const size = (row: Listed) => row.totalSize ?? row.size
  const tie = (a: Listed, b: Listed) => b.id.localeCompare(a.id)
  const order: Record<ListSort, (a: Listed, b: Listed) => number> = {
    newest: (a, b) => time(b) - time(a) || tie(a, b),
    oldest: (a, b) => time(a) - time(b) || -tie(a, b),
    largest: (a, b) => size(b) - size(a) || tie(a, b),
    smallest: (a, b) => size(a) - size(b) || -tie(a, b),
  }
  return [...rows].sort(order[sort])
}

/** A place's page of body search's rows, with how many there are in all. */
export function contentPage(rows: MailMessage[], place: PlaceKey, view: ListView, own: string): Page {
  const { criteria, conversations, filter, sort, page = 0, pageSize = 50 } = view
  const here = rows.filter((row) => inPlace(row, place) && matchesCriteria(row, criteria, own))
  // By conversation, the filters ask about the thread: any unread, any file.
  const listed: Listed[] = conversations
    ? byConversation(here).filter((row) => {
        const thread = row.conversation!
        if (filter === 'unread') return thread.unread > 0
        if (filter === 'read') return thread.unread === 0
        if (filter === 'attachments') return thread.attachmentCount > 0
        return true
      })
    : here.filter((row) => matchesFilter(row, filter))
  const messages = sortRows(listed, sort)
    .slice(page * pageSize, (page + 1) * pageSize)
    .map(({ totalSize: _, ...row }) => row)
  return { messages, next: null, total: listed.length }
}
