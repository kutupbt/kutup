import { describe, expect, it } from 'vitest'
import type { MailMessage } from './api'
import { byConversation, contentPage, inPlace, matchesCriteria } from './contentFilter'

let n = 0
function row(patch: Partial<MailMessage> = {}): MailMessage {
  n += 1
  return {
    id: `00000000-0000-4000-8000-${String(n).padStart(12, '0')}`,
    threadId: `t${n}`,
    direction: 'inbound',
    folder: 'inbox',
    customFolder: null,
    labels: [],
    seen: true,
    starred: false,
    protection: 'end_to_end',
    size: 100,
    receivedAt: new Date(Date.UTC(2026, 9, 1) + n * 60_000).toISOString(),
    sentAt: null,
    subject: 'konu',
    from: { address: 'ayse@example.com', name: 'Ayşe Yılmaz' },
    to: [{ address: 'me@kutup.dev', name: '' }],
    cc: [],
    replyTo: [],
    bcc: [],
    messageId: null,
    inReplyTo: null,
    references: [],
    attachmentCount: 0,
    groupAddress: null,
    sentBy: null,
    ...patch,
  }
}

describe('body search list', () => {
  it('places as the server lists them, Spam and Trash out of All mail', () => {
    expect(inPlace(row(), 'inbox')).toBe(true)
    expect(inPlace(row({ folder: 'trash' }), 'all')).toBe(false)
    expect(inPlace(row({ folder: 'archive' }), 'all')).toBe(true)
    expect(inPlace(row({ starred: true }), 'starred')).toBe(true)
    expect(inPlace(row({ starred: true, folder: 'spam' }), 'starred')).toBe(false)
    expect(inPlace(row({ folder: 'custom', customFolder: 'f1' }), 'folder:f1')).toBe(true)
    expect(inPlace(row({ folder: 'custom', customFolder: 'f2' }), 'folder:f1')).toBe(false)
    expect(inPlace(row({ labels: ['l1'] }), 'label:l1')).toBe(true)
    expect(inPlace(row({ labels: ['l1'], folder: 'trash' }), 'label:l1')).toBe(false)
  })

  it('advanced search: sender, recipient, dates and address', () => {
    const r = row({ cc: [{ address: 'mehmet@example.org', name: 'Mehmet' }], groupAddress: 'ekip@kutup.dev' })
    const own = 'me@kutup.dev'
    expect(matchesCriteria(r, { from: 'AYŞE' }, own)).toBe(true)
    expect(matchesCriteria(r, { from: 'example.com' }, own)).toBe(true)
    expect(matchesCriteria(r, { from: 'mehmet' }, own)).toBe(false)
    expect(matchesCriteria(r, { to: 'mehmet' }, own)).toBe(true)
    expect(matchesCriteria(r, { since: r.receivedAt }, own)).toBe(true)
    expect(matchesCriteria(r, { until: r.receivedAt }, own)).toBe(false)
    expect(matchesCriteria(r, { address: 'ME@kutup.dev' }, own)).toBe(true)
    expect(matchesCriteria(r, { address: 'ekip@kutup.dev' }, own)).toBe(true)
    expect(matchesCriteria(r, { address: 'other@kutup.dev' }, own)).toBe(false)
  })

  it('pages, filters and sorts', () => {
    const rows = [row({ seen: false, size: 300 }), row({ attachmentCount: 1, size: 50 }), row({ folder: 'archive' })]
    const page = (view: Parameters<typeof contentPage>[2]) => contentPage(rows, 'inbox', view, 'me@kutup.dev')
    expect(page({}).messages.map((m) => m.id)).toEqual([rows[1].id, rows[0].id])
    expect(page({}).total).toBe(2)
    expect(page({ filter: 'unread' }).messages.map((m) => m.id)).toEqual([rows[0].id])
    expect(page({ filter: 'attachments' }).messages.map((m) => m.id)).toEqual([rows[1].id])
    expect(page({ sort: 'oldest' }).messages[0].id).toBe(rows[0].id)
    expect(page({ sort: 'smallest' }).messages[0].id).toBe(rows[1].id)
    expect(page({ pageSize: 1, page: 1 }).messages.map((m) => m.id)).toEqual([rows[0].id])
  })

  it('groups by conversation, as the server', () => {
    const a = row({ threadId: 'x', seen: false, attachmentCount: 1, attachments: [{ name: 'a.pdf', type: 'application/pdf', size: 1 }] })
    const b = row({ threadId: 'x', from: { address: 'mehmet@example.org', name: 'Mehmet' }, size: 400 })
    const c = row({ threadId: 'y' })
    const [x, y] = byConversation([b, c, a])
    expect(x.id).toBe(b.id)
    expect(x.conversation!.members.map((m) => m.id)).toEqual([a.id, b.id])
    expect(x.conversation!.unread).toBe(1)
    expect(x.conversation!.senders.map((s) => s.address)).toEqual(['ayse@example.com', 'mehmet@example.org'])
    expect(x.conversation!.attachments).toEqual([{ name: 'a.pdf', type: 'application/pdf', size: 1, message: a.id }])
    expect(y.conversation!.members).toHaveLength(1)
    const page = contentPage([a, b, c], 'inbox', { conversations: true, filter: 'unread' }, 'me@kutup.dev')
    expect(page.messages.map((m) => m.id)).toEqual([b.id])
    expect(page.messages[0].size).toBe(400)
    expect(contentPage([a, b, c], 'inbox', { conversations: true, sort: 'largest' }, '').messages[0].id).toBe(b.id)
  })
})
