import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { EventFields } from '@kutup/crypto/calendar'
import type { Invitation, InvitationOutcome } from '@kutup/crypto/calendarIcs'
import type { MailAccount } from '@kutup/mail-core/api'
import type { Session } from '@kutup/session/store'
import type { Calendar, CalendarEvent } from './api'

// Mail's widget (docs/plans/calendar-e4.md §5): which stored event a
// message may reach, what it shows, and what it does on its own. The ICS
// reading is Rust's (its tests); here the calendars and the server are
// stand-ins.

interface Store {
  series: Map<string, unknown[]>
  syncs: unknown[]
  replies: unknown[]
  replyOutcome: 'applied' | 'stale'
  invited: unknown[]
  opened: unknown
  openedByRow?: (row: { uid: string; organizer?: string }) => unknown
  kutupAddresses: string[]
}
const store = vi.hoisted((): Store => ({ series: new Map(), syncs: [], replies: [], replyOutcome: 'applied', invited: [], opened: null, kutupAddresses: [] }))
vi.mock('./api', () => ({
  activeAddressId: () => Promise.resolve('a1'),
  beforeEventWrite: () => Promise.resolve(),
  loadSeries: (_account: unknown, calendar: { id: string }, uid: string) => Promise.resolve(store.series.get(`${calendar.id}:${uid}`) ?? []),
  saveEvent: () => Promise.resolve('x'),
  syncOne: (_calendar: unknown, _address: unknown, change: { update?: { id: string }; create?: { id: string } }) => {
    store.syncs.push(change)
    // A create lands: the series lists it from now on.
    if (change.create) store.series.set('c1:u1', [{ id: change.create.id, fields: { recurrenceId: null } }])
    return Promise.resolve({ id: change.update?.id ?? change.create?.id })
  },
}))
vi.mock('./invitations', async (actual) => {
  const real = await actual<typeof import('./invitations')>()
  return {
    ...real,
    attendeeAnswers: () => Promise.resolve([]),
    applyReply: (args: unknown) => {
      store.replies.push(args)
      return Promise.resolve(store.replyOutcome)
    },
    loadInvitedRows: () => Promise.resolve(store.invited),
    openInvitedEvent: (_account: unknown, row: { uid: string; organizer?: string }) =>
      Promise.resolve(store.openedByRow?.(row) ?? store.opened),
    kutupInvitees: (_account: unknown, attendees: { email: string }[]) =>
      Promise.resolve(attendees.filter((a) => store.kutupAddresses.includes(a.email)).map((a) => ({ address: a.email, publicKey: 'k' }))),
    invitationLimits: () => Promise.resolve({ attendeesPerEvent: 100, invitationCountMax: 499, busyShownMax: 10, invitationIcsMaxBytes: 1 << 20 }),
  }
})
vi.mock('@kutup/crypto/calendarIcs', () => ({ readInvitation: vi.fn(), writeInvitation: vi.fn() }))

const { applyOnView, calendarParts, widgetState } = await import('./invitationWidget')
const { plannedMessages } = await import('./invitations')

const me = 'ali@kutup.test'
const account = {
  address: me,
  name: 'Ali',
  isOwnAddress: (a: string | null | undefined) => (a ?? '').replace(/^mailto:/i, '').toLowerCase() === me,
  key: {},
  ownPublicKeys: ['ali-key'],
} as unknown as MailAccount
const session = {} as Session
const unlocked = {
  sealInvitation: (_k: unknown, _f: unknown, attendees: { email: string }[]) => ({
    event: { sealed: true },
    attendees: attendees.length ? { data: 'a', signature: 's' } : null,
    tokens: attendees.map((a) => ({ email: a.email, token: `t-${a.email}` })),
    invitees: [],
  }),
}
const calendar = { id: 'c1', owned: true, unlocked } as unknown as Calendar

function fields(over: Partial<EventFields> = {}): EventFields {
  return {
    uid: 'u1',
    dtstamp: '2026-11-20T08:00:00Z',
    created: null,
    start: { utc: '2027-01-10T10:00:00Z' },
    end: { utc: '2027-01-10T11:00:00Z' },
    recurrenceId: null,
    rrule: null,
    organizer: 'mailto:zeynep@outside.example',
    sequence: 0,
    summary: 'Coffee',
    description: null,
    location: null,
    status: 'confirmed',
    transp: 'opaque',
    comment: null,
    ...over,
  }
}

function stored(over: Partial<CalendarEvent> = {}, f: Partial<EventFields> = {}): CalendarEvent {
  return {
    id: 'e1',
    calendarId: 'c1',
    fields: fields(f),
    startUtc: '',
    endUtc: '',
    fullDay: false,
    revision: 1,
    reminders: null,
    verified: true,
    sharedEventId: 'e1',
    home: true,
    organizer: null,
    sealed: {} as CalendarEvent['sealed'],
    attendees: [{ email: me, name: null, optional: false }],
    attendeesVerified: true,
    tokens: [],
    attendeeRows: [],
    sequence: f.sequence ?? 0,
    ...over,
  }
}

function invitation(method: Invitation['method'], over: Partial<Invitation> = {}, f: Partial<EventFields> = {}): InvitationOutcome {
  return {
    read: {
      method,
      fields: fields(f),
      organizer: { email: 'zeynep@outside.example', name: 'Zeynep' },
      attendees: [{ email: me, name: null, partstat: 'needs-action', optional: false, rsvp: true }],
      note: null,
      prodid: null,
      kutupReply: false,
      moreEvents: false,
      dtstampGiven: true,
      ...over,
    },
  }
}

const message = {
  from: 'zeynep@outside.example',
  authenticated: true,
  receivedAt: '2026-11-20T08:00:05Z',
  date: '2026-11-20T08:00:00Z',
  subject: 'Invitation',
  messageId: 'm1@outside.example',
}

beforeEach(() => {
  store.series.clear()
  store.syncs = []
  store.replies = []
  store.replyOutcome = 'applied'
  store.invited = []
  store.opened = null
  store.openedByRow = undefined
  store.kutupAddresses = []
})

describe("the attendee's side", () => {
  it('reaches only an event whose organizer is the one the mail names', async () => {
    // A mail naming the UID of Ali's own event, as an organizer of its own.
    store.series.set('c1:u1', [stored({ organizer: me }, { organizer: `mailto:${me}` })])
    const state = await widgetState({ account, calendars: [calendar], outcome: invitation('CANCEL', {}, { sequence: 9 }), message })
    expect(state.kind === 'attendee' && state.stored).toBe(null)
    expect(await applyOnView({ session, account, calendars: [calendar], state, autoAdd: false, message })).toBe(false)
    expect(store.syncs).toEqual([])
  })

  it('is no invitation from this account to itself (Proton: invalid method)', async () => {
    const outcome = invitation('REQUEST', { organizer: { email: me, name: null } }, { organizer: `mailto:${me}` })
    expect(await widgetState({ account, calendars: [calendar], outcome, message })).toEqual({ kind: 'error', key: 'invitation.widget.error.invalidMethod' })
  })

  it('applies an update of the same SEQUENCE keeping the answer, and a moved one asking it again', async () => {
    store.series.set('c1:u1', [stored()])
    const retitled = await widgetState({ account, calendars: [calendar], outcome: invitation('REQUEST', {}, { dtstamp: '2026-11-21T08:00:00Z', summary: 'Coffee, room 2' }), message })
    expect(retitled.kind === 'attendee' && retitled.status).toBe('updated')
    expect(await applyOnView({ session, account, calendars: [calendar], state: retitled, autoAdd: false, message })).toBe(true)
    expect(store.syncs).toMatchObject([{ update: { id: 'e1', invitation: { resetAnswers: false } } }])
    const moved = await widgetState({ account, calendars: [calendar], outcome: invitation('REQUEST', {}, { sequence: 1, start: { utc: '2027-01-11T10:00:00Z' } }), message })
    await applyOnView({ session, account, calendars: [calendar], state: moved, autoAdd: false, message })
    expect(store.syncs[1]).toMatchObject({ update: { invitation: { resetAnswers: true } } })
  })

  it('leaves an older invitation alone, and adds a new one only when the account says so', async () => {
    store.series.set('c1:u1', [stored({}, { sequence: 2 })])
    const old = await widgetState({ account, calendars: [calendar], outcome: invitation('REQUEST', {}, { sequence: 1 }), message })
    expect(old.kind === 'attendee' && old.status).toBe('outdated')
    expect(await applyOnView({ session, account, calendars: [calendar], state: old, autoAdd: true, message })).toBe(false)
    store.series.clear()
    const fresh = await widgetState({ account, calendars: [calendar], outcome: invitation('REQUEST'), message })
    expect(await applyOnView({ session, account, calendars: [calendar], state: fresh, autoAdd: false, message })).toBe(false)
    expect(store.syncs).toEqual([])
    expect(await applyOnView({ session, account, calendars: [calendar], state: fresh, autoAdd: true, message })).toBe(true)
    expect(store.syncs).toMatchObject([{ create: { invitation: { invitees: [] } } }])
  })

  it('takes a Kutup invitation only when its signed organizer is the one the mail names', async () => {
    store.invited = [{ uid: 'u1' }]
    store.opened = { verified: true, organizer: 'someone@kutup.test', fields: fields(), invitation: { free: vi.fn() }, row: { copies: [] } }
    const state = await widgetState({ account, calendars: [calendar], outcome: invitation('REQUEST'), message })
    expect(state.kind === 'attendee' && state.kutup).toBe(null)
  })

  // Security review H2: a co-attendee or anyone knowing the UID writes
  // ORGANIZER as the real organizer; only a DMARC-verified mail from the
  // organizer itself changes the calendar on view.
  it('changes nothing on view unless the mail verifiably comes from the organizer', async () => {
    store.series.set('c1:u1', [stored()])
    const outcome = invitation('CANCEL', {}, { sequence: 3 })
    const coAttendee = await widgetState({ account, calendars: [calendar], outcome, message: { ...message, from: 'mallory@outside.example' } })
    const spoofed = await widgetState({ account, calendars: [calendar], outcome, message: { ...message, authenticated: false } })
    for (const state of [coAttendee, spoofed]) {
      expect(state.kind === 'attendee' && state.fromOrganizer).toBe(false)
      expect(await applyOnView({ session, account, calendars: [calendar], state, autoAdd: true, message })).toBe(false)
    }
    expect(store.syncs).toEqual([])
    const real = await widgetState({ account, calendars: [calendar], outcome, message })
    expect(real.kind === 'attendee' && real.fromOrganizer).toBe(true)
    expect(await applyOnView({ session, account, calendars: [calendar], state: real, autoAdd: false, message })).toBe(true)
  })

  it('takes a Kutup invitation as cancelled only from its signed state, not a mail (L1)', async () => {
    store.invited = [{ uid: 'u1' }]
    store.opened = { verified: true, organizer: 'zeynep@outside.example', fields: fields(), invitation: { free: vi.fn() }, row: { copies: [] } }
    const state = await widgetState({ account, calendars: [calendar], outcome: invitation('CANCEL'), message })
    expect(state.kind === 'attendee' && state.status).toBe('new')
  })

  it('finds a Kutup invitation among rows of several organizers sharing a UID (L2)', async () => {
    store.invited = [{ uid: 'u1', organizer: 'mallory@kutup.test' }, { uid: 'u1', organizer: 'zeynep@outside.example' }]
    store.openedByRow = (row) => ({ verified: true, organizer: row.organizer, fields: fields(), invitation: { free: vi.fn() }, row: { copies: [] } })
    const state = await widgetState({ account, calendars: [calendar], outcome: invitation('REQUEST'), message })
    expect(state.kind === 'attendee' && state.kutup?.organizer).toBe('zeynep@outside.example')
  })
})

describe("the organizer's side", () => {
  const mine = () => stored({ organizer: me, attendees: [{ email: 'zeynep@outside.example', name: null, optional: false }] }, { organizer: `mailto:${me}` })
  const reply = (over: Partial<Invitation> = {}) =>
    invitation('REPLY', { organizer: { email: me, name: null }, attendees: [{ email: 'zeynep@outside.example', name: null, partstat: 'accepted', optional: false, rsvp: false }], ...over }, { organizer: `mailto:${me}` })

  it('applies a reply from its attendee, and calls an older one out of date', async () => {
    store.series.set('c1:u1', [mine()])
    const state = await widgetState({ account, calendars: [calendar], outcome: reply(), message })
    expect(state.kind === 'organizer' && state.status).toBe('applied')
    expect(await applyOnView({ session, account, calendars: [calendar], state, autoAdd: false, message })).toBe(true)
    expect(store.replies).toMatchObject([{ email: 'zeynep@outside.example', partstat: 'accepted' }])
    store.replyOutcome = 'stale'
    expect(await applyOnView({ session, account, calendars: [calendar], state, autoAdd: false, message })).toBe('stale')
  })

  it("never applies a reply sent by someone other than its attendee, a party crasher's, or a marked Kutup one", async () => {
    store.series.set('c1:u1', [mine()])
    const forged = await widgetState({ account, calendars: [calendar], outcome: reply(), message: { ...message, from: 'mallory@outside.example' } })
    expect(forged.kind === 'organizer' && forged.status).toBe('notFromAttendee')
    const crasher = await widgetState({
      account,
      calendars: [calendar],
      outcome: reply({ attendees: [{ email: 'bob@outside.example', name: null, partstat: 'accepted', optional: false, rsvp: false }] }),
      message: { ...message, from: 'bob@outside.example' },
    })
    expect(crasher.kind === 'organizer' && crasher.status).toBe('partyCrasher')
    const marked = await widgetState({ account, calendars: [calendar], outcome: reply({ kutupReply: true }), message })
    expect(marked.kind === 'organizer' && marked.status).toBe('kutupReply')
    for (const state of [forged, crasher, marked]) await applyOnView({ session, account, calendars: [calendar], state, autoAdd: false, message })
    expect(store.replies).toEqual([])
  })

  it('records a reply only from a DMARC-verified sender (H2)', async () => {
    store.series.set('c1:u1', [mine()])
    const state = await widgetState({ account, calendars: [calendar], outcome: reply(), message: { ...message, authenticated: false } })
    expect(state.kind === 'organizer' && state.status).toBe('unverifiedSender')
    expect(await applyOnView({ session, account, calendars: [calendar], state, autoAdd: false, message })).toBe(false)
    expect(store.replies).toEqual([])
  })

  it("never writes a Kutup attendee's row from a mail: they answer in it themselves (H2)", async () => {
    store.series.set('c1:u1', [mine()])
    store.kutupAddresses = ['zeynep@outside.example']
    const state = await widgetState({ account, calendars: [calendar], outcome: reply(), message })
    expect(await applyOnView({ session, account, calendars: [calendar], state, autoAdd: false, message })).toBe(false)
    expect(store.replies).toEqual([])
  })

  it('dates a reply no later than its arrival (H2: a reply dated ahead would make the real answer look stale)', async () => {
    store.series.set('c1:u1', [mine()])
    const ahead = reply()
    if ('read' in ahead) ahead.read.fields = { ...ahead.read.fields, dtstamp: '2026-11-21T07:00:00Z' }
    const state = await widgetState({ account, calendars: [calendar], outcome: ahead, message })
    await applyOnView({ session, account, calendars: [calendar], state, autoAdd: false, message })
    expect(store.replies).toMatchObject([{ dtstamp: '2026-11-20T08:00:05.000Z' }])
  })

  it('only reaches an event this account organizes', async () => {
    store.series.set('c1:u1', [stored()])
    const state = await widgetState({ account, calendars: [calendar], outcome: reply(), message })
    expect(state.kind === 'organizer' && state.status).toBe('noEvent')
  })
})

describe('the messages a save sends (Proton’s inviteActions)', () => {
  const a = { email: 'a@x.example', name: null, optional: false }
  const b = { email: 'b@x.example', name: null, optional: true }
  const c = { email: 'c@x.example', name: null, optional: false }
  it('requests all on create; updates the kept, requests the added, cancels the removed', () => {
    expect(plannedMessages(account, fields(), [a, b], null, 'en').map((m) => [m.method, m.to.map((p) => p.email)])).toEqual([['REQUEST', ['a@x.example', 'b@x.example']]])
    const changed = plannedMessages(account, fields({ summary: 'New' }), [a, c], { fields: fields(), attendees: [a, b] }, 'en')
    expect(changed.map((m) => [m.method, m.to.map((p) => p.email), !!m.created])).toEqual([
      ['REQUEST', ['a@x.example'], false],
      ['REQUEST', ['c@x.example'], true],
      ['CANCEL', ['b@x.example'], false],
    ])
    // Nothing that a mail tells changed: no update to those kept.
    expect(plannedMessages(account, fields(), [a], { fields: fields(), attendees: [a] }, 'en')).toEqual([])
  })
})

describe('calendar parts', () => {
  it('reads each once: Google sends one inline and one attached', () => {
    const text = new TextEncoder().encode('BEGIN:VCALENDAR\r\nEND:VCALENDAR\r\n')
    const parts = calendarParts(
      [
        { filename: '', mimeType: 'text/calendar', content: text },
        { filename: 'invite.ics', mimeType: 'application/ics', content: text },
        { filename: 'notes.txt', mimeType: 'text/plain', content: text },
      ],
      1 << 20,
    )
    expect(parts).toHaveLength(1)
  })
})
