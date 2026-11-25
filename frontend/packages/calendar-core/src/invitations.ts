// Invitations (docs/plans/calendar-e4.md): what Calendar and Mail share.
//
// - The organizer (§4): an event with participants is sealed with its
//   attendee part, each attendee's keyed token and the shared session key
//   to each Kutup attendee on this server, then Proton's messages go
//   (REQUEST, updates, CANCEL) through Mail.
// - Answers (§3): sealed rows, each opened against the organizer's and the
//   attendees' own keys; an outside reply is written by the organizer's
//   client, a Kutup attendee writes their own.
// - Kutup attendees (§6): the invitations the server lists for them, opened
//   with their address key, adopted into their own calendar.
//
// Trust: nothing the server says about an invitation is taken on its word.
// The ORGANIZER shown is the address whose keys verified the shared parts;
// attendees come from the organizer-signed attendee part, never from the
// server's rows, and a row's answer counts only when it opens for that
// row's token (bound inside the sealed answer) and was signed by a key the
// client looked up itself.

import {
  openInvitation,
  type Answer,
  type Attendee,
  type EventFields,
  type EventPart,
  type OpenedInvitation,
  type Partstat,
} from '@kutup/crypto/calendar'
import { AddressDisabled, addressKeys, GroupAddress, NoKutupAddress } from '@kutup/mail-core/keys'
import type { MailAccount, PinnedKeys } from '@kutup/mail-core/api'
import api from '@kutup/session/client'
import { loadServerSettings } from '@kutup/session/apps'
import type { Session } from '@kutup/session/store'
import {
  activeAddressId,
  authorKeys,
  beforeEventWrite,
  syncOne,
  timesOf,
  type AttendeeRow,
  type Calendar,
  type CalendarEvent,
  type EventRow,
  type Reminder,
} from './api'
import { sendInvitationMessage, type InvitationMessage, type SendFailure } from './invitationMail'

export type { SendFailure } from './invitationMail'

// ----- settings and limits -----

/** The account's invitation settings (Proton's `InviteLocale`, `AutoImportInvite`). */
export interface InviteSettings {
  /** The language invitations and replies go in; null: the app's. */
  inviteLocale: 'en' | 'tr' | null
  /** Received invitations go into the calendar at once, marked as pending. */
  autoAdd: boolean
}

export async function loadInviteSettings(): Promise<InviteSettings> {
  return (await api.get<InviteSettings>('/calendar/settings/invitations')).data
}

export async function saveInviteSettings(settings: InviteSettings): Promise<InviteSettings> {
  return (await api.put<InviteSettings>('/calendar/settings/invitations', settings)).data
}

/** The language an account sends in: its setting, else the app's. */
export function sendLanguage(settings: InviteSettings | undefined, appLanguage: string): string {
  return settings?.inviteLocale ?? (appLanguage.startsWith('tr') ? 'tr' : 'en')
}

/** The site's invitation limits (`/auth/settings`). */
export interface InvitationLimits {
  attendeesPerEvent: number
  invitationCountMax: number
  busyShownMax: number
  invitationIcsMaxBytes: number
}

export async function invitationLimits(): Promise<InvitationLimits> {
  const settings = await loadServerSettings<{ calendar?: Partial<InvitationLimits> }>()
  const c = settings.calendar ?? {}
  return {
    attendeesPerEvent: c.attendeesPerEvent ?? 100,
    invitationCountMax: c.invitationCountMax ?? 499,
    busyShownMax: c.busyShownMax ?? 10,
    invitationIcsMaxBytes: c.invitationIcsMaxBytes ?? 1024 * 1024,
  }
}

// ----- people -----

/** An address as attendees are compared: trimmed, lowercase, no `mailto:`. */
export function canonicalEmail(value: string): string {
  return value
    .trim()
    .replace(/^mailto:/i, '')
    .trim()
    .toLowerCase()
}

/** An address a participant row takes (one `@`, no spaces or separators). */
export function isAddress(value: string): boolean {
  return /^[^\s@;:,"<>]+@[^\s@;:,"<>]+\.[^\s@;:,"<>]+$/.test(value.trim())
}

/**
 * The Kutup attendees on this server the event reaches at once (§6): their
 * address and the primary key of their checked key list. Anyone else (an
 * outside address, a Kutup address elsewhere, a shared mailbox) gets the mail
 * only. Only those answers leave someone out: any other failure to look an
 * address up (the network, a changed or unverified key) fails the save, since
 * the server takes a shorter invitee list as removing the rest (security
 * review M2).
 */
export async function kutupInvitees(account: MailAccount, attendees: Attendee[]): Promise<{ address: string; publicKey: string }[]> {
  const settings = await loadServerSettings<{ chat?: { serverName?: string } }>()
  const server = settings.chat?.serverName
  const found = await Promise.all(
    attendees.map(async (attendee) => {
      if (!server || account.isOwnAddress(attendee.email)) return null
      try {
        const keys = await addressKeys(attendee.email)
        if (keys.group || keys.disabled || keys.accountRef?.server !== server) return null
        return { address: attendee.email, publicKey: keys.primary }
      } catch (error) {
        if (error instanceof NoKutupAddress || error instanceof GroupAddress || error instanceof AddressDisabled) return null
        throw error
      }
    }),
  )
  return found.filter((invitee): invitee is { address: string; publicKey: string } => invitee !== null)
}

// ----- the organizer -----

/**
 * Whether a change moved the event (Proton's SEQUENCE + 1): its times (as
 * instants, whatever their spelling), all-day or its rule.
 */
export async function movedEvent(before: EventFields, after: EventFields): Promise<boolean> {
  const [a, b] = await Promise.all([timesOf(before), timesOf(after)])
  const same = (x: string, y: string) => Date.parse(x) === Date.parse(y)
  return !same(a.startUtc, b.startUtc) || !same(a.endUtc, b.endUtc) || a.fullDay !== b.fullDay || (before.rrule ?? null) !== (after.rrule ?? null)
}

/** Whether a change touches what an update mail tells (Proton's title, description, location, times or rule). */
export function changedData(before: EventFields, after: EventFields): boolean {
  const pick = (f: EventFields) => [f.summary ?? '', f.description ?? '', f.location ?? '', f.start, f.end, f.rrule ?? null, f.exdates ?? []]
  return JSON.stringify(pick(before)) !== JSON.stringify(pick(after))
}

/** The organizer as an ICS names them. */
function organizerOf(account: MailAccount) {
  return { email: canonicalEmail(account.address), name: account.name || null }
}

/** Attendees as the ICS lists them, with the answers the organizer holds. */
function listed(attendees: Attendee[], answers: Map<string, Partstat> = new Map()) {
  return attendees.map((attendee) => ({
    email: attendee.email,
    name: attendee.name ?? null,
    partstat: answers.get(attendee.email) ?? ('needs-action' as const),
    optional: attendee.optional ?? false,
    rsvp: true,
  }))
}

/**
 * The messages a save sends (Proton's `inviteActions`): a new event, REQUEST
 * to all; a change, an update to those kept when the data changed, REQUEST
 * to those added, CANCEL to those removed.
 */
export function plannedMessages(
  account: MailAccount,
  fields: EventFields,
  attendees: Attendee[],
  before: { fields: EventFields; attendees: Attendee[] } | null,
  lng: string,
): InvitationMessage[] {
  const organizer = organizerOf(account)
  const everyone = listed(attendees)
  const people = (list: Attendee[]) => list.map((a) => ({ email: a.email, name: a.name ?? null }))
  if (!before || before.attendees.length === 0) {
    return attendees.length ? [{ method: 'REQUEST', fields, organizer, attendees: everyone, to: people(attendees), created: true, lng }] : []
  }
  const had = new Set(before.attendees.map((a) => a.email))
  const has = new Set(attendees.map((a) => a.email))
  const kept = attendees.filter((a) => had.has(a.email))
  const added = attendees.filter((a) => !had.has(a.email))
  const removed = before.attendees.filter((a) => !has.has(a.email))
  const messages: InvitationMessage[] = []
  if (kept.length && changedData(before.fields, fields)) {
    messages.push({ method: 'REQUEST', fields, organizer, attendees: everyone, to: people(kept), old: before.fields, lng })
  }
  if (added.length) messages.push({ method: 'REQUEST', fields, organizer, attendees: everyone, to: people(added), created: true, lng })
  if (removed.length) {
    messages.push({ method: 'CANCEL', fields, organizer, attendees: listed(removed), to: people(removed), lng })
  }
  return messages
}

/** What an organizer's save did: the event, and the messages that didn't go (listed on it, "Send again"). */
export interface InvitationSave {
  id: string
  failures: SendFailure[]
  /** The messages planned, for "Send again". */
  messages: InvitationMessage[]
}

/**
 * Saves an event with its participants (the organizer's): the event first,
 * then the messages. `existing`: the event as opened, changed.
 */
export async function saveInvitedEvent(args: {
  session: Session
  account: MailAccount
  pinned: PinnedKeys
  calendar: Calendar
  fields: EventFields
  attendees: Attendee[]
  existing?: CalendarEvent
  reminders?: Reminder[] | null
  newId?: string
  lng: string
}): Promise<InvitationSave> {
  const { session, account, pinned, calendar, existing, lng } = args
  await beforeEventWrite(session)
  if (!calendar.owned) throw new Error('invitations are sent from your own calendars')
  const attendees = args.attendees.map((a) => ({ email: canonicalEmail(a.email), name: a.name?.trim() || null, optional: a.optional ?? false }))
  if (attendees.some((a) => account.isOwnAddress(a.email))) throw new Error('self invitation not allowed')
  const before = existing && existing.attendees ? { fields: existing.fields, attendees: existing.attendees } : null
  // An update that moved the event asks everyone again (Proton's SEQUENCE + 1).
  const moved = !!before && (await movedEvent(before.fields, args.fields))
  const fields: EventFields = {
    ...args.fields,
    organizer: attendees.length ? `mailto:${canonicalEmail(account.address)}` : null,
    sequence: (existing?.sequence ?? args.fields.sequence ?? 0) + (moved ? 1 : 0),
    dtstamp: new Date(Math.floor(Date.now() / 1000) * 1000).toISOString().replace('.000Z', 'Z'),
  }
  const invitees = attendees.length ? await kutupInvitees(account, attendees) : []
  const sealed = calendar.unlocked.sealInvitation(account.key, fields, attendees, invitees, existing?.sealed ?? null)
  const tokenOf = new Map(sealed.tokens.map((t) => [t.email, t.token]))
  const invitation = sealed.attendees
    ? {
        attendees: sealed.attendees,
        rows: attendees.map((a) => ({ token: tokenOf.get(a.email)!, optional: a.optional })),
        invitees: sealed.invitees.map((i) => ({ address: i.address, keyPacket: i.keyPacket, token: tokenOf.get(i.address)! })),
        resetAnswers: moved,
      }
    : undefined
  const addressId = await activeAddressId(account)
  const reminders = args.reminders
  const stored = await syncOne(
    calendar,
    addressId,
    existing
      ? { update: { id: existing.id, baseRevision: existing.revision, event: sealed.event, ...(reminders !== undefined ? { reminders } : {}), ...(invitation ? { invitation } : {}) } }
      : { create: { id: args.newId ?? crypto.randomUUID(), event: sealed.event, ...(reminders ? { reminders } : {}), ...(invitation ? { invitation } : {}) } },
  )
  const messages = plannedMessages(account, fields, attendees, before, lng)
  const failures = await sendMessages(account, pinned, messages)
  return { id: stored?.id ?? existing?.id ?? '', failures, messages }
}

/** Sends planned messages; what didn't go. */
export async function sendMessages(account: MailAccount, pinned: PinnedKeys, messages: InvitationMessage[]): Promise<SendFailure[]> {
  const failures: SendFailure[] = []
  for (const message of messages) failures.push(...(await sendInvitationMessage(account, pinned, message)))
  return failures
}

/** "Send again": the planned messages, to the recipients that failed only. */
export function retryMessages(messages: InvitationMessage[], failures: SendFailure[]): InvitationMessage[] {
  const failed = new Set(failures.map((f) => f.address))
  return messages.map((m) => ({ ...m, to: m.to.filter((p) => failed.has(p.email)) })).filter((m) => m.to.length > 0)
}

/** The CANCEL an organizer's delete sends to everyone (SEQUENCE + 1). */
export function cancelMessage(account: MailAccount, event: CalendarEvent, lng: string): InvitationMessage | null {
  if (!event.attendees?.length || !event.home || !account.isOwnAddress(event.organizer)) return null
  const fields = { ...event.fields, sequence: (event.sequence ?? 0) + 1 }
  return {
    method: 'CANCEL',
    fields,
    organizer: organizerOf(account),
    attendees: listed(event.attendees),
    to: event.attendees.map((a) => ({ email: a.email, name: a.name ?? null })),
    lng,
  }
}

// ----- answers -----

/** One attendee with their answer, as the event view lists them. */
export interface AttendeeAnswer extends Attendee {
  partstat: Partstat
  note: string | null
  /** The answer opened for this attendee's row and a key the client looked up signed it. */
  verified: boolean
}

/** An attendee's own keys (the account's when it is one of its addresses). */
async function attendeeKeys(account: MailAccount, email: string): Promise<string[]> {
  return account.isOwnAddress(email) ? account.ownPublicKeys : await addressKeys(email).then((k) => k.all).catch(() => [])
}

/**
 * Each answer row opened against only the keys that may sign it: the
 * organizer's (who writes outside attendees' replies) and that row's own
 * attendee's, by the token the row is for. Every attendee holds the shared
 * key and could seal an answer for another's row; checking a row against
 * all attendees' keys together would show it as verified (security review M1).
 */
export async function openAnswerRows(
  account: MailAccount,
  open: (rows: { token: string; answer: string | null }[], keys: string[]) => { token: string; answer: Answer | null; verified: boolean }[],
  organizer: string | null,
  tokens: { email: string; token: string }[],
  rows: { token: string; answer: string | null }[],
): Promise<{ token: string; answer: Answer | null; verified: boolean }[]> {
  const organizerKeys = organizer ? await authorKeys(account, organizer).catch(() => []) : []
  return Promise.all(
    rows.map(async (row) => {
      const email = tokens.find((t) => t.token === row.token)?.email
      const keys = [...organizerKeys, ...(email ? await attendeeKeys(account, email) : [])]
      return open([row], keys)[0] ?? { token: row.token, answer: null, verified: false }
    }),
  )
}

/** Each attendee of an invitation with their answer (none given: needs-action). */
export async function attendeeAnswers(account: MailAccount, calendar: Calendar, event: CalendarEvent): Promise<AttendeeAnswer[]> {
  if (!event.attendees) return []
  const organizer = event.fields.organizer ? canonicalEmail(event.fields.organizer) : null
  const rows = event.attendeeRows.map((row) => ({ token: row.token, answer: row.answer }))
  const opened = await openAnswerRows(
    account,
    (some, keys) => calendar.unlocked.openAnswers(event.sealed, event.sharedEventId, some, keys),
    organizer,
    event.tokens,
    rows,
  )
  return answersOf(event.attendees, event.tokens, opened)
}

function answersOf(attendees: Attendee[], tokens: { email: string; token: string }[], opened: { token: string; answer: Answer | null; verified: boolean }[]): AttendeeAnswer[] {
  const byToken = new Map(opened.map((o) => [o.token, o]))
  return attendees.map((attendee) => {
    const token = tokens.find((t) => t.email === attendee.email)?.token
    const row = token ? byToken.get(token) : undefined
    return {
      ...attendee,
      partstat: row?.answer?.partstat ?? 'needs-action',
      note: row?.answer?.note ?? null,
      verified: row?.verified ?? false,
    }
  })
}

/**
 * Leaves a Kutup invitation: this account's copy and its invitee row go, so
 * it stops counting against the account's limits and isn't listed again;
 * the answer row stays with the last answer given (decline first).
 */
export async function leaveInvitation(sharedEventId: string): Promise<void> {
  await api.delete(`/calendar/invitations/events/${encodeURIComponent(sharedEventId)}`)
}

/** Writes an answer row (`409 answerStale` when a newer one is stored). */
export async function putAnswer(sharedEventId: string, token: string, answer: string, updatedAt: string): Promise<void> {
  await api.put(`/calendar/shared-events/${encodeURIComponent(sharedEventId)}/attendees/${encodeURIComponent(token)}`, { answer, updatedAt })
}

function nowSeconds(): string {
  return new Date(Math.floor(Date.now() / 1000) * 1000).toISOString().replace('.000Z', 'Z')
}

/** The attendee this account is on an invitation, by its addresses. */
export function ownAttendee(account: MailAccount, attendees: Attendee[] | null): Attendee | null {
  return attendees?.find((a) => account.isOwnAddress(a.email)) ?? null
}

/**
 * An attendee answers from their copy (Calendar's event view, or Mail's
 * widget for a Kutup invitation): their sealed answer written first, then
 * the REPLY to the organizer, marked as already on the server.
 */
export async function answerFromCopy(args: {
  account: MailAccount
  pinned: PinnedKeys
  calendar: Calendar
  event: CalendarEvent
  partstat: Exclude<Partstat, 'needs-action'>
  note: string | null
  lng: string
}): Promise<SendFailure[]> {
  const { account, pinned, calendar, event, partstat, note, lng } = args
  const me = ownAttendee(account, event.attendees)
  const organizer = event.fields.organizer ? canonicalEmail(event.fields.organizer) : null
  if (!me || !organizer) throw new Error('not invited at an address of this account')
  const at = nowSeconds()
  const sealed = calendar.unlocked.sealAnswer(account.key, event.sealed, event.sharedEventId, me.email, partstat, note, at)
  await putAnswer(event.sharedEventId, sealed.token, sealed.answer, at)
  return sendReply({ account, pinned, fields: event.fields, organizer: { email: organizer, name: null }, me, partstat, note, lng, kutupReply: event.home === false })
}

/** Proton's REPLY: to the organizer only, the sender's answer alone. */
export async function sendReply(args: {
  account: MailAccount
  pinned: PinnedKeys
  fields: EventFields
  organizer: { email: string; name?: string | null }
  me: Attendee
  partstat: Exclude<Partstat, 'needs-action'>
  note: string | null
  lng: string
  kutupReply: boolean
  subject?: string
  inReplyTo?: string | null
}): Promise<SendFailure[]> {
  const { account, pinned, fields, organizer, me, partstat, note, lng } = args
  return sendInvitationMessage(account, pinned, {
    method: 'REPLY',
    fields: { ...fields, dtstamp: nowSeconds() },
    organizer: { email: organizer.email, name: organizer.name ?? null },
    attendees: [{ email: me.email, name: me.name ?? null, partstat, optional: me.optional ?? false, rsvp: false }],
    to: [{ email: organizer.email, name: organizer.name ?? null }],
    note,
    kutupReply: args.kutupReply,
    lng,
    subject: args.subject,
    inReplyTo: args.inReplyTo,
  })
}

/**
 * The organizer applies an outside reply (§5): the answer of `email`
 * (the reply's ATTENDEE, which must be its sender), sealed under the
 * event's shared key and signed by the organizer, at the reply's DTSTAMP.
 * `stale`: a newer answer is stored.
 */
export async function applyReply(args: {
  account: MailAccount
  calendar: Calendar
  event: CalendarEvent
  email: string
  partstat: Exclude<Partstat, 'needs-action'>
  note: string | null
  dtstamp: string
}): Promise<'applied' | 'stale'> {
  const { account, calendar, event } = args
  const at = new Date(Math.floor(Date.parse(args.dtstamp) / 1000) * 1000).toISOString().replace('.000Z', 'Z')
  const sealed = calendar.unlocked.sealAnswer(account.key, event.sealed, event.sharedEventId, canonicalEmail(args.email), args.partstat, args.note, at)
  try {
    await putAnswer(event.sharedEventId, sealed.token, sealed.answer, at)
    return 'applied'
  } catch (error) {
    const code = (error as { response?: { status?: number; data?: { code?: string } } }).response?.data?.code
    if (code === 'answerStale') return 'stale'
    throw error
  }
}

// ----- Kutup attendees: invitations listed, opened, adopted -----

/** An invitation as the server lists it to its Kutup attendee. */
export interface InvitedEventRow {
  sharedEventId: string
  uid: string
  authorAddress: string | null
  address: string
  keyPacket: string
  token: string
  sharedSigned: EventPart
  sharedEncrypted: EventPart
  attendees: EventPart | null
  startUtc: string
  endUtc: string
  rangeEndUtc: string | null
  sequence: number
  copies: [string, string][]
  attendeeRows: AttendeeRow[]
}

/** An invitation opened by its Kutup attendee. */
export interface InvitedEvent {
  row: InvitedEventRow
  fields: EventFields
  /** The organizer's keys signed the shared parts and the attendee part, and ORGANIZER is that address. */
  verified: boolean
  organizer: string | null
  attendees: Attendee[]
  me: Attendee | null
  /** This account's own answer, as its row holds it. */
  answer: Answer | null
  invitation: OpenedInvitation
}

/** The most pages the invitations list is read in. */
const MAX_INVITATION_PAGES = 100

export async function loadInvitedRows(): Promise<InvitedEventRow[]> {
  const rows: InvitedEventRow[] = []
  let after: string | null = null
  for (let pages = 1; ; pages++) {
    const response: { data: { events: InvitedEventRow[]; next: string | null } } = await api.get('/calendar/invitations/events', { params: after ? { afterId: after } : {} })
    const page = response.data
    rows.push(...page.events)
    if (!page.next) break
    if (pages >= MAX_INVITATION_PAGES || (after && page.next <= after)) throw new Error('the server never ends this listing')
    after = page.next
  }
  return rows
}

/** Opens a listed invitation with the account's address key; `free()` its `invitation` when done. */
export async function openInvitedEvent(account: MailAccount, row: InvitedEventRow): Promise<InvitedEvent> {
  const organizerKeys = await authorKeys(account, row.authorAddress).catch(() => [])
  const invitation = await openInvitation(account.key, row.keyPacket, { sharedSigned: row.sharedSigned, sharedEncrypted: row.sharedEncrypted, attendees: row.attendees }, organizerKeys)
  const view = invitation.view
  const organizer = view.fields.organizer ? canonicalEmail(view.fields.organizer) : null
  const signedByOrganizer = !!organizer && !!row.authorAddress && organizer === canonicalEmail(row.authorAddress) && organizerKeys.length > 0
  const me = ownAttendee(account, view.attendees)
  // The row the server says is ours must be the token we derive ourselves.
  const ownToken = me ? invitation.tokenFor(me.email) : null
  const ownRow = row.attendeeRows.find((r) => r.token === ownToken && ownToken === row.token)
  const keys = [...organizerKeys, ...account.ownPublicKeys]
  const answer = ownRow ? (invitation.openAnswers(row.sharedEventId, [{ token: ownRow.token, answer: ownRow.answer }], keys)[0]?.answer ?? null) : null
  return {
    row,
    fields: view.fields,
    verified: view.verified && view.attendeesVerified && signedByOrganizer,
    organizer,
    attendees: view.attendees,
    me,
    answer,
    invitation,
  }
}

/**
 * Adopts an invitation into a calendar the account owns (Q-6), marked as
 * pending: the attendee's own calendar row for the shared event.
 */
export async function adoptInvitation(session: Session, account: MailAccount, calendar: Calendar, invited: InvitedEvent): Promise<EventRow> {
  await beforeEventWrite(session)
  if (!calendar.owned) throw new Error('an invitation goes into a calendar of your own')
  const row = invited.invitation.adopt(calendar.unlocked, account.key, { dtstamp: nowSeconds() })
  const addressId = await activeAddressId(account)
  const { data } = await api.post<EventRow>(`/calendar/calendars/${encodeURIComponent(calendar.id)}/events/adopt`, {
    id: crypto.randomUUID(),
    sharedEventId: invited.row.sharedEventId,
    addressId,
    ...row,
  })
  return data
}

/** A Kutup attendee answers a listed invitation (Mail's widget): the answer row, then the REPLY. */
export async function answerInvited(args: {
  account: MailAccount
  pinned: PinnedKeys
  invited: InvitedEvent
  partstat: Exclude<Partstat, 'needs-action'>
  note: string | null
  lng: string
  subject?: string
  inReplyTo?: string | null
}): Promise<SendFailure[]> {
  const { account, pinned, invited, partstat, note, lng } = args
  if (!invited.me || !invited.organizer) throw new Error('not invited at an address of this account')
  const at = nowSeconds()
  const sealed = invited.invitation.sealAnswer(account.key, invited.row.sharedEventId, invited.me.email, partstat, note, at)
  await putAnswer(invited.row.sharedEventId, sealed.token, sealed.answer, at)
  return sendReply({
    account,
    pinned,
    fields: invited.fields,
    organizer: { email: invited.organizer },
    me: invited.me,
    partstat,
    note,
    lng,
    kutupReply: true,
    subject: args.subject,
    inReplyTo: args.inReplyTo,
  })
}

/** The calendar an invitation lands in (Q-6): the first the account owns, or the one chosen. */
export function defaultCalendar(calendars: Calendar[]): Calendar | null {
  return calendars.find((calendar) => calendar.owned) ?? null
}

/**
 * "Add to calendar and mark as pending" (Proton's `AutoImportInvite`): every
 * listed invitation not in a calendar yet, and not declined, adopted into
 * the default calendar. Returns how many were added.
 */
/** Invitations already looked at on this page, by shared event and the state it was looked at in. */
const lookedAt = new Set<string>()

export async function addPendingInvitations(session: Session, account: MailAccount, calendars: Calendar[]): Promise<number> {
  const target = defaultCalendar(calendars)
  if (!target) return 0
  let added = 0
  for (const row of await loadInvitedRows()) {
    if (row.copies.length > 0) continue
    // Each listed invitation is opened once per change, not at every look
    // (security review M5): one declined, unverified or failing stays
    // skipped until its organizer changes it.
    const seen = `${row.sharedEventId}:${row.sequence}:${row.sharedSigned.signature}:${row.attendees?.signature ?? ''}`
    if (lookedAt.has(seen)) continue
    lookedAt.add(seen)
    let invited: InvitedEvent | null = null
    try {
      invited = await openInvitedEvent(account, row)
      // Only what the organizer signed, invites this account, and wasn't declined.
      if (!invited.verified || !invited.me || invited.answer?.partstat === 'declined') continue
      await adoptInvitation(session, account, target, invited)
      added++
    } catch {
      // One that doesn't open or adopt is left for Mail's widget.
    } finally {
      invited?.invitation.free()
    }
  }
  return added
}
