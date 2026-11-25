// Mail's invitation widget (docs/plans/calendar-e4.md §5), as Proton's
// `ExtraEvents` (`applications/mail/src/app/helpers/calendar/invite.ts`):
// each `text/calendar` part of a message read with the calendar runtime,
// matched against the account's calendars, and the states and actions
// Proton's widget has.
//
// What is trusted, and on what:
// - The ICS is the sender's word only. A REPLY is applied only when its
//   ATTENDEE is the message's sender (`replyNotFromAttendee` otherwise), and
//   only to an event this account organizes, for an attendee it invited.
// - `X-KUTUP-REPLY` grants nothing: it only says the answer may already be
//   on the event, which the organizer reads from its own sealed row.
// - A Kutup invitation is opened from the server's listing with the
//   account's address key and checked against the organizer's keys; the
//   ICS in the mail only finds it (by UID).

import type { Attendee, EventFields, Partstat } from '@kutup/crypto/calendar'
import { readInvitation, type Invitation, type InvitationAttendee, type InvitationOutcome } from '@kutup/crypto/calendarIcs'
import type { MailAccount, PinnedKeys } from '@kutup/mail-core/api'
import type { Session } from '@kutup/session/store'
import { activeAddressId, beforeEventWrite, loadSeries, saveEvent, syncOne, type Calendar, type CalendarEvent } from './api'
import {
  addPendingInvitations,
  adoptInvitation,
  answerInvited,
  applyReply,
  attendeeAnswers,
  canonicalEmail,
  defaultCalendar,
  invitationLimits,
  kutupInvitees,
  loadInvitedRows,
  openInvitedEvent,
  putAnswer,
  saveInvitedEvent,
  sendReply,
  type InvitedEvent,
  type SendFailure,
} from './invitations'

/** A message's calendar parts, each once (Google sends one inline and one attached). */
export function calendarParts(attachments: { filename: string; mimeType: string; content: Uint8Array }[], maxBytes: number): string[] {
  const seen = new Set<string>()
  const texts: string[] = []
  for (const part of attachments) {
    const type = part.mimeType.toLowerCase()
    if (type !== 'text/calendar' && type !== 'application/ics' && !/\.ics$/i.test(part.filename)) continue
    if (part.content.length > maxBytes) continue
    const text = new TextDecoder().decode(part.content)
    const key = text.replace(/\r\n/g, '\n').trim()
    if (seen.has(key)) continue
    seen.add(key)
    texts.push(text)
  }
  return texts
}

/** The message an invitation came in. */
export interface CarryingMessage {
  /** The sender's address (the From the message was delivered with). */
  from: string | null
  /** The From passed DMARC on arrival, or a Kutup account sent it. */
  authenticated: boolean
  /** When the server received it (not the sender's own Date). */
  receivedAt: string | null
  date: string | null
  subject: string
  messageId: string | null
}

/** A stored event an invitation matches, and its calendar. */
export interface Stored {
  calendar: Calendar
  event: CalendarEvent
}

export type WidgetState =
  | { kind: 'error'; key: string }
  | { kind: 'unsupported'; method: string }
  | { kind: 'publish'; invitation: Invitation; stored: Stored | null }
  | {
      kind: 'attendee'
      invitation: Invitation
      /** The account's attendee, by its addresses; null: a party crasher. */
      me: InvitationAttendee | null
      stored: Stored | null
      kutup: InvitedEvent | null
      status: 'new' | 'updated' | 'outdated' | 'cancelled'
      /**
       * The mail verifiably comes from the invitation's organizer (its From
       * is the ORGANIZER and passed DMARC): only then does Mail apply an
       * update or a cancellation, or add it, on its own.
       */
      fromOrganizer: boolean
      /** This account's answer as its calendar holds it. */
      answer: Partstat | null
      timing: 'upcoming' | 'inProgress' | 'ended'
    }
  | {
      kind: 'organizer'
      invitation: Invitation
      attendee: InvitationAttendee
      stored: Stored | null
      status: 'applied' | 'kutupReply' | 'outdated' | 'noEvent' | 'partyCrasher' | 'notFromAttendee' | 'unverifiedSender' | 'occurrence' | 'counter'
    }

/** The widget's error text key for a refusal, as Proton's `getICSInvitationErrorMessage`. */
export function errorKey(outcome: Extract<InvitationOutcome, { refused: unknown }>['refused']): string {
  const method = outcome.method
  const response = method === 'REPLY' || method === 'COUNTER' || method === 'REFRESH'
  const kind = !method ? null : method === 'PUBLISH' ? 'event' : response ? 'response' : 'invitation'
  switch (outcome.error) {
    case 'invitationInvalid':
      return kind ? `invitation.widget.error.${kind}Invalid` : 'invitation.widget.error.parsingError'
    case 'invitationUnsupported':
      if (outcome.reason === 'tzidUnsupported') return 'invitation.widget.error.tzidUnsupported'
      return `invitation.widget.error.${kind ?? 'invitation'}Unsupported`
    case 'invalidMethod':
      return 'invitation.widget.error.invalidMethod'
    default:
      return `invitation.widget.error.${outcome.error}`
  }
}

function zone(): string {
  try {
    return Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC'
  } catch {
    return 'UTC'
  }
}

/** Reads one calendar part. */
export async function readPart(text: string, message: CarryingMessage): Promise<InvitationOutcome> {
  const limits = await invitationLimits()
  return readInvitation(text, {
    primaryZone: zone(),
    maxBytes: limits.invitationIcsMaxBytes,
    maxCount: limits.invitationCountMax,
    maxAttendees: limits.attendeesPerEvent,
    now: new Date().toISOString(),
    messageDate: message.date,
    sender: message.from,
  })
}

function sameRecurrence(a: EventFields['recurrenceId'], b: EventFields['recurrenceId']): boolean {
  return JSON.stringify(a ?? null) === JSON.stringify(b ?? null)
}

/**
 * The stored event an invitation names: by UID and RECURRENCE-ID, in the
 * account's own calendars first, and only one organized by `organizer`
 * (when given): a mail naming someone else's UID never reaches an event
 * that isn't theirs, and never one this account organizes.
 */
export async function findStored(account: MailAccount, calendars: Calendar[], fields: EventFields, organizer?: string | null): Promise<Stored | null> {
  for (const calendar of [...calendars].sort((a, b) => Number(b.owned) - Number(a.owned))) {
    try {
      const series = await loadSeries(account, calendar, fields.uid)
      const event = series.find(
        (e) =>
          sameRecurrence(e.fields.recurrenceId, fields.recurrenceId) &&
          (organizer === undefined || organizerMatches(account, e, organizer)),
      )
      if (event) return { calendar, event }
    } catch {
      // A calendar that can't be read now holds nothing for the widget.
    }
  }
  return null
}

/**
 * Whether a stored event is the attendee's copy of `organizer`'s invitation:
 * its ORGANIZER that address (a Kutup copy: the address that signed it),
 * and not this account's own.
 */
function organizerMatches(account: MailAccount, event: CalendarEvent, organizer: string | null): boolean {
  if (!organizer || account.isOwnAddress(organizer)) return false
  const stored = event.fields.organizer ? canonicalEmail(event.fields.organizer) : null
  if (stored !== organizer) return false
  // A Kutup copy's organizer is the one whose keys verified it.
  return event.home || event.organizer === organizer
}

function timing(fields: EventFields, now = Date.now()): 'upcoming' | 'inProgress' | 'ended' {
  if (fields.rrule) return 'upcoming'
  const at = (time: EventFields['start'] | null) => {
    if (!time) return null
    if ('date' in time) return Date.parse(`${time.date}T00:00:00Z`)
    if ('utc' in time) return Date.parse(time.utc)
    return Date.parse(`${time.zoned.local}Z`)
  }
  const start = at(fields.start) ?? now
  const end = at(fields.end) ?? start
  if (end < now) return 'ended'
  if (start <= now) return 'inProgress'
  return 'upcoming'
}

/** Proton's "outdated": a lower SEQUENCE, or the same and an older DTSTAMP. */
function isOutdated(received: EventFields, stored: EventFields): boolean {
  const a = received.sequence ?? 0
  const b = stored.sequence ?? 0
  if (a !== b) return a < b
  return Date.parse(received.dtstamp) < Date.parse(stored.dtstamp)
}

/** Works out what the widget shows for one invitation. */
export async function widgetState(args: {
  account: MailAccount
  calendars: Calendar[]
  outcome: InvitationOutcome
  message: CarryingMessage
}): Promise<WidgetState> {
  const { account, calendars, outcome, message } = args
  if ('refused' in outcome) {
    if (outcome.refused.error === 'invitationUnsupported' && !outcome.refused.reason && outcome.refused.method) {
      return { kind: 'unsupported', method: outcome.refused.method }
    }
    return { kind: 'error', key: errorKey(outcome.refused) }
  }
  const invitation = outcome.read
  const organizerIsMe = !!invitation.organizer && account.isOwnAddress(invitation.organizer.email)
  if (invitation.method === 'PUBLISH') {
    return { kind: 'publish', invitation, stored: await findStored(account, calendars, invitation.fields) }
  }
  if (invitation.method === 'REPLY' || invitation.method === 'COUNTER') {
    // Proton: a reply only reaches an organizer.
    if (!organizerIsMe) return { kind: 'error', key: 'invitation.widget.error.invalidMethod' }
    const attendee = invitation.attendees[0]
    if (!attendee) return { kind: 'error', key: 'invitation.widget.error.responseInvalid' }
    const stored = await findStored(account, calendars.filter((c) => c.owned), invitation.fields)
    const base = { kind: 'organizer' as const, invitation, attendee, stored }
    if (!message.from || canonicalEmail(message.from) !== attendee.email) return { ...base, status: 'notFromAttendee' }
    // A From header alone is anyone's to write: the answer counts only from a
    // sender DMARC vouched for.
    if (!message.authenticated) return { ...base, status: 'unverifiedSender' }
    // Only an event this account organizes, at its home, signed by it.
    if (!stored || !stored.event.home || stored.event.organizer === null || !account.isOwnAddress(stored.event.organizer)) {
      // A reply to one occurrence of a series this account holds.
      if (invitation.fields.recurrenceId) {
        const series = await findStored(account, calendars.filter((c) => c.owned), { ...invitation.fields, recurrenceId: null })
        if (series) return { ...base, stored: series, status: 'occurrence' }
      }
      return { ...base, status: 'noEvent' }
    }
    if (!stored.event.attendees?.some((a) => a.email === attendee.email)) return { ...base, status: 'partyCrasher' }
    if (invitation.method === 'COUNTER' && attendee.partstat === 'needs-action') return { ...base, status: 'counter' }
    if (invitation.kutupReply) return { ...base, status: 'kutupReply' }
    if ((invitation.fields.sequence ?? 0) < (stored.event.sequence ?? 0)) return { ...base, status: 'outdated' }
    return { ...base, status: invitation.method === 'COUNTER' ? 'counter' : 'applied' }
  }
  // REQUEST and CANCEL only reach an attendee.
  if (organizerIsMe) return { kind: 'error', key: 'invitation.widget.error.invalidMethod' }
  const me = invitation.attendees.find((a) => account.isOwnAddress(a.email)) ?? null
  const organizer = invitation.organizer?.email ?? null
  if (!organizer) return { kind: 'error', key: 'invitation.widget.error.invitationInvalid' }
  const stored = await findStored(account, calendars, invitation.fields, organizer)
  let kutup: InvitedEvent | null = null
  if (!stored || stored.event.home === false) {
    try {
      // Every row with the UID: another organizer may use the same one.
      for (const row of (await loadInvitedRows()).filter((r) => r.uid === invitation.fields.uid)) {
        const opened = await openInvitedEvent(account, row)
        // The mail only finds it: it counts when its signed organizer is the one the mail names.
        if (opened.verified && opened.organizer === organizer && sameRecurrence(opened.fields.recurrenceId, invitation.fields.recurrenceId)) {
          kutup = opened
          break
        }
        opened.invitation.free()
      }
    } catch {
      kutup = null
    }
  }
  const known = stored?.event.fields ?? kutup?.fields ?? null
  let status: 'new' | 'updated' | 'outdated' | 'cancelled' = 'new'
  // A Kutup invitation is cancelled when its signed state says so, never by
  // a mail's METHOD alone (anyone can send a CANCEL naming its UID).
  if (kutup) status = kutup.fields.status === 'cancelled' ? 'cancelled' : 'new'
  else if (invitation.method === 'CANCEL') status = 'cancelled'
  else if (known && isOutdated(invitation.fields, known)) status = 'outdated'
  // An update: a higher SEQUENCE (the event moved), or the same and a newer
  // DTSTAMP (its title, place or description changed, the answer kept).
  else if (known && ((invitation.fields.sequence ?? 0) > (known.sequence ?? 0) || Date.parse(invitation.fields.dtstamp) > Date.parse(known.dtstamp))) status = 'updated'
  let answer: Partstat | null = kutup?.answer?.partstat ?? null
  if (!answer && stored?.event.attendees) {
    const mine = (await attendeeAnswers(account, stored.calendar, stored.event).catch(() => [])).find((a) => account.isOwnAddress(a.email))
    answer = mine && mine.partstat !== 'needs-action' ? mine.partstat : null
  }
  const fromOrganizer = message.authenticated && !!message.from && canonicalEmail(message.from) === organizer
  return { kind: 'attendee', invitation, me, stored, kutup, status, fromOrganizer, answer, timing: timing(invitation.fields) }
}

// ----- actions -----

function attendeesOf(invitation: Invitation): Attendee[] {
  return invitation.attendees.map((a) => ({ email: a.email, name: a.name ?? null, optional: a.optional }))
}

/**
 * An outside invitation kept as the attendee's own event (its ORGANIZER the
 * outside one, its attendees as the invitation lists them, so the event view
 * shows them), updated in place when it is there.
 */
async function storeOutside(
  session: Session,
  account: MailAccount,
  calendar: Calendar,
  invitation: Invitation,
  stored: Stored | null,
  keepAttendees = false,
): Promise<Stored> {
  await beforeEventWrite(session)
  const existing = stored?.event
  // An older copy of the invitation (a lower SEQUENCE, or the same and an
  // older DTSTAMP) never replaces what is stored (security review L4).
  const older = !!existing && isOutdated(invitation.fields, existing.fields)
  const fields: EventFields = {
    ...(older && existing ? existing.fields : { ...(existing ? existing.fields : {}), ...invitation.fields }),
    comment: existing?.fields.comment ?? null,
    organizer: invitation.organizer ? `mailto:${invitation.organizer.email}` : null,
  }
  // A cancellation lists only whom it cancels: the event keeps its list.
  const attendees = (keepAttendees || older) && existing?.attendees ? existing.attendees : attendeesOf(invitation)
  const sealed = calendar.unlocked.sealInvitation(account.key, fields, attendees, [], existing?.sealed ?? null)
  const tokenOf = new Map(sealed.tokens.map((t) => [t.email, t.token]))
  const invitationIn = sealed.attendees
    ? {
        attendees: sealed.attendees,
        rows: attendees.map((a) => ({ token: tokenOf.get(a.email)!, optional: a.optional ?? false })),
        invitees: [],
        // A moved event is answered again (Proton resets the answer on a higher SEQUENCE).
        resetAnswers: !!existing && (invitation.fields.sequence ?? 0) > (existing.sequence ?? 0),
      }
    : undefined
  const addressId = await activeAddressId(account)
  const row = await syncOne(
    calendar,
    addressId,
    existing
      ? { update: { id: existing.id, baseRevision: existing.revision, event: sealed.event, ...(invitationIn ? { invitation: invitationIn } : {}) } }
      : { create: { id: crypto.randomUUID(), event: sealed.event, ...(invitationIn ? { invitation: invitationIn } : {}) } },
  )
  const series = await loadSeries(account, calendar, fields.uid)
  const event = series.find((e) => e.id === row?.id) ?? series.find((e) => sameRecurrence(e.fields.recurrenceId, fields.recurrenceId))
  if (!event) throw new Error('the event is not in the calendar after saving it')
  return { calendar, event }
}

/**
 * The attendee answers (Yes / Maybe / No, with a note): a Kutup invitation's
 * answer row (adopting it first), or an outside one kept in the calendar
 * with the answer; then the REPLY to the organizer.
 */
export async function answerInvitation(args: {
  session: Session
  account: MailAccount
  pinned: PinnedKeys
  calendars: Calendar[]
  /** The calendar a new one goes in (Q-6: the default, or the one chosen). */
  calendar: Calendar | null
  state: Extract<WidgetState, { kind: 'attendee' }>
  partstat: Exclude<Partstat, 'needs-action'>
  note: string | null
  lng: string
  message: CarryingMessage
}): Promise<SendFailure[]> {
  const { session, account, pinned, state, partstat, note, lng, message } = args
  const { invitation, me } = state
  if (!me) throw new Error('not invited at an address of this account')
  const target = args.calendar ?? state.stored?.calendar ?? defaultCalendar(args.calendars)
  if (state.kutup) {
    if (state.kutup.row.copies.length === 0 && target) await adoptInvitation(session, account, target, state.kutup)
    return answerInvited({ account, pinned, invited: state.kutup, partstat, note, lng, subject: message.subject, inReplyTo: message.messageId })
  }
  if (!target) throw new Error('no calendar')
  const kept = await storeOutside(session, account, state.stored?.calendar ?? target, invitation, state.stored)
  const at = new Date(Math.floor(Date.now() / 1000) * 1000).toISOString().replace('.000Z', 'Z')
  const sealed = kept.calendar.unlocked.sealAnswer(account.key, kept.event.sealed, kept.event.sharedEventId, me.email, partstat, note, at)
  await putAnswer(kept.event.sharedEventId, sealed.token, sealed.answer, at)
  return sendReply({
    account,
    pinned,
    fields: invitation.fields,
    organizer: invitation.organizer ?? { email: message.from ?? '' },
    me: { email: me.email, name: me.name ?? null, optional: me.optional },
    partstat,
    note,
    lng,
    kutupReply: false,
    subject: message.subject,
    inReplyTo: message.messageId,
  })
}

/**
 * What the widget does on its own when shown, as Proton's: an update or a
 * cancellation of an outside invitation already in the calendar is applied
 * to it; a new one goes in as pending when the account says so ("Add to
 * calendar and mark as pending").
 */
export async function applyOnView(args: {
  session: Session
  account: MailAccount
  calendars: Calendar[]
  state: WidgetState
  autoAdd: boolean
  message: CarryingMessage
}): Promise<boolean | 'stale'> {
  const { session, account, calendars, state, message } = args
  if (state.kind === 'organizer') {
    if (state.status !== 'applied' && !(state.status === 'counter' && state.attendee.partstat !== 'needs-action')) return false
    if (!state.stored || state.attendee.partstat === 'needs-action' || state.attendee.partstat === 'delegated') return false
    // A Kutup attendee answers in their own row, signed; a mail never writes it.
    if ((await kutupInvitees(account, [{ email: state.attendee.email, name: null }]).catch(() => [null])).length > 0) return false
    // Dated no later than its arrival: a reply dated ahead would make the
    // attendee's real answer look stale until then.
    const arrived = message.receivedAt ? Date.parse(message.receivedAt) : Date.now()
    const dated = Math.min(Date.parse(state.invitation.fields.dtstamp), arrived)
    return applyReply({
      account,
      calendar: state.stored.calendar,
      event: state.stored.event,
      email: state.attendee.email,
      partstat: state.attendee.partstat,
      note: state.invitation.note,
      dtstamp: new Date(dated).toISOString(),
    }).then((outcome) => (outcome === 'stale' ? 'stale' : true))
  }
  if (state.kind !== 'attendee' || state.kutup || !state.me) {
    if (state.kind === 'attendee' && state.kutup && args.autoAdd) return (await addPendingInvitations(session, account, calendars)) > 0
    return false
  }
  if (state.status === 'outdated') return false
  // Only what verifiably comes from the organizer changes the calendar by
  // itself; anything else the person applies by answering.
  if (!state.fromOrganizer) return false
  if (state.stored && state.stored.event.home) {
    if (state.status === 'cancelled') {
      if (state.stored.event.fields.status === 'cancelled') return false
      const cancelled = { ...state.invitation, fields: { ...state.invitation.fields, status: 'cancelled' as const } }
      await storeOutside(session, account, state.stored.calendar, cancelled, state.stored, true)
      return true
    }
    if (state.status === 'updated') {
      await storeOutside(session, account, state.stored.calendar, state.invitation, state.stored)
      return true
    }
    return false
  }
  if (!state.stored && state.status === 'new' && args.autoAdd) {
    const target = defaultCalendar(calendars)
    if (!target) return false
    await storeOutside(session, account, target, state.invitation, null)
    return true
  }
  return false
}

/** "Add to Calendar" for a published event (PUBLISH): an event of the account's own, no organizer. */
export async function addPublished(session: Session, account: MailAccount, calendar: Calendar, invitation: Invitation): Promise<void> {
  await saveEvent(session, account, calendar, { ...invitation.fields, organizer: null })
}

/** The organizer adds a party crasher (Proton's "Add participant"): saved with them, invited. */
export async function addParticipant(args: {
  session: Session
  account: MailAccount
  pinned: PinnedKeys
  state: Extract<WidgetState, { kind: 'organizer' }>
  lng: string
}): Promise<SendFailure[]> {
  const { state } = args
  if (!state.stored) throw new Error('no event')
  const event = state.stored.event
  const attendees = [...(event.attendees ?? []), { email: state.attendee.email, name: state.attendee.name ?? null, optional: false }]
  const saved = await saveInvitedEvent({
    session: args.session,
    account: args.account,
    pinned: args.pinned,
    calendar: state.stored.calendar,
    fields: event.fields,
    attendees,
    existing: event,
    lng: args.lng,
  })
  return saved.failures
}
