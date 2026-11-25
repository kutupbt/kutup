// Invitations as mail (docs/plans/calendar-e4.md §4–5), as Proton sends
// them (`packages/shared/lib/calendar/mailIntegration/invite.ts`,
// `useSendIcs`): one plain-text message for everyone and `invite.ics`
// (`text/calendar; method=…`) beside it, through Mail's own send, so each
// recipient's encryption is Mail's (Kutup, PGP or plain). The text is in the
// language the organizer sends in ("Send in", Proton's `InviteLocale`).

import type { CalendarTime, EventFields } from '@kutup/crypto/calendar'
import { writeInvitation, type InvitationAttendee, type InvitationPartstat, type InvitationPerson } from '@kutup/crypto/calendarIcs'
import { i18n } from '@kutup/i18n'
import { emptyDraft, isHeld, sendDraft, type MailAccount, type PinnedKeys } from '@kutup/mail-core/api'
import { attachmentPart } from '@kutup/mail-core/mime'
import { RELEASE } from '@kutup/session/release'

export type InviteMethod = 'REQUEST' | 'REPLY' | 'CANCEL'

/** A recipient a message didn't reach, and why (the send's error). */
export interface SendFailure {
  address: string
  reason: string
}

/** The release as an ICS PRODID takes it (`-//Kutup//Calendar <release>//EN`). */
function release(): string {
  return /^[A-Za-z0-9.+_-]{1,64}$/.test(RELEASE) ? RELEASE : '0.0.0-dev'
}

function zoneOf(time: CalendarTime): string | undefined {
  return 'zoned' in time ? time.zoned.tzid : undefined
}

/** A time as the message shows it: in its own zone (and the zone named), a date as a date. */
function formatTime(time: CalendarTime, lng: string): string {
  if ('date' in time) {
    return new Intl.DateTimeFormat(lng, { dateStyle: 'full', timeZone: 'UTC' }).format(new Date(`${time.date}T00:00:00Z`))
  }
  if ('utc' in time) {
    return new Intl.DateTimeFormat(lng, { dateStyle: 'full', timeStyle: 'short', timeZone: 'UTC', timeZoneName: 'short' }).format(new Date(time.utc))
  }
  // A wall-clock time shown as written, with its zone's name.
  const [date, clock] = time.zoned.local.split('T')
  const shown = new Intl.DateTimeFormat(lng, { dateStyle: 'full', timeStyle: 'short', timeZone: 'UTC' }).format(new Date(`${date}T${clock}Z`))
  return `${shown} (${zoneOf(time)})`
}

/** The day before an all-day end (an all-day DTEND is exclusive). */
function dayBefore(date: string): string {
  const day = new Date(`${date}T00:00:00Z`)
  day.setUTCDate(day.getUTCDate() - 1)
  return day.toISOString().slice(0, 10)
}

function whenOf(fields: EventFields, lng: string): { start: string; end: string | null; allDay: boolean; singleDay: boolean } {
  const allDay = 'date' in fields.start
  const start = formatTime(fields.start, lng)
  if (!fields.end) return { start, end: null, allDay, singleDay: true }
  if (allDay && 'date' in fields.end && 'date' in fields.start) {
    const last = dayBefore(fields.end.date)
    if (last <= fields.start.date) return { start, end: null, allDay, singleDay: true }
    return { start, end: formatTime({ date: last }, lng), allDay, singleDay: false }
  }
  return { start, end: formatTime(fields.end, lng), allDay, singleDay: false }
}

/** Proton's `generateEmailSubject`. */
export function invitationSubject(method: InviteMethod, fields: EventFields, created: boolean, lng: string): string {
  const t = i18n.getFixedT(lng)
  const when = whenOf(fields, lng)
  const day = when.allDay && when.singleDay ? 'AllDay' : ''
  const kind = method === 'CANCEL' ? 'cancel' : method === 'REPLY' ? 'reply' : created && !fields.recurrenceId ? 'invite' : 'update'
  return t(`invitation.subject.${kind}${day}`, { when: when.start })
}

interface Texts {
  title: string
  whenText: string
  location: string
  description: string
}

function texts(fields: EventFields, lng: string): Texts {
  const t = i18n.getFixedT(lng)
  const when = whenOf(fields, lng)
  const span = when.end ? t('invitation.body.range', { start: when.start, end: when.end }) : when.allDay ? t('invitation.body.allDay', { when: when.start }) : when.start
  return {
    title: fields.summary?.trim() || t('invitation.body.untitled'),
    whenText: `${t('invitation.body.time')}\n${span}`,
    location: fields.location ? `${t('invitation.body.location')}\n${fields.location}` : '',
    description: fields.description ? `${t('invitation.body.description')}\n${fields.description}` : '',
  }
}

/** What an update changed, as Proton's `getUpdateEmailBodyText` lists it. */
function changes(fields: EventFields, old: EventFields, lng: string): string {
  const t = i18n.getFixedT(lng)
  const now = texts(fields, lng)
  const before = texts(old, lng)
  const removed = t('invitation.body.removed')
  const lines: string[] = []
  const push = (label: string, value: string, changed: boolean, empty: boolean) => {
    if (!changed) return
    lines.push(empty ? `${label}\n${removed}` : value)
  }
  push(t('invitation.body.title'), `${t('invitation.body.title')}\n${now.title}`, now.title !== before.title, false)
  push(t('invitation.body.time'), now.whenText, now.whenText !== before.whenText, false)
  push(t('invitation.body.location'), now.location, (fields.location ?? '') !== (old.location ?? ''), !fields.location)
  push(t('invitation.body.description'), now.description, (fields.description ?? '') !== (old.description ?? ''), !fields.description)
  return lines.join('\n')
}

/** Proton's `generateEmailBody`: the plain text of a request, an update, a cancellation or a reply. */
export function invitationBody(
  method: InviteMethod,
  fields: EventFields,
  lng: string,
  options: { old?: EventFields; partstat?: InvitationPartstat; email?: string; note?: string | null } = {},
): string {
  const t = i18n.getFixedT(lng)
  const own = texts(fields, lng)
  const note = options.note ? `${t('invitation.body.note')}\n${options.note}` : ''
  if (method === 'REPLY') {
    const key = options.partstat === 'accepted' ? 'accepted' : options.partstat === 'tentative' ? 'tentative' : 'declined'
    const line = t(`invitation.body.${key}`, { email: options.email ?? '', title: own.title })
    return note ? `${line}\n\n${note}` : line
  }
  if (method === 'CANCEL') {
    const intro = fields.recurrenceId ? t('invitation.body.cancelledOccurrence') : t('invitation.body.cancelled', { title: own.title })
    return note ? `${intro}\n\n${note}` : intro
  }
  if (!options.old) {
    const details = [own.whenText, own.location, own.description].filter(Boolean).join('\n')
    return `${t('invitation.body.invited', { title: own.title })}\n\n${details}`
  }
  const intro = fields.recurrenceId ? t('invitation.body.updatedOccurrence') : fields.rrule ? t('invitation.body.updatedSeries') : t('invitation.body.updated')
  const changed = changes(fields, options.old, lng)
  return changed ? `${intro}\n\n${t('invitation.body.changed')}\n\n${changed}` : intro
}

/** One message of an invitation's: who it goes to, and the ICS it carries. */
export interface InvitationMessage {
  method: InviteMethod
  /** The event as the ICS carries it (its SEQUENCE the one to send). */
  fields: EventFields
  organizer: InvitationPerson
  /** Everyone the ICS lists (for a reply: the sender alone, with the answer). */
  attendees: InvitationAttendee[]
  /** Who the message goes to. */
  to: InvitationPerson[]
  /** A new invitation (the subject says so). */
  created?: boolean
  /** An update: the event before it, for "Here's what changed". */
  old?: EventFields
  note?: string | null
  /** A reply whose answer is already on the organizer's server. */
  kutupReply?: boolean
  /** The language it is sent in ("Send in"). */
  lng: string
  /** A reply: the subject of the message answered (`Re: <subject>`). */
  subject?: string
  inReplyTo?: string | null
}

/**
 * Sends one invitation message through Mail: from the account's address,
 * plain text with `invite.ics`, a copy in Sent. Returns the recipients it
 * didn't reach (none on success; a held send is counted as sent, as Mail's
 * composer does).
 */
export async function sendInvitationMessage(account: MailAccount, pinned: PinnedKeys, message: InvitationMessage): Promise<SendFailure[]> {
  if (message.to.length === 0) return []
  const ics = await writeInvitation({
    method: message.method,
    release: release(),
    fields: message.fields,
    organizer: message.organizer,
    attendees: message.attendees,
    note: message.note ?? null,
    kutupReply: message.kutupReply ?? false,
  })
  const partstat = message.method === 'REPLY' ? (message.attendees[0]?.partstat ?? 'accepted') : undefined
  const text = invitationBody(message.method, message.fields, message.lng, {
    old: message.old,
    partstat,
    email: message.attendees[0]?.email,
    note: message.note,
  })
  const subject = message.subject
    ? /^re:/i.test(message.subject)
      ? message.subject
      : `Re: ${message.subject}`
    : invitationSubject(message.method, message.fields, message.created ?? false, message.lng)
  const draft = emptyDraft(account, {
    to: message.to.map((person) => ({ address: person.email, name: person.name ?? '' })),
    subject,
    text,
    html: '',
    plain: true,
    inReplyTo: message.inReplyTo ?? null,
  })
  const part = attachmentPart({
    name: 'invite.ics',
    type: `text/calendar; method=${message.method}; charset=utf-8`,
    bytes: new TextEncoder().encode(ics),
  })
  try {
    const outcome = await sendDraft(account, draft, [part], pinned)
    if (isHeld(outcome)) return []
    return outcome.filter((r) => r.status === 'failed').map((r) => ({ address: r.address, reason: 'failed' }))
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error)
    return message.to.map((person) => ({ address: person.email, reason }))
  }
}
