// Calendars and events (docs/plans/calendar.md, E1) as the Calendar app
// reads and writes them. Every calendar opens from the member's copy of its
// passphrase (the owner's signature checked), and its name, description and
// events through its key, which stays in WASM. The calendars the account
// holds are the account head's `calendars` scope: the list read is checked
// against the verified head, and every change of one carries the next head.

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { isAxiosError } from 'axios'
import {
  createCalendar as makeCalendar,
  localToUtc,
  sealCalendarEvent,
  sealCalendarMetadata,
  unlockCalendar,
  type CalendarTime,
  type EventFields,
  type SealedEvent,
  type SealedMetadata,
  type SealedPassphrase,
  type UnlockedCalendar,
} from '@kutup/crypto/calendar'
import type { SealedMailKey } from '@kutup/crypto/mailKey'
import { OlderThanSeenError, revisionGuard } from '@kutup/crypto/revisionGuard'
import { useMailAccount, type MailAccount } from '@kutup/mail-core/api'
import { accountHead, HeadBlockedError, NotInVerifiedIndexError, type ListedEdit, type VerifiedIndex } from '@kutup/session/accountHead'
import api from '@kutup/session/client'
import { useRequiredSession, type Session } from '@kutup/session/store'

/** The account head's scope of the calendars the account holds. */
const HEAD_SCOPE = 'calendars'
/** This browser's revision guard scope: the highest revision of each calendar seen here. */
const GUARD_SCOPE = 'calendar'
/**
 * What the guard remembers of a deleted calendar: higher than any revision,
 * so a server bringing it back is refused. Calendar ids are drawn fresh
 * (UUID v4), never reused.
 */
const DELETED = Number.MAX_SAFE_INTEGER
/**
 * The most pages one window's events are read in, against a server that
 * never ends a listing: far above what the largest calendar a server allows
 * (`calendarEventsPerCalendar`) needs at the smallest page it allows.
 */
const MAX_EVENT_PAGES = 1000

/** Proton's permission bits (`CALENDAR_PERMISSIONS`). */
export const PERMISSION = { superOwner: 1, owner: 2, write: 16, read: 32 } as const

/**
 * A reminder (Proton's notification): on this member's devices or by email,
 * `trigger` an RFC 5545 duration from the start (`-PT15M`; all-day `PT9H` is
 * 09:00 that day). Readable by the server, which keeps and fires the alarms.
 */
export interface Reminder {
  type: 'device' | 'email'
  trigger: string
}

/** A member's default reminders for a calendar's timed and all-day events. */
export interface DefaultReminders {
  timed: Reminder[]
  allDay: Reminder[]
}

/** A calendar as the server lists it for its member. */
export interface CalendarRow {
  id: string
  ownerAddress: string
  publicKey: string
  fingerprint: string
  lockedSecretKey: string
  passphrase: SealedPassphrase
  addressId: string
  metadata: SealedMetadata
  permissions: number
  color: string
  display: boolean
  /** This member's defaults (Proton's DefaultPartDayNotifications and DefaultFullDayNotifications). */
  defaultReminders: DefaultReminders
  revision: number
  createdAt: string
  updatedAt: string
}

/** A calendar, opened. */
export interface Calendar {
  id: string
  name: string
  description: string
  color: string
  display: boolean
  permissions: number
  revision: number
  defaultReminders: DefaultReminders
  unlocked: UnlockedCalendar
}

/** An event as the server stores it. */
export interface EventRow {
  id: string
  calendarId: string
  uid: string
  authorAddress: string | null
  event: SealedEvent
  startUtc: string
  endUtc: string
  fullDay: boolean
  /** A repeating event's last end as the server expanded it; null for one without end. */
  rangeEndUtc: string | null
  sequence: number
  /** Starts at 1; each update adds one, and names the one it was made from. */
  revision: number
  modifiedAt: string
  /** The caller's own reminders for it; null: the calendar's defaults. */
  reminders: Reminder[] | null
}

/** An event, opened. */
export interface CalendarEvent {
  id: string
  calendarId: string
  fields: EventFields
  startUtc: string
  endUtc: string
  fullDay: boolean
  /** The stored revision, which a change of it names as its base. */
  revision: number
  /** This member's own reminders; null: the calendar's defaults. */
  reminders: Reminder[] | null
  /**
   * Its author signed every part, and the times the server read are the
   * ones signed. An event that isn't is shown as such, never trusted.
   */
  verified: boolean
}

export const calendarsKey = ['calendar', 'calendars'] as const

/** Calendars unlocked in this tab, by id and key: WASM objects, kept, never cloned. */
const unlocked = new Map<string, Promise<UnlockedCalendar>>()

/** The keys a member's own copy of a passphrase may be to: the address's primary first. */
function ownKeys(account: MailAccount): SealedMailKey[] {
  return [account.key, ...account.olderKeys]
}

async function unlock(account: MailAccount, row: CalendarRow): Promise<UnlockedCalendar> {
  const cacheKey = `${row.id}/${row.fingerprint}/${row.passphrase.keyPacket}`
  let found = unlocked.get(cacheKey)
  if (!found) {
    found = (async () => {
      if (!account.isOwnAddress(row.ownerAddress)) {
        // Shared calendars come in E3, with their owners' verified keys.
        throw new Error('a calendar of another account')
      }
      let last: unknown = null
      for (const key of ownKeys(account)) {
        let opened: UnlockedCalendar
        try {
          opened = await unlockCalendar(key, row.passphrase, account.ownPublicKeys, row.lockedSecretKey)
        } catch (error) {
          last = error
          continue
        }
        // The key unlocked is the one listed, or the listing is not the calendar's.
        if (opened.fingerprint !== row.fingerprint.toLowerCase()) {
          opened.free()
          throw new Error('the calendar key is not the one listed')
        }
        return opened
      }
      throw last instanceof Error ? last : new Error('no key opens this calendar')
    })()
    found.catch(() => unlocked.delete(cacheKey))
    unlocked.set(cacheKey, found)
  }
  return found
}

async function calendarsIndex(session: Session): Promise<VerifiedIndex | null> {
  try {
    return await (await accountHead(session)).verifiedIndex(HEAD_SCOPE)
  } catch (error) {
    if (error instanceof HeadBlockedError) return null
    throw error
  }
}

async function listed<T>(session: Session, edit: (index: VerifiedIndex) => Promise<ListedEdit<T> | null>): Promise<T | undefined> {
  return (await accountHead(session)).listedWrite(HEAD_SCOPE, edit)
}

/**
 * The account's calendars, opened. The list and the head's index are two
 * reads: a write landing between them is read again once before the list
 * counts as one the head does not vouch for (then nothing of it is shown).
 * Every calendar is also held to this browser's revision guard, which is
 * all that holds it while the app is blocked: a calendar rolled back, or
 * brought back after this browser saw it deleted, refuses the list as the
 * head would.
 */
export async function loadCalendars(session: Session, account: MailAccount): Promise<{ calendars: Calendar[]; unreadable: number }> {
  for (let attempt = 0; ; attempt++) {
    const index = await calendarsIndex(session)
    const { data } = await api.get<{ calendars: CalendarRow[] }>('/calendar/calendars')
    try {
      if (index) {
        index.expectListing(data.calendars.map((row) => row.id))
        for (const row of data.calendars) index.expect(row.id, row.revision)
      }
      let unreadable = 0
      const calendars: Calendar[] = []
      for (const row of data.calendars) {
        try {
          const key = await unlock(account, row)
          // The id the metadata must name is the one the verified head lists
          // (`expectListing` and `expect` above refuse any other listing).
          const metadata = key.openMetadata(row.metadata, row.id, account.ownPublicKeys)
          // A name its owner didn't sign is never shown: the calendar counts
          // as unreadable.
          if (!metadata.verified) throw new Error('the calendar name is not signed by its owner')
          await revisionGuard(session).accept(GUARD_SCOPE, row.id, row.revision)
          calendars.push({
            id: row.id,
            name: metadata.name,
            description: metadata.description,
            color: row.color,
            display: row.display,
            permissions: row.permissions,
            revision: row.revision,
            defaultReminders: row.defaultReminders,
            unlocked: key,
          })
        } catch (error) {
          if (error instanceof OlderThanSeenError) throw error
          unreadable++
        }
      }
      return { calendars, unreadable }
    } catch (error) {
      const refused = error instanceof NotInVerifiedIndexError || error instanceof OlderThanSeenError
      if (!refused || attempt > 0) throw error
    }
  }
}

/** The account's mail address and its row id: what a calendar's passphrase and events are bound to. */
export async function activeAddressId(account: MailAccount): Promise<string> {
  const { data } = await api.get<{ id: string; address: string; state: string }[]>('/mail/addresses')
  const row = data.find((address) => address.state === 'active' && account.isOwnAddress(address.address))
  if (!row) throw new Error('the account has no active mail address')
  return row.id
}

/** Every calendar's colour on the server's palette (`#rrggbb`), Proton's accents first. */
export const CALENDAR_COLORS = ['#8080ff', '#db60d6', '#415df0', '#179fd9', '#1da583', '#3cbb3a', '#b4a40e', '#936d58', '#f78400', '#ec3e7c'] as const

/** Makes a calendar under a fresh id; the head that lists it is made before the create. */
export async function createCalendar(session: Session, account: MailAccount, name: string, color: string): Promise<string> {
  const id = crypto.randomUUID()
  const addressId = await activeAddressId(account)
  const made = await makeCalendar(account.key, id, { name, description: '' })
  // The fingerprint is the server's to read from the key, not to be told.
  const body = { publicKey: made.publicKey, lockedSecretKey: made.lockedSecretKey, passphrase: made.passphrase, metadata: made.metadata }
  await listed(session, (index) =>
    Promise.resolve(
      index.revision(id) !== undefined
        ? null
        : {
            changes: [[id, 1]] as const,
            send: async (head: string) => {
              await api.post('/calendar/calendars', { id, addressId, ...body, color, head })
            },
          },
    ),
  )
  await revisionGuard(session).accept(GUARD_SCOPE, id, 1)
  return id
}

/** Another device changed the calendar first: read it again. */
export class CalendarChangedError extends Error {
  constructor() {
    super('the calendar changed on another device')
    this.name = 'CalendarChangedError'
  }
}

export interface CalendarChange {
  name?: string
  description?: string
  color?: string
  display?: boolean
  /** This member's defaults (Proton's event defaults). */
  defaultReminders?: DefaultReminders
}

/** Changes a calendar: the owner's name and description, the member's colour and visibility. */
export async function updateCalendar(session: Session, account: MailAccount, calendar: Calendar, change: CalendarChange): Promise<void> {
  const renamed = change.name !== undefined || change.description !== undefined
  const metadata = renamed
    ? sealCalendarMetadata(calendar.unlocked, account.key, calendar.id, {
        name: change.name ?? calendar.name,
        description: change.description ?? calendar.description,
      })
    : undefined
  const revision = calendar.revision + 1
  try {
    await listed(session, (index) => {
      const listedRevision = index.revision(calendar.id)
      if (listedRevision === revision) return Promise.resolve(null)
      if (listedRevision !== undefined && listedRevision !== calendar.revision) throw new CalendarChangedError()
      return Promise.resolve({
        changes: [[calendar.id, revision]] as const,
        send: async (head: string) => {
          await api.put(`/calendar/calendars/${calendar.id}`, {
            metadata,
            color: change.color,
            display: change.display,
            defaultReminders: change.defaultReminders,
            baseRevision: calendar.revision,
            revision,
            head,
          })
        },
      })
    })
  } catch (error) {
    if (isAxiosError(error) && (error.response?.data as { code?: string } | undefined)?.code === 'revision_conflict') throw new CalendarChangedError()
    throw error
  }
  await revisionGuard(session).accept(GUARD_SCOPE, calendar.id, revision)
}

/** Deletes a calendar and its events (owner only). */
export async function deleteCalendar(session: Session, calendar: Calendar): Promise<void> {
  await listed(session, (index) =>
    Promise.resolve(
      index.revision(calendar.id) === undefined
        ? null
        : {
            changes: [[calendar.id, null]] as const,
            send: async (head: string) => {
              await api.delete(`/calendar/calendars/${calendar.id}`, { data: { head } })
            },
          },
    ),
  )
  await revisionGuard(session).accept(GUARD_SCOPE, calendar.id, DELETED)
}

/** The instant a time names, as the server converts it (the same time zone database). */
export async function instantOf(time: CalendarTime): Promise<string> {
  if ('date' in time) return `${time.date}T00:00:00Z`
  if ('utc' in time) return time.utc
  return localToUtc(time.zoned.local, time.zoned.tzid)
}

function sameInstant(a: string, b: string): boolean {
  return Date.parse(a) === Date.parse(b)
}

/** The day after an all-day `date` (`yyyy-MM-dd`). */
function nextDay(date: string): string {
  const day = new Date(`${date}T00:00:00Z`)
  day.setUTCDate(day.getUTCDate() + 1)
  return day.toISOString().slice(0, 10)
}

/**
 * An event's times from its signed fields, as the server reads them: a
 * missing end is RFC 5545's (a date lasts one day, a time has no length).
 */
export async function timesOf(fields: EventFields): Promise<{ startUtc: string; endUtc: string; fullDay: boolean }> {
  const startUtc = await instantOf(fields.start)
  const fullDay = 'date' in fields.start
  const end = fields.end ?? ('date' in fields.start ? { date: nextDay(fields.start.date) } : fields.start)
  return { startUtc, endUtc: await instantOf(end), fullDay }
}

/**
 * Opens an event with its calendar's key and checks it: every part signed by
 * the author (one of the account's addresses in E1). Its times are drawn
 * from the signed fields only; the server's are compared, and an event whose
 * server times differ is shown as unverified.
 */
export async function openEvent(account: MailAccount, calendar: Calendar, row: EventRow): Promise<CalendarEvent> {
  const opened = calendar.unlocked.openEvent(row.event, account.ownPublicKeys)
  const times = await timesOf(opened.fields)
  const ownAuthor = row.authorAddress !== null && account.isOwnAddress(row.authorAddress)
  const asServed = sameInstant(times.startUtc, row.startUtc) && sameInstant(times.endUtc, row.endUtc) && times.fullDay === row.fullDay
  return {
    id: row.id,
    calendarId: row.calendarId,
    fields: opened.fields,
    ...times,
    revision: row.revision,
    reminders: row.reminders ?? null,
    verified: opened.verified && ownAuthor && asServed,
  }
}

/** One event of `calendar`, opened (a reminder's, to name it). */
export async function loadEvent(account: MailAccount, calendar: Calendar, eventId: string): Promise<CalendarEvent> {
  const { data } = await api.get<EventRow>(`/calendar/calendars/${calendar.id}/events/${eventId}`)
  return openEvent(account, calendar, data)
}

/** Where the next page of events starts. */
interface EventCursor {
  afterStart: string
  afterId: string
}

/** `next` comes after `previous` in the (start, id) order pages follow. */
function cursorAfter(next: EventCursor, previous: EventCursor): boolean {
  const a = Date.parse(next.afterStart)
  const b = Date.parse(previous.afterStart)
  return a > b || (a === b && next.afterId > previous.afterId)
}

/** The events of `calendar` that meet [start, end), every page, opened (unreadable ones counted). */
export async function loadEvents(
  account: MailAccount,
  calendar: Calendar,
  start: string,
  end: string,
): Promise<{ events: CalendarEvent[]; unreadable: number }> {
  const events: CalendarEvent[] = []
  let unreadable = 0
  // The cursor is the last event's (start, id), the client's to hold; a
  // server's next cursor must move forward, and a window ends within
  // MAX_EVENT_PAGES pages.
  for (let after: EventCursor | null = null, pages = 1; ; pages++) {
    const response: { data: { events: EventRow[]; next: EventCursor | null } } = await api.get(`/calendar/calendars/${calendar.id}/events`, {
      params: { start, end, ...after },
    })
    const data = response.data
    for (const row of data.events) {
      try {
        events.push(await openEvent(account, calendar, row))
      } catch {
        unreadable++
      }
    }
    if (!data.next) break
    if (pages >= MAX_EVENT_PAGES) throw new Error('the server never ends this listing')
    if (after && !cursorAfter(data.next, after)) throw new Error('the server repeats a page')
    after = data.next
  }
  return { events, unreadable }
}

/**
 * One change refused by an events sync, with its code (`uidTaken`,
 * `eventLimit`, `revision_conflict` when another device saved first,
 * `sequenceBehind`…).
 */
export class EventRefusedError extends Error {
  constructor(
    readonly status: number,
    readonly code: string | null,
  ) {
    super(`the event was refused (${code ?? status})`)
    this.name = 'EventRefusedError'
  }
}

interface SyncResult {
  status: number
  event: EventRow | null
  code: string | null
}

async function syncOne(calendar: Calendar, addressId: string, change: unknown): Promise<EventRow | null> {
  const { data } = await api.post<{ results: SyncResult[] }>(`/calendar/calendars/${calendar.id}/events/sync`, {
    addressId,
    changes: [change],
  })
  const result = data.results[0]
  if (!result || result.status !== 200) throw new EventRefusedError(result?.status ?? 0, result?.code ?? null)
  return result.event
}

/**
 * The account head, verified, before an event write: a blocked app writes
 * nothing (the banner says why), as listed writes refuse.
 */
async function beforeEventWrite(session: Session): Promise<void> {
  await (await accountHead(session)).verifiedHead()
}

/**
 * Saves an event's fields to `calendar`: a new event, or `existing` (as
 * opened) changed. `reminders`: this member's own (a list), the calendar's
 * defaults (`null`), or, left out, as they are (a new event: the defaults).
 */
export async function saveEvent(
  session: Session,
  account: MailAccount,
  calendar: Calendar,
  fields: EventFields,
  existing?: Pick<CalendarEvent, 'id' | 'revision'>,
  reminders?: Reminder[] | null,
): Promise<string> {
  await beforeEventWrite(session)
  const addressId = await activeAddressId(account)
  const event = sealCalendarEvent(calendar.unlocked, account.key, fields)
  const stored = await syncOne(
    calendar,
    addressId,
    // A new event's id is drawn here, so a create sent again is the stored one, never a second.
    existing
      ? { update: { id: existing.id, baseRevision: existing.revision, event, ...(reminders !== undefined ? { reminders } : {}) } }
      : { create: { id: crypto.randomUUID(), event, ...(reminders ? { reminders } : {}) } },
  )
  return stored?.id ?? existing?.id ?? ''
}

/** Deletes `existing` (as opened): refused when another device changed it since. */
export async function deleteEvent(
  session: Session,
  account: MailAccount,
  calendar: Calendar,
  existing: Pick<CalendarEvent, 'id' | 'revision'>,
): Promise<void> {
  await beforeEventWrite(session)
  const addressId = await activeAddressId(account)
  await syncOne(calendar, addressId, { delete: { id: existing.id, baseRevision: existing.revision } })
}

/** One of the caller's alarms (`GET /api/calendar/alarms`). */
export interface Alarm {
  calendarId: string
  eventId: string
  action: 'device' | 'email'
  /** The occurrence it is for, and when it fires (RFC 3339). */
  occurrenceStart: string
  fireAt: string
}

/** The most pages one alarms window is read in (a server that never ends a listing). */
const MAX_ALARM_PAGES = 100

/** The caller's alarms firing in [start, end), every page, by fire time. */
export async function loadAlarms(start: string, end: string): Promise<Alarm[]> {
  const alarms: Alarm[] = []
  let after: { afterFire: string; afterEvent: string } | null = null
  for (let pages = 1; ; pages++) {
    const response: { data: { alarms: Alarm[] } } = await api.get('/calendar/alarms', { params: { start, end, ...after } })
    const page = response.data.alarms
    alarms.push(...page)
    // Pages go on after the last one's last alarm until one is empty (the
    // page size is the server's setting); each must move forward.
    const last = page.at(-1)
    if (!last) break
    const next = { afterFire: last.fireAt, afterEvent: last.eventId }
    const forward = !after || Date.parse(next.afterFire) > Date.parse(after.afterFire) || (next.afterFire === after.afterFire && next.afterEvent > after.afterEvent)
    if (!forward) throw new Error('the server repeats a page')
    if (pages >= MAX_ALARM_PAGES) throw new Error('the server never ends this listing')
    after = next
  }
  return alarms
}

/** The account's calendar zone (all-day reminders fire in it); null: UTC. */
export async function loadCalendarZone(): Promise<string | null> {
  const { data } = await api.get<{ zone: string | null }>('/calendar/settings')
  return data.zone
}

export async function saveCalendarZone(zone: string | null): Promise<void> {
  await api.put('/calendar/settings', { zone })
}

/** This browser takes reminder pushes (its `PushSubscription`'s endpoint and keys, base64url). */
export async function savePushSubscription(subscription: { endpoint: string; p256dh: string; auth: string }): Promise<void> {
  await api.put('/calendar/push-subscription', subscription)
}

export async function deletePushSubscription(): Promise<void> {
  await api.delete('/calendar/push-subscription')
}

// ----- hooks -----

/** The account's calendars, opened (needs the account's mail keys). */
export function useCalendars() {
  const session = useRequiredSession()
  const account = useMailAccount()
  return useQuery({
    queryKey: [...calendarsKey, session.sessionId],
    enabled: !!account.data,
    // WASM handles inside: compared by identity, never copied.
    structuralSharing: false,
    queryFn: () => loadCalendars(session, account.data!),
  })
}

/** The shown calendars' events in [start, end). */
export function useEvents(calendars: Calendar[] | undefined, start: string, end: string) {
  const account = useMailAccount()
  const shown = (calendars ?? []).filter((calendar) => calendar.display)
  return useQuery({
    queryKey: ['calendar', 'events', start, end, shown.map((calendar) => `${calendar.id}:${calendar.revision}`).join(',')],
    enabled: !!account.data && calendars !== undefined,
    queryFn: async () => {
      const all = await Promise.all(shown.map((calendar) => loadEvents(account.data!, calendar, start, end)))
      return {
        events: all.flatMap((result) => result.events),
        unreadable: all.reduce((sum, result) => sum + result.unreadable, 0),
      }
    },
  })
}

/** Invalidates what a change touched. */
export function useCalendarMutation<T, V>(fn: (variables: V) => Promise<T>) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: fn,
    onSettled: async () => {
      await queryClient.invalidateQueries({ queryKey: ['calendar'] })
    },
  })
}
