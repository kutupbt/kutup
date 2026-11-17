// Calendars and events (docs/plans/calendar.md, E1) as the Calendar app
// reads and writes them. Every calendar opens from the member's share of its
// passphrase on the account's own keys (the owner's account signature
// checked; docs/plans/wipe-unification.md, W4), and its name, description
// and events through its key, which stays in WASM. The member's own colour
// and display flag are a record of the account's `calendarSettings` scope
// (docs/plans/account-records.md), sealed and filed under a keyed hash of the
// calendar id, read with the verified head: a calendar listed without its
// record is not one the head vouches for. The record is written before the
// calendar is created, and removed after it is deleted.

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  calendarEventKeyId,
  createCalendar as makeCalendar,
  localToUtc,
  sealCalendarEvent,
  sealCalendarMetadata,
  unlockCalendar,
  unlockSharedCalendar,
  type CalendarOwner,
  type CalendarTime,
  type EventFields,
  type SealedEvent,
  type CalendarAccount,
  type SealedMetadata,
  type UnlockedCalendar,
} from '@kutup/crypto/calendar'
import { OlderThanSeenError, revisionGuard } from '@kutup/crypto/revisionGuard'
import { useMailAccount, type MailAccount } from '@kutup/mail-core/api'
import { addressKeys } from '@kutup/mail-core/keys'
import { openScopeRecord, scopeRecordId, sealScopeRecord, type CalendarSettingsRecord } from '@kutup/crypto/scopeRecords'
import { accountHead, HeadBlockedError } from '@kutup/session/accountHead'
import api from '@kutup/session/client'
import { ownAccount } from '@kutup/session/devices'
import { useRequiredSession, type Session } from '@kutup/session/store'

/** The account-records scope of the member's own calendar settings. */
const SETTINGS_SCOPE = 'calendarSettings'
/** This browser's revision guard scope: the highest settings revision of each calendar seen here. */
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
export const PERMISSION = { superOwner: 1, owner: 2, write: 16, read: 32, availability: 64 } as const

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
  /** The owner's account id (on this server): who shared the passphrase. */
  ownerId: string
  publicKey: string
  fingerprint: string
  lockedSecretKey: string
  /** The calendar key's generation, which the share names. */
  keyGeneration: number
  /** This member's share of the passphrase, on its account key. */
  passphraseShare: string
  metadata: SealedMetadata
  permissions: number
  /** This member's defaults (Proton's DefaultPartDayNotifications and DefaultFullDayNotifications). */
  defaultReminders: DefaultReminders
  createdAt: string
  updatedAt: string
  /**
   * A calendar someone else owns (docs/plans/calendar-e3.md §1): who, as the
   * server says; the member checks it against its pins before trusting it.
   */
  owner?: CalendarOwnerRow
  /**
   * Every live key generation with this member's share of it, oldest first
   * (§2): older events open with their own generation's key. Without it the
   * row's own key is the only one.
   */
  keys?: CalendarKeyRow[]
}

/** A calendar's owner as the server lists them to a member. */
export interface CalendarOwnerRow {
  accountId: string
  /** Their current address, which the pins and their address keys are looked up by. */
  address: string
  incarnationId: string
  /** Their account signing key (base64), which signed the member's shares. */
  signingPublicKey: string
}

/** One key generation of a calendar, with the caller's share of its passphrase. */
export interface CalendarKeyRow {
  keyGeneration: number
  publicKey: string
  fingerprint: string
  lockedSecretKey: string
  passphraseShare: string
}

/** A calendar, opened. */
export interface Calendar {
  id: string
  name: string
  description: string
  color: string
  display: boolean
  permissions: number
  /** The settings record's revision (0 while the app is blocked and can't read it). */
  revision: number
  /** The settings record's id: a keyed hash of the calendar id. */
  settingsId: string
  /** The settings' version and a newer client's fields, sealed again on a change. */
  settingsRest?: Record<string, unknown>
  defaultReminders: DefaultReminders
  unlocked: UnlockedCalendar
  /** Every generation's unlocked key by its key ID: an event opens with the one its key packets name. */
  keyring: Map<string, UnlockedCalendar>
  /** The newest key generation (`unlocked`'s). */
  keyGeneration: number
  /** The account owns it (else it is shared with it, and `owner` says by whom). */
  owned: boolean
  owner?: CalendarOwnerRow
  /** The sealed metadata's version and a newer client's fields, sealed again on a rename. */
  metadataRest?: Record<string, unknown>
}

/**
 * Checks a shared calendar's owner against this account's identity pins
 * (Drive's: docs/plans/drive-identity-pins.md) and answers their verified
 * keys; the app installs it ({@link setOwnerCheck}), since the pins live in
 * Drive's package. A changed identity throws {@link OwnerIdentityChanged}.
 */
export type OwnerCheck = (session: Session, owner: CalendarOwnerRow) => Promise<CalendarOwner>

let ownerCheck: OwnerCheck | null = null

/** Installs the owner check shared calendars open through. */
export function setOwnerCheck(check: OwnerCheck): void {
  ownerCheck = check
}

/** A shared calendar's owner no longer matches the identity this account pinned: shown, not opened, until confirmed. */
export class OwnerIdentityChanged extends Error {
  constructor(
    readonly calendarId: string,
    readonly ownerAddress: string,
  ) {
    super(`the identity of ${ownerAddress} changed`)
    this.name = 'OwnerIdentityChanged'
  }
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

/** The signed-in account as its calendars' shares name it. */
async function calendarAccount(session: Session): Promise<CalendarAccount> {
  return { identityRoot: session.roots.identityRoot, account: await ownAccount(session) }
}

/** One generation's key, unlocked from this member's share (the owner's account signature checked). */
async function unlockOne(session: Session, calendarId: string, key: CalendarKeyRow, owner: CalendarOwner | null): Promise<UnlockedCalendar> {
  const cacheKey = `${calendarId}/${key.fingerprint}/${key.keyGeneration}/${key.passphraseShare}`
  let found = unlocked.get(cacheKey)
  if (!found) {
    found = (async () => {
      const lock = { calendarId, keyGeneration: key.keyGeneration, passphraseShare: key.passphraseShare, lockedSecretKey: key.lockedSecretKey }
      const member = await calendarAccount(session)
      const opened = owner ? await unlockSharedCalendar(member, owner, lock) : await unlockCalendar(member, lock)
      // The key unlocked is the one listed, or the listing is not the calendar's.
      if (opened.fingerprint !== key.fingerprint.toLowerCase()) {
        opened.free()
        throw new Error('the calendar key is not the one listed')
      }
      return opened
    })()
    found.catch(() => unlocked.delete(cacheKey))
    unlocked.set(cacheKey, found)
  }
  return found
}

/** A calendar's keys, newest last, every one unlocked: the row's own when it lists no generations. */
async function unlock(session: Session, row: CalendarRow): Promise<{ newest: UnlockedCalendar; generation: number; keyring: Map<string, UnlockedCalendar> }> {
  const owned = row.ownerId === session.userId
  let owner: CalendarOwner | null = null
  if (!owned) {
    if (!row.owner || row.owner.accountId !== row.ownerId) throw new Error('a shared calendar without its owner')
    if (!ownerCheck) throw new Error('shared calendars need the owner check')
    owner = await ownerCheck(session, row.owner)
  }
  const keys = row.keys?.length
    ? [...row.keys].sort((a, b) => a.keyGeneration - b.keyGeneration)
    : [{ keyGeneration: row.keyGeneration, publicKey: row.publicKey, fingerprint: row.fingerprint, lockedSecretKey: row.lockedSecretKey, passphraseShare: row.passphraseShare }]
  const opened = await Promise.all(keys.map((key) => unlockOne(session, row.id, key, owner)))
  const keyring = new Map(opened.map((key) => [key.keyId, key]))
  return { newest: opened[opened.length - 1], generation: keys[keys.length - 1].keyGeneration, keyring }
}

/** The keys an author's signature may be under: the account's own, or their address's checked keys. */
async function authorKeys(account: MailAccount, address: string | null, owner?: CalendarOwnerRow): Promise<string[]> {
  if (address === null) return []
  if (account.isOwnAddress(address)) return account.ownPublicKeys
  const keys = await addressKeys(address)
  // A shared calendar's name is its owner's: their address, their account.
  if (owner && keys.accountRef?.accountId !== owner.accountId) return []
  return keys.all
}

/** The settings record id of a calendar (its 16 UUID bytes, hashed under the object-id key). */
async function settingsId(session: Session, calendarId: string): Promise<string> {
  const hex = calendarId.replace(/-/g, '')
  const bytes = new Uint8Array(16)
  for (let i = 0; i < 16; i++) bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  return scopeRecordId(session.roots.objectIdKey, SETTINGS_SCOPE, bytes)
}

interface OpenedSettings {
  revision: number
  value: CalendarSettingsRecord
}

/**
 * The account's calendar settings, by record id, read with the verified
 * head; null while the app is blocked on another history (reads go on,
 * held to this browser's guard, and the banner says why). A record this
 * device can't open counts as missing.
 */
async function loadSettings(session: Session): Promise<Map<string, OpenedSettings | null> | null> {
  let copy
  try {
    copy = await (await accountHead(session)).records(SETTINGS_SCOPE)
  } catch (error) {
    if (error instanceof HeadBlockedError) return null
    throw error
  }
  const settings = new Map<string, OpenedSettings | null>()
  for (const [id, stored] of copy.records) {
    try {
      const opened = await openScopeRecord<CalendarSettingsRecord>(session.masterKeys, session.envelopeBinding, SETTINGS_SCOPE, id, stored.envelope)
      settings.set(id, opened.revision === stored.revision ? opened : null)
    } catch {
      settings.set(id, null)
    }
  }
  return settings
}

/** What a settings record holds beyond the fields edited here. */
function settingsRest(value: CalendarSettingsRecord): Record<string, unknown> {
  return Object.fromEntries(Object.entries(value).filter(([key]) => key !== 'color' && key !== 'display'))
}

/** A colour from the palette, by the calendar id: what a calendar shows while its settings can't be read. */
function fallbackColor(calendarId: string): string {
  let sum = 0
  for (const char of calendarId) sum += char.charCodeAt(0)
  return CALENDAR_COLORS[sum % CALENDAR_COLORS.length]
}

/**
 * The account's calendars, opened. A calendar shows only with its settings
 * record from the verified head; one without it (rolled back, or brought
 * back after its record was removed) counts as unreadable. Every calendar is
 * also held to this browser's revision guard, which is all that holds it
 * while the app is blocked: a calendar this browser saw deleted is refused,
 * as the head would.
 */
export async function loadCalendars(
  session: Session,
  account: MailAccount,
): Promise<{ calendars: Calendar[]; unreadable: number; ownerChanged: OwnerIdentityChanged[] }> {
  const settings = await loadSettings(session)
  const { data } = await api.get<{ calendars: CalendarRow[] }>('/calendar/calendars')
  const guard = revisionGuard(session)
  let unreadable = 0
  const ownerChanged: OwnerIdentityChanged[] = []
  const calendars: Calendar[] = []
  for (const row of data.calendars) {
    try {
      const id = await settingsId(session, row.id)
      const own = settings?.get(id)
      if (settings && !own) throw new Error('the calendar has no settings the head vouches for')
      if (own) await guard.accept(GUARD_SCOPE, row.id, own.revision)
      else if ((await guard.seen(GUARD_SCOPE, row.id)) === DELETED) throw new OlderThanSeenError(GUARD_SCOPE, 0, DELETED)
      const keys = await unlock(session, row)
      const owned = row.ownerId === session.userId
      const signers = owned ? account.ownPublicKeys : await authorKeys(account, row.owner!.address, row.owner)
      const metadata = keys.newest.openMetadata(row.metadata, row.id, signers)
      // A name its owner didn't sign is never shown: the calendar counts
      // as unreadable.
      if (!metadata.verified) throw new Error('the calendar name is not signed by its owner')
      calendars.push({
        id: row.id,
        name: metadata.name,
        description: metadata.description,
        color: own?.value.color ?? fallbackColor(row.id),
        display: own?.value.display ?? true,
        permissions: row.permissions,
        revision: own?.revision ?? 0,
        settingsId: id,
        settingsRest: own ? settingsRest(own.value) : undefined,
        defaultReminders: row.defaultReminders,
        unlocked: keys.newest,
        keyring: keys.keyring,
        keyGeneration: keys.generation,
        owned,
        owner: owned ? undefined : row.owner,
        metadataRest: metadata.rest,
      })
    } catch (error) {
      if (error instanceof OlderThanSeenError) throw error
      if (error instanceof OwnerIdentityChanged) ownerChanged.push(new OwnerIdentityChanged(row.id, error.ownerAddress))
      else unreadable++
    }
  }
  return { calendars, unreadable, ownerChanged }
}

/** Writes a calendar's settings record at the next revision (a newer client's fields kept). */
async function writeSettings(session: Session, id: string, value: CalendarSettingsRecord, from?: number): Promise<number> {
  const written = await (await accountHead(session)).recordsWrite(SETTINGS_SCOPE, async (copy) => {
    const stored = copy.records.get(id)
    if (from !== undefined && stored?.revision !== from) throw new CalendarChangedError()
    const revision = (stored?.revision ?? 0) + 1
    const envelope = await sealScopeRecord(session.masterKeys, session.envelopeBinding, SETTINGS_SCOPE, id, revision, value)
    return { puts: [{ id, revision, envelope }], deletes: [], done: revision }
  })
  return written ?? 0
}

/**
 * Files the member's own settings record for a calendar shared with it,
 * before the invitation is accepted (a calendar listed without its record is
 * not one the head vouches for). Answers the record id, to remove it again
 * when the accept fails.
 */
export async function fileSharedCalendarSettings(session: Session, calendarId: string, color: string): Promise<string> {
  const id = await settingsId(session, calendarId)
  const revision = await writeSettings(session, id, { color, display: true })
  await revisionGuard(session).accept(GUARD_SCOPE, calendarId, revision)
  return id
}

/** Drops the member's settings record of a calendar it left (or never joined). */
export async function forgetCalendarSettings(session: Session, calendarId: string, deleted = false): Promise<void> {
  const id = await settingsId(session, calendarId)
  if (deleted) await revisionGuard(session).accept(GUARD_SCOPE, calendarId, DELETED)
  await removeSettings(session, id)
}

/** Removes a calendar's settings record, if there is one. */
async function removeSettings(session: Session, id: string): Promise<void> {
  await (await accountHead(session)).recordsWrite(SETTINGS_SCOPE, (copy) =>
    Promise.resolve(copy.records.has(id) ? { puts: [], deletes: [id], done: undefined } : null),
  )
}

/** The account's mail address and its row id: the address whose key signs its events. */
export async function activeAddressId(account: MailAccount): Promise<string> {
  const { data } = await api.get<{ id: string; address: string; state: string }[]>('/mail/addresses')
  const row = data.find((address) => address.state === 'active' && account.isOwnAddress(address.address))
  if (!row) throw new Error('the account has no active mail address')
  return row.id
}

/** Every calendar's colour on the server's palette (`#rrggbb`), Proton's accents first. */
export const CALENDAR_COLORS = ['#8080ff', '#db60d6', '#415df0', '#179fd9', '#1da583', '#3cbb3a', '#b4a40e', '#936d58', '#f78400', '#ec3e7c'] as const

/** Makes a calendar under a fresh id; its settings record is written before the create. */
export async function createCalendar(session: Session, account: MailAccount, name: string, color: string): Promise<string> {
  const id = crypto.randomUUID()
  const made = await makeCalendar(await calendarAccount(session), account.key, id, { name, description: '' })
  // The fingerprint is the server's to read from the key, not to be told.
  const body = { publicKey: made.publicKey, lockedSecretKey: made.lockedSecretKey, passphraseShare: made.passphraseShare, metadata: made.metadata }
  const record = await settingsId(session, id)
  const revision = await writeSettings(session, record, { color, display: true })
  try {
    await api.post('/calendar/calendars', { id, ...body })
  } catch (error) {
    // No calendar: its record goes too (one left behind is never shown).
    await removeSettings(session, record).catch(() => undefined)
    throw error
  }
  await revisionGuard(session).accept(GUARD_SCOPE, id, revision)
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

/**
 * Changes a calendar: the owner's name and description and the member's
 * default reminders on the server, the member's colour and visibility in its
 * settings record (refused with {@link CalendarChangedError} when another
 * device changed them first).
 */
export async function updateCalendar(session: Session, account: MailAccount, calendar: Calendar, change: CalendarChange): Promise<void> {
  const renamed = change.name !== undefined || change.description !== undefined
  const metadata = renamed
    ? sealCalendarMetadata(calendar.unlocked, account.key, calendar.id, {
        name: change.name ?? calendar.name,
        description: change.description ?? calendar.description,
        rest: calendar.metadataRest,
      })
    : undefined
  if (change.color !== undefined || change.display !== undefined) {
    const revision = await writeSettings(
      session,
      calendar.settingsId,
      { ...calendar.settingsRest, color: change.color ?? calendar.color, display: change.display ?? calendar.display },
      calendar.revision,
    )
    await revisionGuard(session).accept(GUARD_SCOPE, calendar.id, revision)
  }
  if (metadata || change.defaultReminders) {
    await api.put(`/calendar/calendars/${calendar.id}`, { metadata, defaultReminders: change.defaultReminders })
  }
}

/** Deletes a calendar and its events (owner only), then its settings record. */
export async function deleteCalendar(session: Session, calendar: Calendar): Promise<void> {
  await api.delete(`/calendar/calendars/${calendar.id}`)
  await revisionGuard(session).accept(GUARD_SCOPE, calendar.id, DELETED)
  await removeSettings(session, calendar.settingsId)
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
  // The generation its key packets name: older events keep their own key.
  const key = calendar.keyring.get(await calendarEventKeyId(row.event)) ?? calendar.unlocked
  const signers = await authorKeys(account, row.authorAddress).catch(() => [])
  const opened = key.openEvent(row.event, signers)
  const times = await timesOf(opened.fields)
  // Signed by the address the server names as the author, with its checked keys.
  const knownAuthor = signers.length > 0
  const asServed = sameInstant(times.startUtc, row.startUtc) && sameInstant(times.endUtc, row.endUtc) && times.fullDay === row.fullDay
  return {
    id: row.id,
    calendarId: row.calendarId,
    fields: opened.fields,
    ...times,
    revision: row.revision,
    reminders: row.reminders ?? null,
    verified: opened.verified && knownAuthor && asServed,
  }
}

/** One event of `calendar`, opened (a reminder's, to name it). */
export async function loadEvent(account: MailAccount, calendar: Calendar, eventId: string): Promise<CalendarEvent> {
  const { data } = await api.get<EventRow>(`/calendar/calendars/${encodeURIComponent(calendar.id)}/events/${encodeURIComponent(eventId)}`)
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
