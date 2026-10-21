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
import { useMailAccount, type MailAccount } from '@kutup/mail-core/api'
import { accountHead, HeadBlockedError, NotInVerifiedIndexError, type ListedEdit, type VerifiedIndex } from '@kutup/session/accountHead'
import api from '@kutup/session/client'
import { useRequiredSession, type Session } from '@kutup/session/store'

/** The account head's scope of the calendars the account holds. */
const HEAD_SCOPE = 'calendars'

/** Proton's permission bits (`CALENDAR_PERMISSIONS`). */
export const PERMISSION = { superOwner: 1, owner: 2, write: 16, read: 32 } as const

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
  publicKey: string
  /** The owner signed the name and description. */
  verified: boolean
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
  sequence: number
  modifiedAt: string
}

/** An event, opened. */
export interface CalendarEvent {
  id: string
  calendarId: string
  fields: EventFields
  startUtc: string
  endUtc: string
  fullDay: boolean
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
        try {
          return await unlockCalendar(key, row.passphrase, account.ownPublicKeys, row.lockedSecretKey)
        } catch (error) {
          last = error
        }
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
          const metadata = key.openMetadata(row.metadata, account.ownPublicKeys)
          calendars.push({
            id: row.id,
            name: metadata.name,
            description: metadata.description,
            verified: metadata.verified,
            color: row.color,
            display: row.display,
            permissions: row.permissions,
            revision: row.revision,
            publicKey: row.publicKey,
            unlocked: key,
          })
        } catch {
          unreadable++
        }
      }
      return { calendars, unreadable }
    } catch (error) {
      if (!(error instanceof NotInVerifiedIndexError) || attempt > 0) throw error
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
  const made = await makeCalendar(account.key, account.publicKey, { name, description: '' })
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
}

/** Changes a calendar: the owner's name and description, the member's colour and visibility. */
export async function updateCalendar(session: Session, account: MailAccount, calendar: Calendar, change: CalendarChange): Promise<void> {
  const renamed = change.name !== undefined || change.description !== undefined
  const metadata = renamed
    ? await sealCalendarMetadata(account.key, calendar.publicKey, {
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

/**
 * Opens an event with its calendar's key and checks it: every part signed by
 * the author (one of the account's addresses in E1), and the times the
 * server read the ones signed.
 */
export async function openEvent(account: MailAccount, calendar: Calendar, row: EventRow): Promise<CalendarEvent> {
  const opened = calendar.unlocked.openEvent(row.event, account.ownPublicKeys)
  const start = await instantOf(opened.fields.start)
  const ownAuthor = row.authorAddress !== null && account.isOwnAddress(row.authorAddress)
  return {
    id: row.id,
    calendarId: row.calendarId,
    fields: opened.fields,
    startUtc: row.startUtc,
    endUtc: row.endUtc,
    fullDay: row.fullDay,
    verified: opened.verified && ownAuthor && sameInstant(start, row.startUtc),
  }
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
  for (let after: string | null = null; ; ) {
    const response: { data: { events: EventRow[]; next: string | null } } = await api.get(`/calendar/calendars/${calendar.id}/events`, {
      params: { start, end, after: after ?? undefined },
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
    after = data.next
  }
  return { events, unreadable }
}

/** One change refused by an events sync, with its code (`uidTaken`, `eventLimit`, `invalid`…). */
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

/** Saves an event's fields to `calendar`: a new event, or `existingId` changed. */
export async function saveEvent(
  account: MailAccount,
  calendar: Calendar,
  fields: EventFields,
  existingId?: string,
): Promise<string> {
  const addressId = await activeAddressId(account)
  const event = await sealCalendarEvent(account.key, calendar.publicKey, fields)
  const stored = await syncOne(calendar, addressId, existingId ? { update: { id: existingId, event } } : { create: event })
  return stored?.id ?? existingId ?? ''
}

export async function deleteEvent(account: MailAccount, calendar: Calendar, id: string): Promise<void> {
  const addressId = await activeAddressId(account)
  await syncOne(calendar, addressId, { delete: { id } })
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
