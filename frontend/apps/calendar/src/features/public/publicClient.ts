// A calendar link's public view (docs/plans/calendar-e3.md §3, E3d): the
// one module that talks to the public link routes, so that when the server
// slice (E3b/E3d) lands only this file meets it. No account takes part:
// requests go out with `fetch` and no credentials, never through the
// session's client (no token refresh, no sign-in redirect, no instance-id
// reconciliation: a page without a session must not clear anything kept on
// this origin). A full link's key is the URL's fragment, which never
// reaches the server; the events open in WASM.

import { calendarEventKeyId, openCalendarLink, type SealedEvent, type SealedMetadata, type UnlockedCalendar } from '@kutup/crypto/calendar'
import { timesOf, type CalendarEvent } from '@kutup/calendar-core/api'
import { resolveApiBase } from '@kutup/session/apiBase'

/** One key generation as a full link's page serves it: that generation's passphrase sealed under the link's secret. */
export interface PublicKeyRow {
  keyGeneration: number
  fingerprint: string
  lockedSecretKey: string
  /** `seal_link_passphrase`'s output (base64). */
  passphrase: string
}

/** What `GET /api/calendar/links/{id}` answers: never the calendar's members or owner. */
export interface PublicLinkRow {
  calendarId: string
  kind: 'full' | 'query' | 'busy'
  /** A full link's sealed name; absent on busy links (the name is not theirs to show). */
  metadata?: SealedMetadata
  /** A full link's key generations, oldest first. */
  keys?: PublicKeyRow[]
}

/** An event as a full link's page serves it. */
export interface PublicEventRow {
  id: string
  event: SealedEvent
  startUtc: string
  endUtc: string
  fullDay: boolean
}

/** A busy block as a busy link serves it: times only. */
export interface BusyBlock {
  startUtc: string
  endUtc: string
  fullDay: boolean
}

/** The link is gone (deleted, or never was). */
export class LinkNotFound extends Error {
  constructor() {
    super('this calendar link does not exist')
    this.name = 'LinkNotFound'
  }
}

/** A full link opened without its key (the fragment lost on the way). */
export class LinkKeyMissing extends Error {
  constructor() {
    super('the link is missing its key')
    this.name = 'LinkKeyMissing'
  }
}

/** The most pages one window's events are read in, against a server that never ends a listing. */
const MAX_PAGES = 1000

async function getJson<T>(path: string, params?: Record<string, string>): Promise<T> {
  const base = await resolveApiBase()
  const query = params ? `?${new URLSearchParams(params).toString()}` : ''
  const response = await fetch(`${base}${path}${query}`, { credentials: 'omit', headers: { Accept: 'application/json' }, cache: 'no-store' })
  if (response.status === 404 || response.status === 410) throw new LinkNotFound()
  if (!response.ok) throw new Error(`the server answered ${response.status}`)
  return (await response.json()) as T
}

function linkPath(linkId: string, rest = ''): string {
  return `/calendar/links/${encodeURIComponent(linkId)}${rest}`
}

export function loadPublicLink(linkId: string): Promise<PublicLinkRow> {
  return getJson<PublicLinkRow>(linkPath(linkId))
}

/** A full link's calendar, opened from the URL's secret. */
export interface PublicCalendar {
  calendarId: string
  name: string
  description: string
  /** Every generation's key by key ID; WASM objects, freed with {@link closePublicCalendar}. */
  keyring: Map<string, UnlockedCalendar>
}

/**
 * Opens a full link: every generation's key from the URL's secret (refused
 * under any other secret, calendar, link or generation), each checked
 * against the fingerprint served, and the name. The name's signature can't
 * be checked here (no account to look the owner's keys up with), so the
 * page shows it as the link's, not as verified.
 */
export async function openPublicCalendar(linkId: string, link: PublicLinkRow, urlSecret: string): Promise<PublicCalendar> {
  if (link.kind !== 'full' || !link.keys?.length || !link.metadata) throw new Error('not a full link')
  if (!urlSecret) throw new LinkKeyMissing()
  const keyring = new Map<string, UnlockedCalendar>()
  try {
    const keys = [...link.keys].sort((a, b) => a.keyGeneration - b.keyGeneration)
    for (const key of keys) {
      const opened = await openCalendarLink(urlSecret, link.calendarId, linkId, {
        keyGeneration: key.keyGeneration,
        sealedPassphrase: key.passphrase,
        lockedSecretKey: key.lockedSecretKey,
      })
      keyring.set(opened.keyId, opened)
      if (opened.fingerprint !== key.fingerprint.toLowerCase()) throw new Error('the calendar key is not the one listed')
    }
    const newest = [...keyring.values()].at(-1)!
    const metadata = newest.openMetadata(link.metadata, link.calendarId, [])
    return { calendarId: link.calendarId, name: metadata.name, description: metadata.description, keyring }
  } catch (error) {
    for (const key of keyring.values()) key.free()
    throw error
  }
}

export function closePublicCalendar(calendar: PublicCalendar): void {
  for (const key of calendar.keyring.values()) key.free()
  calendar.keyring.clear()
}

/**
 * A full link's events in [start, end), opened with the generation each
 * names. Their authors can't be checked without an account, so none is
 * shown as verified; the times come from the signed fields, as in the app.
 */
export async function loadPublicEvents(linkId: string, calendar: PublicCalendar, start: string, end: string): Promise<{ events: CalendarEvent[]; unreadable: number }> {
  const events: CalendarEvent[] = []
  let unreadable = 0
  let after: { afterStart: string; afterId: string } | null = null
  for (let page = 0; page < MAX_PAGES; page++) {
    const params: Record<string, string> = { start, end, ...(after ?? {}) }
    const data: { events: PublicEventRow[]; next: { afterStart: string; afterId: string } | null } = await getJson(linkPath(linkId, '/events'), params)
    for (const row of data.events) {
      try {
        const key = calendar.keyring.get(await calendarEventKeyId(row.event))
        if (!key) throw new Error('no key of its generation')
        const opened = key.openEvent(row.event, [])
        const times = await timesOf(opened.fields)
        events.push({ id: row.id, calendarId: calendar.calendarId, fields: opened.fields, ...times, revision: 0, reminders: null, verified: false })
      } catch {
        unreadable++
      }
    }
    if (!data.next) return { events, unreadable }
    // A page that doesn't move forward is a server going round in circles.
    if (after && data.next.afterStart === after.afterStart && data.next.afterId === after.afterId) throw new Error('the server repeats a page')
    after = data.next
  }
  throw new Error('the server never ends the listing')
}

/** A busy link's blocks in [start, end): times only, nothing to open. */
export async function loadBusyBlocks(linkId: string, start: string, end: string): Promise<BusyBlock[]> {
  const { busy } = await getJson<{ busy: BusyBlock[] }>(linkPath(linkId, '/busy'), { start, end })
  return busy
}
