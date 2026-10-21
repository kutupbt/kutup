// Calendars in the browser (docs/plans/calendar.md, E1), over the
// `crypto-calendar` WASM runtime: the Calendar app (and Mail for
// invitations) loads it instead of `crypto` (@kutup/config/vite). The
// unlocked calendar key stays in WASM inside an `UnlockedCalendar`; this
// module never sees it or the passphrase.

import type { SealedMailKey } from './mailKey'
import { getCryptoWasm } from './rustWasm'

/** A time as the Rust core writes it (`TimeV1`). */
export type CalendarTime =
  | { date: string }
  | { zoned: { local: string; tzid: string } }
  | { utc: string }

/** An event as a client edits it (`EventFieldsV1`). */
export interface EventFields {
  uid: string
  dtstamp: string
  created: string | null
  start: CalendarTime
  end: CalendarTime | null
  recurrenceId: CalendarTime | null
  rrule: string | null
  exdates?: CalendarTime[]
  organizer: string | null
  sequence?: number
  summary: string | null
  description: string | null
  location: string | null
  status: 'tentative' | 'confirmed' | 'cancelled' | null
  transp: 'opaque' | 'transparent' | null
  comment: string | null
  other?: string[]
}

export interface EventPart {
  data: string
  signature: string
}

/** A sealed event as the server stores it (`SealedEventV1`). */
export interface SealedEvent {
  sharedKeyPacket: string
  calendarKeyPacket: string
  sharedSigned: EventPart
  sharedEncrypted: EventPart
  calendarSigned: EventPart
  calendarEncrypted: EventPart | null
}

/** A calendar's sealed name and description (`SealedMetadataV1`). */
export interface SealedMetadata {
  keyPacket: string
  dataPacket: string
  signature: string
}

/** A member's copy of a calendar's passphrase. */
export interface SealedPassphrase {
  dataPacket: string
  signature: string
  keyPacket: string
}

export interface CalendarMetadata {
  name: string
  description: string
}

/** What `createCalendar` makes, for `POST /api/calendar/calendars`. */
export interface NewCalendar {
  publicKey: string
  lockedSecretKey: string
  fingerprint: string
  passphrase: SealedPassphrase
  metadata: SealedMetadata
}

type KeyArgs = [masterKeyBase64: string, binding: string, address: string, envelope: string, fingerprint: string]

/**
 * A calendar's key in WASM memory; `free()` it when the calendar closes. It
 * seals only to the key derived from its own secret, never to a public key
 * the server lists (#307 review H1).
 */
export interface UnlockedCalendar {
  /** The key's fingerprint (hex), derived from the unlocked secret. */
  readonly fingerprint: string
  openEvent(event: SealedEvent, authorPublicKeys: string[]): { fields: EventFields; verified: boolean }
  /** Refused unless the metadata names `calendarId` and this key. */
  openMetadata(metadata: SealedMetadata, calendarId: string, authorPublicKeys: string[]): CalendarMetadata & { verified: boolean }
  sealEvent(...args: [...KeyArgs, fields: EventFields]): SealedEvent
  sealMetadata(...args: [...KeyArgs, calendarId: string, metadata: CalendarMetadata]): SealedMetadata
  free(): void
}

interface CalendarWasm {
  createCalendar(...args: [...KeyArgs, calendarId: string, metadata: CalendarMetadata, createdAtSecs: number]): NewCalendar
  unlockCalendar(...args: [...KeyArgs, passphrase: SealedPassphrase, ownerPublicKeys: string[], lockedSecretKey: string]): UnlockedCalendar
  calendarUtcToLocal(instant: string, tzid: string): string
  calendarLocalToUtc(local: string, tzid: string): string
  calendarTimeZones(): string[]
}

/** The loaded runtime's calendar functions; an app that loaded `crypto` has none. */
async function wasm(): Promise<CalendarWasm> {
  const module = (await getCryptoWasm()) as unknown as Partial<CalendarWasm>
  if (typeof module.unlockCalendar !== 'function') {
    throw new Error('this app loads the crypto runtime without calendars (use crypto-calendar)')
  }
  return module as CalendarWasm
}

function keyArgs(key: SealedMailKey): KeyArgs {
  return [key.masterKeyBase64, key.binding, key.address, key.envelope, key.fingerprint]
}

/**
 * A new calendar `calendarId` owned by `owner` (its primary address key),
 * named `metadata`; the passphrase is sealed to the key derived from the
 * owner's secret, never to a public key given.
 */
export async function createCalendar(owner: SealedMailKey, calendarId: string, metadata: CalendarMetadata): Promise<NewCalendar> {
  return (await wasm()).createCalendar(...keyArgs(owner), calendarId, metadata, Math.floor(Date.now() / 1000))
}

/**
 * Unlocks a calendar with the member's address key: refused unless one of
 * `ownerPublicKeys` (the owner's address keys, verified) signed the passphrase.
 */
export async function unlockCalendar(
  member: SealedMailKey,
  passphrase: SealedPassphrase,
  ownerPublicKeys: string[],
  lockedSecretKey: string,
): Promise<UnlockedCalendar> {
  return (await wasm()).unlockCalendar(...keyArgs(member), passphrase, ownerPublicKeys, lockedSecretKey)
}

/** Seals an event's fields for an unlocked calendar, signed by the author's address key. */
export function sealCalendarEvent(calendar: UnlockedCalendar, author: SealedMailKey, fields: EventFields): SealedEvent {
  return calendar.sealEvent(...keyArgs(author), fields)
}

/** Seals an unlocked calendar's new name and description, bound to its id. */
export function sealCalendarMetadata(calendar: UnlockedCalendar, author: SealedMailKey, calendarId: string, metadata: CalendarMetadata): SealedMetadata {
  return calendar.sealMetadata(...keyArgs(author), calendarId, metadata)
}

/** A UTC instant (RFC 3339) as a wall-clock time in `tzid`, `2026-10-29T09:30:00`. */
export async function utcToLocal(instant: string, tzid: string): Promise<string> {
  return (await wasm()).calendarUtcToLocal(instant, tzid)
}

/** A wall-clock time in `tzid` as a UTC instant (RFC 3339), as events convert theirs. */
export async function localToUtc(local: string, tzid: string): Promise<string> {
  return (await wasm()).calendarLocalToUtc(local, tzid)
}

/** The IANA time zones the bundled database knows. */
export async function timeZones(): Promise<string[]> {
  return (await wasm()).calendarTimeZones()
}
