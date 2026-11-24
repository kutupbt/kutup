// Calendars in the browser (docs/plans/calendar.md, E1), over the
// `crypto-calendar` WASM runtime: the Calendar app (and Mail for
// invitations) loads it instead of `crypto` (@kutup/config/vite). The
// unlocked calendar key stays in WASM inside an `UnlockedCalendar`; this
// module never sees it or the passphrase. The passphrase is shared on the
// account's keys, which WASM derives from the identity root
// (docs/plans/wipe-unification.md, W4); the address key signs the name and
// the events.

import type { IdentityRoot } from './accountRoots'
import type { MasterKeys } from './masterKeys'
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
  /**
   * Properties a newer client put in the other parts, kept so an edit here
   * seals them again (docs/plans/format-evolution.md). An edit spreads the
   * opened fields (`{ ...fields, summary }`) to keep them.
   */
  signedOther?: string[]
  calendarOther?: string[]
  commentOther?: string[]
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

export interface CalendarMetadata {
  name: string
  description: string
  /**
   * What the sealed metadata holds besides: its version and a newer
   * client's fields. `openMetadata` gives it; pass it back with a rename so
   * nothing is dropped (docs/plans/format-evolution.md).
   */
  rest?: Record<string, unknown>
}

/** What `createCalendar` makes, for `POST /api/v1/calendar/calendars`. */
export interface NewCalendar {
  publicKey: string
  lockedSecretKey: string
  fingerprint: string
  /** The owner's own share of the passphrase (`CalendarShareEnvelopeV1`, base64). */
  passphraseShare: string
  metadata: SealedMetadata
}

type KeyArgs = [masterKeys: MasterKeys, binding: string, address: string, envelope: string, fingerprint: string]

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
  /** The key ID (hex) key packets to this key name: which generation an event needs. */
  readonly keyId: string
  /** A key packet `older` (an older generation's key) opens, sealed again to this key (compaction). */
  rewrapKeyPacket(older: UnlockedCalendar, keyPacket: string): string
  /** A link's optional purpose, sealed to this calendar's key, bound to it and the link, signed by the owner's address key. */
  sealLinkPurpose(...args: [...KeyArgs, calendarId: string, linkId: string, purpose: string]): SealedMetadata
  /** Refused unless the purpose names `calendarId` and `linkId`. */
  openLinkPurpose(sealed: SealedMetadata, calendarId: string, linkId: string, authorPublicKeys: string[]): { purpose: string; verified: boolean }
  free(): void
}

/** The signed-in account: its identity root and `aci:<uuid>@<server>`. */
export interface CalendarAccount {
  identityRoot: IdentityRoot
  account: string
}

/** A calendar as its member's row names it, for unlocking. */
export interface CalendarLock {
  calendarId: string
  keyGeneration: number
  passphraseShare: string
  lockedSecretKey: string
}

/**
 * A member the passphrase is shared with, as their verified key binding names
 * them (docs/plans/calendar-e3.md §1): `aci:<uuid>@<server>`, the account
 * incarnation (hex) and its account HPKE public key (base64).
 */
export interface CalendarMember {
  account: string
  incarnationId: string
  xwingPublicKey: string
}

/** A calendar's owner as a member checks their shares, verified: their account signing key (base64). */
export interface CalendarOwner {
  account: string
  incarnationId: string
  signingPublicKey: string
}

/** One key generation's own share of the passphrase. */
export interface GenerationShare {
  keyGeneration: number
  share: string
}

/** One key generation's sealed copy (a link's passphrase). */
export interface GenerationSealed {
  keyGeneration: number
  sealed: string
}

/** What a rotation takes: who stays, the calendar's names, and its full links. */
export interface RotationInput {
  members: CalendarMember[]
  names: CalendarMetadata
  /** Each keyed link and its secret, sealed to the owner's own account key. */
  links: { linkId: string; secret: string }[]
}

/** A new key generation, all of it for one request (docs/plans/calendar-e3.md §2). */
export interface RotatedCalendar {
  keyGeneration: number
  publicKey: string
  lockedSecretKey: string
  fingerprint: string
  ownShare: string
  memberShares: { account: string; share: string }[]
  metadata: SealedMetadata
  links: { linkId: string; passphrase: string }[]
}

/** A new full link: its URL's secret (never stored), and what the server keeps. */
export interface NewCalendarLink {
  urlSecret: string
  /** The secret sealed to the owner's own account key (never to the calendar's passphrase). */
  secret: string
  passphrases: GenerationSealed[]
  /** What the link's page shows the server (base64url); the server keeps its hash. */
  accessProof: string
}

/** A reminder as the server keeps it: on the device or by email, a trigger relative to the start. */
export interface IcsReminder {
  type: 'device' | 'email'
  trigger: string
}

/** What an `.ics` import may take (`ImportOptionsV1`): the site's limits, the person's zone, and now. */
export interface IcsImportOptions {
  primaryZone: string
  maxBytes: number
  maxEvents: number
  maxCount: number
  maxReminders: number
  now: string
}

/** Why a whole file is refused (Proton's `IMPORT_ERROR_TYPE`). */
export type IcsFileError = 'fileEmpty' | 'fileTooBig' | 'invalidCalendar' | 'invalidMethod' | 'noEvents' | 'tooManyEvents'

/** Why one component isn't imported (Proton's `IMPORT_EVENT_ERROR_TYPE`). */
export type IcsErrorKind =
  | 'wrongFormat'
  | 'nonGregorian'
  | 'todoFormat'
  | 'journalFormat'
  | 'freebusyFormat'
  | 'timezoneFormat'
  | 'unexpectedFloatingTime'
  | 'alldayInconsistency'
  | 'dtstartMissing'
  | 'dtstartMalformed'
  | 'dtstartOutOfBounds'
  | 'dtendMalformed'
  | 'dtendOutOfBounds'
  | 'xWrTimezoneUnsupported'
  | 'tzidUnsupported'
  | 'rruleMalformed'
  | 'rruleUnsupported'
  | 'singleEditUnsupported'
  | 'validationError'
  | 'externalError'

/** A component not imported: what it is (`vevent`, `vtodo`…), what names it, and why. */
export interface IcsError {
  component: string
  id: string
  kind: IcsErrorKind
}

export interface IcsImportedEvent {
  fields: EventFields
  reminders: IcsReminder[]
  id: string
}

/** A file read: its method, the events (series first), what isn't imported, and the events with no occurrence left. */
export interface IcsImport {
  method: string
  events: IcsImportedEvent[]
  errors: IcsError[]
  hidden: number
}

export type IcsImportOutcome = { read: IcsImport } | { refused: IcsFileError }

/** What an export writes (`ExportCalendarV1`). */
export interface IcsExport {
  name: string
  description: string | null
  zone: string
  release: string
  /** What an untitled event's alarms show. */
  untitled: string
  /** The member's address, for email alarms. */
  email: string | null
  events: { fields: EventFields; reminders: IcsReminder[] }[]
}

interface CalendarWasm {
  createCalendar(
    ...args: [...KeyArgs, identityRoot: IdentityRoot, account: string, calendarId: string, metadata: CalendarMetadata, createdAtSecs: number]
  ): NewCalendar
  unlockCalendar(
    identityRoot: IdentityRoot,
    account: string,
    calendarId: string,
    keyGeneration: number,
    passphraseShare: string,
    lockedSecretKey: string,
  ): UnlockedCalendar
  shareCalendarPassphrase(identityRoot: IdentityRoot, ownerAccount: string, calendarId: string, keyGeneration: number, ownShare: string, member: CalendarMember): string
  unlockSharedCalendar(
    identityRoot: IdentityRoot,
    memberAccount: string,
    owner: CalendarOwner,
    calendarId: string,
    keyGeneration: number,
    passphraseShare: string,
    lockedSecretKey: string,
  ): UnlockedCalendar
  calendarEventKeyId(event: SealedEvent): string
  calendarKeyPacketKeyId(keyPacket: string): string
  rotateCalendar(
    ...args: [...KeyArgs, identityRoot: IdentityRoot, ownerAccount: string, calendarId: string, keyGeneration: number, ownShare: string, rotation: RotationInput, createdAtSecs: number]
  ): RotatedCalendar
  createCalendarLink(identityRoot: IdentityRoot, ownerAccount: string, calendarId: string, linkId: string, ownShares: GenerationShare[]): NewCalendarLink
  calendarLinkUrlSecret(identityRoot: IdentityRoot, ownerAccount: string, linkId: string, sealedSecret: string): string
  calendarLinkAccessProof(urlSecret: string, linkId: string): string
  openCalendarLink(
    urlSecret: string,
    calendarId: string,
    linkId: string,
    keyGeneration: number,
    sealedPassphrase: string,
    lockedSecretKey: string,
  ): UnlockedCalendar
  calendarUtcToLocal(instant: string, tzid: string): string
  calendarLocalToUtc(local: string, tzid: string): string
  calendarTimeZones(): string[]
  calendarImportIcs(text: string, options: IcsImportOptions): IcsImportOutcome
  calendarExportIcs(calendar: IcsExport): string
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
  return [key.masterKeys, key.binding, key.address, key.envelope, key.fingerprint]
}

/**
 * A new calendar `calendarId` owned by `owner`, named `metadata` (signed by
 * `signer`, its primary address key); the passphrase is shared with the
 * owner's own account key, derived from its identity root, never a public
 * key given.
 */
export async function createCalendar(
  owner: CalendarAccount,
  signer: SealedMailKey,
  calendarId: string,
  metadata: CalendarMetadata,
): Promise<NewCalendar> {
  return (await wasm()).createCalendar(...keyArgs(signer), owner.identityRoot, owner.account, calendarId, metadata, Math.floor(Date.now() / 1000))
}

/**
 * Unlocks a calendar of the signed-in account from its own share of the
 * passphrase: refused unless the share names this calendar and key
 * generation and the account itself signed it. (Shared calendars, E3, add
 * the owner's verified keys.)
 */
export async function unlockCalendar(member: CalendarAccount, lock: CalendarLock): Promise<UnlockedCalendar> {
  return (await wasm()).unlockCalendar(
    member.identityRoot,
    member.account,
    lock.calendarId,
    lock.keyGeneration,
    lock.passphraseShare,
    lock.lockedSecretKey,
  )
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

/**
 * The owner shares generation `keyGeneration`'s passphrase (opened from their
 * own share) with `member`, whose keys the caller checked against the pins.
 */
export async function shareCalendarPassphrase(owner: CalendarAccount, calendarId: string, own: GenerationShare, member: CalendarMember): Promise<string> {
  return (await wasm()).shareCalendarPassphrase(owner.identityRoot, owner.account, calendarId, own.keyGeneration, own.share, member)
}

/**
 * A member unlocks a calendar someone else owns from their share of one
 * generation's passphrase: refused unless `owner` (verified) signed it for
 * this member, calendar and generation.
 */
export async function unlockSharedCalendar(member: CalendarAccount, owner: CalendarOwner, lock: CalendarLock): Promise<UnlockedCalendar> {
  return (await wasm()).unlockSharedCalendar(
    member.identityRoot,
    member.account,
    owner,
    lock.calendarId,
    lock.keyGeneration,
    lock.passphraseShare,
    lock.lockedSecretKey,
  )
}

/** The key ID (hex) one key packet is to (a link purpose's, in compaction). */
export async function calendarKeyPacketKeyId(keyPacket: string): Promise<string> {
  return (await wasm()).calendarKeyPacketKeyId(keyPacket)
}

/** The key ID (hex) an event's key packets are to: which generation's key opens it. */
export async function calendarEventKeyId(event: SealedEvent): Promise<string> {
  return (await wasm()).calendarEventKeyId(event)
}

/**
 * The calendar's next key generation after `own.keyGeneration`: a new key and
 * passphrase, shares for the owner and every member who stays, the name
 * re-sealed (signed by `signer`), and each full link carried over.
 */
export async function rotateCalendar(
  owner: CalendarAccount,
  signer: SealedMailKey,
  calendarId: string,
  own: GenerationShare,
  rotation: RotationInput,
): Promise<RotatedCalendar> {
  return (await wasm()).rotateCalendar(
    ...keyArgs(signer),
    owner.identityRoot,
    owner.account,
    calendarId,
    own.keyGeneration,
    own.share,
    rotation,
    Math.floor(Date.now() / 1000),
  )
}

/** A new full link `linkId`, from the owner's share of each live generation. */
export async function createCalendarLink(owner: CalendarAccount, calendarId: string, linkId: string, ownShares: GenerationShare[]): Promise<NewCalendarLink> {
  return (await wasm()).createCalendarLink(owner.identityRoot, owner.account, calendarId, linkId, ownShares)
}

/** A keyed link's URL secret again, from the owner's own envelope. */
export async function calendarLinkUrlSecret(owner: CalendarAccount, linkId: string, sealedSecret: string): Promise<string> {
  return (await wasm()).calendarLinkUrlSecret(owner.identityRoot, owner.account, linkId, sealedSecret)
}

/** What a keyed link's page shows the server, from the URL's secret (base64url). */
export async function calendarLinkAccessProof(urlSecret: string, linkId: string): Promise<string> {
  return (await wasm()).calendarLinkAccessProof(urlSecret, linkId)
}

/** Seals a link's purpose with an unlocked calendar, signed by the owner's address key. */
export function sealLinkPurpose(calendar: UnlockedCalendar, author: SealedMailKey, calendarId: string, linkId: string, purpose: string): SealedMetadata {
  return calendar.sealLinkPurpose(...keyArgs(author), calendarId, linkId, purpose)
}

/** One generation's key, as a link's viewer opens it: from the URL's secret and the passphrase the link's page serves. */
export interface LinkKeyLock {
  keyGeneration: number
  sealedPassphrase: string
  lockedSecretKey: string
}

/**
 * A full link's viewer unlocks one generation's key from the URL's secret:
 * refused under any other secret, calendar, link or generation. No account
 * and no session take part.
 */
export async function openCalendarLink(urlSecret: string, calendarId: string, linkId: string, lock: LinkKeyLock): Promise<UnlockedCalendar> {
  return (await wasm()).openCalendarLink(urlSecret, calendarId, linkId, lock.keyGeneration, lock.sealedPassphrase, lock.lockedSecretKey)
}

/** Reads an `.ics` file for import, every event rebuilt as Proton's import does (docs/plans/calendar.md, E2 §5). */
export async function importIcs(text: string, options: IcsImportOptions): Promise<IcsImportOutcome> {
  return (await wasm()).calendarImportIcs(text, options)
}

/** Writes a calendar's opened events as one `.ics` file (E2 §6). */
export async function exportIcs(calendar: IcsExport): Promise<string> {
  return (await wasm()).calendarExportIcs(calendar)
}
