// Calendar sharing (docs/plans/calendar-e3.md, E3c and E3d's dialog) as the
// app sees it: the one module that talks to the sharing routes, so that when
// the server slice (E3b) lands, only this file meets it. Shapes follow the
// plan under the post-W7 names (`/calendar/...`, `accountId` fields). The
// crypto is Rust's (`@kutup/crypto/calendar`); who someone is comes from
// Drive's identity pins, as Drive shares: looked up by the address typed,
// warned about (not refused) when changed, and sealed to exactly the answer
// checked.

import {
  calendarLinkUrlSecret,
  createCalendarLink,
  rotateCalendar,
  sealLinkPurpose,
  shareCalendarPassphrase,
  unlockSharedCalendar,
  type CalendarAccount,
  type CalendarOwner,
  type GenerationSealed,
  type GenerationShare,
} from '@kutup/crypto/calendar'
import { accountKeyOf, type AccountRef } from '@kutup/crypto/accountRef'
import type { SealedMetadata } from '@kutup/crypto/calendar'
import {
  CalendarChangedError,
  fileSharedCalendarSettings,
  forgetCalendarSettings,
  OwnerIdentityChanged,
  PERMISSION,
  setOwnerCheck,
  type Calendar,
  type CalendarKeyRow,
  type CalendarOwnerRow,
} from '@kutup/calendar-core/api'
import { driveIdentityOf, type DriveIdentity } from '@kutup/drive-core/identity'
import {
  acceptIdentity,
  checkIdentity,
  confirmRecipient,
  IdentityNotConfirmed,
  lookupAddress,
  sealableDriveKey,
  type AccountAnswer,
  type IdentityStatus,
} from '@kutup/drive-core/identityPins'
import type { MailAccount } from '@kutup/mail-core/api'
import { addressKeys } from '@kutup/mail-core/keys'
import { resolveApiBase } from '@kutup/session/apiBase'
import { loadServerSettings } from '@kutup/session/apps'
import api from '@kutup/session/client'
import { ownAccount } from '@kutup/session/devices'
import type { Session } from '@kutup/session/store'

export { CalendarChangedError, IdentityNotConfirmed, OwnerIdentityChanged }

// ------------------------------------------------------------ presets

/** Proton's two member presets (`ShareCalendarModal`); links use `busy`. */
export type Preset = 'edit' | 'view'

export const PRESET_PERMISSIONS: Record<Preset, number> = {
  edit: PERMISSION.write | PERMISSION.read | PERMISSION.availability,
  view: PERMISSION.read | PERMISSION.availability,
}

/** The preset a member's bits are; `null` for bits no preset gives. */
export function presetOf(permissions: number): Preset | null {
  if (permissions === PRESET_PERMISSIONS.edit) return 'edit'
  if (permissions === PRESET_PERMISSIONS.view) return 'view'
  return null
}

// ------------------------------------------------------------ shapes

/** A member of a calendar, as its owner lists them. */
export interface MemberRow {
  accountId: string
  /** Their current address, for showing and for looking their keys up. */
  address: string
  permissions: number
  addedAt: string
}

/** An invitation the owner sent and the person has not accepted. */
export interface SentInvitationRow {
  id: string
  accountId: string
  address: string
  permissions: number
  state: 'pending' | 'declined'
  createdAt: string
  expiresAt: string
}

/** An invitation to this account: the calendar, its owner, and this account's shares of every generation. */
export interface ReceivedInvitationRow {
  id: string
  calendarId: string
  owner: CalendarOwnerRow
  permissions: number
  metadata: SealedMetadata
  keys: CalendarKeyRow[]
  createdAt: string
  expiresAt: string
}

/** Proton's three kinds of link, Kutup's way (§3): the key in the fragment, in the query, or no key (busy times only). */
export type LinkKind = 'full' | 'query' | 'busy'

export interface LinkRow {
  id: string
  kind: LinkKind
  /** A full or query link's secret, sealed under the newest generation's passphrase, for the members; null for busy. */
  secret: GenerationSealed | null
  /** The owner's optional label for it (Proton's), sealed to the calendar key and signed. */
  purpose?: SealedMetadata | null
  createdAt: string
}

/** Proton's limit on a link's label; kutup-crypto refuses a longer one. */
export const MAX_LINK_PURPOSE = 100

/** Where a link leads: the page (fragment or busy links) and the calendar feed other apps subscribe to. */
export interface LinkUrls {
  page?: string
  ics?: string
}

/** The site's limits and switches for sharing (admin settings, namespaced `calendar.*`). */
export interface SharingSettings {
  /** Links that carry their key in the query (the server reads the calendar on each fetch). */
  queryLinksAllowed: boolean
  membersPerCalendar: number
  linksPerCalendar: number
}

// ------------------------------------------------------------ errors

export class RecipientNotFound extends Error {
  constructor(readonly address: string) {
    super(`no Kutup account at ${address}`)
    this.name = 'RecipientNotFound'
  }
}

/** The address is the owner's own. */
export class SelfShare extends Error {
  constructor() {
    super('a calendar is already its owner’s')
    this.name = 'SelfShare'
  }
}

/** The person lives on another server: sharing is same-server only (plan Q-2). */
export class OtherServer extends Error {
  constructor(readonly address: string) {
    super(`${address} is on another server`)
    this.name = 'OtherServer'
  }
}

/** Already a member, or already invited. */
export class AlreadyShared extends Error {
  constructor(readonly address: string) {
    super(`${address} already has this calendar`)
    this.name = 'AlreadyShared'
  }
}

/** The calendar has as many members (with invitations) as the site allows. */
export class TooManyMembers extends Error {
  constructor(readonly limit: number) {
    super(`a calendar has at most ${limit} members`)
    this.name = 'TooManyMembers'
  }
}

type DoubtfulStatus = Extract<IdentityStatus, { kind: 'changed' | 'invalid' | 'someoneElse' }>

/**
 * A shared calendar's owner (or a member who stays, in a rotation) can't be
 * confirmed until the user says so. Drive's own error, so Drive's warning
 * shows it; `address` is the person's.
 */
export class PersonNotConfirmed extends IdentityNotConfirmed {
  constructor(
    readonly address: string,
    status: DoubtfulStatus,
  ) {
    super(address, status)
    this.name = 'PersonNotConfirmed'
  }
}

// ------------------------------------------------------------ helpers

function calendarPath(calendarId: string, rest = ''): string {
  return `/calendar/calendars/${encodeURIComponent(calendarId)}${rest}`
}

async function calendarAccount(session: Session): Promise<CalendarAccount> {
  return { identityRoot: session.roots.identityRoot, account: await ownAccount(session) }
}

function refString(ref: AccountRef): string {
  return accountKeyOf(ref)
}

/** Each live generation's key with this account's share, oldest first. */
export async function loadKeys(calendarId: string): Promise<CalendarKeyRow[]> {
  const { data } = await api.get<{ keys: CalendarKeyRow[] }>(calendarPath(calendarId, '/keys'))
  if (!data.keys.length) throw new Error('the calendar lists no keys')
  return [...data.keys].sort((a, b) => a.keyGeneration - b.keyGeneration)
}

function sharesOf(keys: CalendarKeyRow[]): GenerationShare[] {
  return keys.map((key) => ({ keyGeneration: key.keyGeneration, share: key.passphraseShare }))
}

export async function loadSharingSettings(): Promise<SharingSettings> {
  const data = await loadServerSettings<{ calendar?: Partial<SharingSettings> }>()
  return {
    // Allowed unless the administrator turned it off (Proton allows them).
    queryLinksAllowed: data.calendar?.queryLinksAllowed !== false,
    membersPerCalendar: data.calendar?.membersPerCalendar ?? 49,
    linksPerCalendar: data.calendar?.linksPerCalendar ?? 5,
  }
}

// ------------------------------------------------------------ the owner's side

/** The calendar's members and the invitations not yet accepted. */
export async function loadSharing(calendarId: string): Promise<{ members: MemberRow[]; invitations: SentInvitationRow[] }> {
  const { data } = await api.get<{ members: MemberRow[]; invitations: SentInvitationRow[] }>(calendarPath(calendarId, '/members'))
  return data
}

/**
 * Invites the person at `address` with `preset`: looked up by the address as
 * typed, checked against the pins (a changed identity stops it with
 * `IdentityNotConfirmed` until `confirmed`), and given every live
 * generation's passphrase, sealed to exactly the account checked.
 */
export async function invite(
  session: Session,
  me: DriveIdentity,
  calendar: Calendar,
  address: string,
  preset: Preset,
  confirmed = false,
): Promise<void> {
  const typed = address.trim()
  const person: AccountAnswer | null = await lookupAddress(me, typed)
  if (!person) throw new RecipientNotFound(typed)
  if (person.accountId === me.accountRef.accountId && person.server === me.accountRef.server) throw new SelfShare()
  if (person.server !== me.accountRef.server) throw new OtherServer(typed)
  const [sharing, settings] = await Promise.all([loadSharing(calendar.id), loadSharingSettings()])
  if (sharing.members.some((m) => m.accountId === person.accountId) || sharing.invitations.some((i) => i.accountId === person.accountId && i.state === 'pending')) {
    throw new AlreadyShared(typed)
  }
  if (sharing.members.length + sharing.invitations.filter((i) => i.state === 'pending').length >= settings.membersPerCalendar) {
    throw new TooManyMembers(settings.membersPerCalendar)
  }
  await confirmRecipient(me, typed, person, confirmed)
  const member = {
    account: refString({ server: person.server, accountId: person.accountId }),
    incarnationId: person.accountIncarnationId,
    hpkePublicKey: sealableDriveKey(typed, person.driveHpkePublicKey, person.identitySuite),
  }
  const owner = await calendarAccount(session)
  const keys = await loadKeys(calendar.id)
  const shares = await Promise.all(
    sharesOf(keys).map(async (own) => ({ keyGeneration: own.keyGeneration, share: await shareCalendarPassphrase(owner, calendar.id, own, member) })),
  )
  await api.post(calendarPath(calendar.id, '/invitations'), {
    accountId: person.accountId,
    incarnationId: person.accountIncarnationId,
    permissions: PRESET_PERMISSIONS[preset],
    shares,
  })
}

/** A member's preset changed (the server queues their alarms to be worked out again). */
export async function setMemberPreset(calendarId: string, accountId: string, preset: Preset): Promise<void> {
  await api.patch(calendarPath(calendarId, `/members/${encodeURIComponent(accountId)}`), { permissions: PRESET_PERMISSIONS[preset] })
}

export async function revokeInvitation(calendarId: string, invitationId: string): Promise<void> {
  await api.delete(calendarPath(calendarId, `/invitations/${encodeURIComponent(invitationId)}`))
}

/**
 * Removes a member, rotating the calendar's key in the same request (§2):
 * a new generation sealed to everyone who stays (members and pending
 * invitations, each checked against the pins again; a changed identity stops
 * it with `PersonNotConfirmed` unless its account is in `confirmed`), the
 * name re-sealed, and every keyed link carried over. The removed member keeps
 * only what it could already read.
 */
export async function removeMember(
  session: Session,
  me: DriveIdentity,
  account: MailAccount,
  calendar: Calendar,
  accountId: string,
  confirmed: ReadonlySet<string> = new Set(),
): Promise<void> {
  const [sharing, keys, links] = await Promise.all([loadSharing(calendar.id), loadKeys(calendar.id), loadLinks(calendar.id)])
  const newest = keys[keys.length - 1]
  const stay = [
    ...sharing.members.filter((m) => m.accountId !== accountId).map((m) => ({ accountId: m.accountId, address: m.address })),
    ...sharing.invitations.filter((i) => i.state === 'pending' && i.accountId !== accountId).map((i) => ({ accountId: i.accountId, address: i.address })),
  ]
  const members = await Promise.all(
    stay.map(async (person) => {
      const answer = await lookupAddress(me, person.address)
      // The address now leads elsewhere: whoever holds it is not the member.
      if (!answer || answer.accountId !== person.accountId) throw new PersonNotConfirmed(person.address, { kind: 'someoneElse' })
      try {
        await confirmRecipient(me, person.address, answer, confirmed.has(person.accountId))
      } catch (error) {
        if (error instanceof IdentityNotConfirmed) throw new PersonNotConfirmed(person.address, error.status)
        throw error
      }
      return {
        accountId: person.accountId,
        member: {
          account: refString({ server: answer.server, accountId: answer.accountId }),
          incarnationId: answer.accountIncarnationId,
          hpkePublicKey: sealableDriveKey(person.address, answer.driveHpkePublicKey, answer.identitySuite),
        },
      }
    }),
  )
  const keyed = links.filter((link) => link.kind !== 'busy')
  if (keyed.some((link) => link.secret?.keyGeneration !== newest.keyGeneration)) throw new CalendarChangedError()
  const rotated = await rotateCalendar(
    await calendarAccount(session),
    account.key,
    calendar.id,
    { keyGeneration: newest.keyGeneration, share: newest.passphraseShare },
    {
      members: members.map((m) => m.member),
      names: { name: calendar.name, description: calendar.description, rest: calendar.metadataRest },
      links: keyed.map((link) => ({ linkId: link.id, secret: link.secret!.sealed })),
    },
  )
  const byAccount = new Map(members.map((m) => [m.member.account, m.accountId]))
  await api.post(calendarPath(calendar.id, '/keys/rotate'), {
    removeAccountId: accountId,
    // The generation this rotation follows: refused if another one came first.
    fromKeyGeneration: newest.keyGeneration,
    keyGeneration: rotated.keyGeneration,
    publicKey: rotated.publicKey,
    lockedSecretKey: rotated.lockedSecretKey,
    ownShare: rotated.ownShare,
    memberShares: rotated.memberShares.map((share) => ({ accountId: byAccount.get(share.account)!, share: share.share })),
    metadata: rotated.metadata,
    links: rotated.links.map((link) => ({ id: link.linkId, passphrase: link.passphrase, secret: link.secret })),
  })
}

// ------------------------------------------------------------ the member's side

/** Invitations to this account, newest first. */
export async function loadInvitations(): Promise<ReceivedInvitationRow[]> {
  const { data } = await api.get<{ invitations: ReceivedInvitationRow[] }>('/calendar/invitations')
  return [...data.invitations].sort((a, b) => b.createdAt.localeCompare(a.createdAt))
}

/** A shared calendar's owner, checked against the pins; their verified keys, or `PersonNotConfirmed`. */
export async function checkOwner(me: DriveIdentity, owner: CalendarOwnerRow, confirmed = false): Promise<CalendarOwner> {
  const status = await checkIdentity(me, owner.address, { driveSigningPublicKey: owner.signingPublicKey, incarnationId: owner.incarnationId })
  if ((status.kind === 'changed' || status.kind === 'invalid' || status.kind === 'someoneElse') && !confirmed) throw new PersonNotConfirmed(owner.address, status)
  return { account: refString({ server: me.accountRef.server, accountId: owner.accountId }), incarnationId: owner.incarnationId, signingPublicKey: owner.signingPublicKey }
}

/**
 * The check calendar-core opens shared calendars through
 * (`setOwnerCheck`): a doubtful owner leaves the calendar closed, listed as
 * `OwnerIdentityChanged` so the app can ask.
 */
export function ownerCheckFor(identity: (session: Session) => Promise<DriveIdentity>) {
  return async (session: Session, owner: CalendarOwnerRow): Promise<CalendarOwner> => {
    try {
      return await checkOwner(await identity(session), owner)
    } catch (error) {
      // calendar-core names the calendar when it lists it.
      if (error instanceof PersonNotConfirmed) throw new OwnerIdentityChanged('', owner.address)
      throw error
    }
  }
}

const identities = new Map<string, Promise<DriveIdentity>>()

/** The signed-in account's Drive identity, derived once per session. */
export function identityOf(session: Session): Promise<DriveIdentity> {
  let found = identities.get(session.sessionId)
  if (!found) {
    found = driveIdentityOf(session)
    found.catch(() => identities.delete(session.sessionId))
    identities.set(session.sessionId, found)
  }
  return found
}

/** Installs the owner check calendar-core opens shared calendars through; once, at start. */
export function installOwnerCheck(): void {
  setOwnerCheck(ownerCheckFor(identityOf))
}

/** The user accepted an owner's new identity: trusted from now on (Drive's pins keep the old one in their history). */
export async function trustOwner(me: DriveIdentity, ownerAddress: string): Promise<void> {
  await acceptIdentity(me, ownerAddress)
}

/** What an invitation shows before it is accepted: the calendar's name, opened with the owner's verified keys. */
export interface OpenedInvitation {
  name: string
  description: string
  ownerAddress: string
  preset: Preset | null
}

/**
 * Opens an invitation: the owner checked against the pins (`PersonNotConfirmed`
 * until `confirmed`), this account's share of the newest generation opened
 * (refused unless the owner signed it for this account and calendar), and
 * the name checked against the owner's address keys.
 */
export async function openInvitation(
  session: Session,
  me: DriveIdentity,
  invitation: ReceivedInvitationRow,
  confirmed = false,
): Promise<OpenedInvitation> {
  const owner = await checkOwner(me, invitation.owner, confirmed)
  const keys = [...invitation.keys].sort((a, b) => a.keyGeneration - b.keyGeneration)
  const newest = keys[keys.length - 1]
  if (!newest) throw new Error('the invitation holds no key')
  const key = await unlockSharedCalendar(await calendarAccount(session), owner, {
    calendarId: invitation.calendarId,
    keyGeneration: newest.keyGeneration,
    passphraseShare: newest.passphraseShare,
    lockedSecretKey: newest.lockedSecretKey,
  })
  try {
    if (key.fingerprint !== newest.fingerprint.toLowerCase()) throw new Error('the calendar key is not the one listed')
    const signer = await addressKeys(invitation.owner.address)
    if (signer.accountRef?.accountId !== invitation.owner.accountId) throw new Error('the owner’s address belongs to someone else')
    const metadata = key.openMetadata(invitation.metadata, invitation.calendarId, signer.all)
    if (!metadata.verified) throw new Error('the calendar name is not signed by its owner')
    return { name: metadata.name, description: metadata.description, ownerAddress: invitation.owner.address, preset: presetOf(invitation.permissions) }
  } finally {
    key.free()
  }
}

/**
 * Joins a calendar: opened as above (an owner the user confirmed is trusted
 * from now on), the member's own settings record filed, then the accept. A
 * failed accept takes the record back.
 */
export async function acceptInvitation(
  session: Session,
  me: DriveIdentity,
  invitation: ReceivedInvitationRow,
  color: string,
  confirmed = false,
): Promise<void> {
  await openInvitation(session, me, invitation, confirmed)
  if (confirmed) await trustOwner(me, invitation.owner.address)
  await fileSharedCalendarSettings(session, invitation.calendarId, color)
  try {
    await api.post(`/calendar/invitations/${encodeURIComponent(invitation.id)}/accept`)
  } catch (error) {
    await forgetCalendarSettings(session, invitation.calendarId).catch(() => undefined)
    throw error
  }
}

export async function declineInvitation(invitationId: string): Promise<void> {
  await api.post(`/calendar/invitations/${encodeURIComponent(invitationId)}/decline`)
}

/** Leaves a calendar someone else owns; its settings record goes after. */
export async function leaveCalendar(session: Session, calendar: Calendar): Promise<void> {
  if (calendar.owned) throw new Error('an owner deletes a calendar, never leaves it')
  await api.delete(calendarPath(calendar.id, '/members/me'))
  await forgetCalendarSettings(session, calendar.id, true)
}

// ------------------------------------------------------------ links (E3d)

export async function loadLinks(calendarId: string): Promise<LinkRow[]> {
  const { data } = await api.get<{ links: LinkRow[] }>(calendarPath(calendarId, '/links'))
  return data.links
}

/** The URLs of a link; `secret` is a full or query link's URL secret. */
export async function linkUrls(kind: LinkKind, linkId: string, secret?: string): Promise<LinkUrls> {
  const origin = window.location.origin
  const base = await resolveApiBase()
  const feed = `${origin}${base}/calendar/links/${encodeURIComponent(linkId)}/calendar.ics`
  switch (kind) {
    // The fragment never reaches the server.
    case 'full':
      return { page: `${origin}/l/${encodeURIComponent(linkId)}#${secret}` }
    // For other calendar apps: the server opens it on each fetch.
    case 'query':
      return { ics: `${feed}?key=${secret}` }
    case 'busy':
      return { page: `${origin}/l/${encodeURIComponent(linkId)}`, ics: feed }
  }
}

/**
 * Makes a link of `kind`. A keyed one carries a fresh secret that opens
 * every live generation's passphrase; the server keeps only the sealed copies
 * and never sees the secret of a full link.
 */
export async function createLink(
  session: Session,
  account: MailAccount,
  calendar: Calendar,
  kind: LinkKind,
  label = '',
): Promise<{ link: LinkRow; urls: LinkUrls }> {
  if (!calendar.owned) throw new Error('only the owner makes links')
  const [settings, existing] = await Promise.all([loadSharingSettings(), loadLinks(calendar.id)])
  if (existing.length >= settings.linksPerCalendar) throw new TooManyLinks(settings.linksPerCalendar)
  if (kind === 'query' && !settings.queryLinksAllowed) throw new Error('this server does not allow links with the key in the address')
  const id = crypto.randomUUID()
  // Only the owner reads it back; the server keeps it sealed.
  const purpose = label.trim() ? sealLinkPurpose(calendar.unlocked, account.key, calendar.id, id, label.trim()) : null
  if (kind === 'busy') {
    const { data } = await api.post<LinkRow>(calendarPath(calendar.id, '/links'), { id, kind, purpose })
    return { link: data, urls: await linkUrls(kind, id) }
  }
  const keys = await loadKeys(calendar.id)
  const made = await createCalendarLink(await calendarAccount(session), calendar.id, id, sharesOf(keys))
  const { data } = await api.post<LinkRow>(calendarPath(calendar.id, '/links'), { id, kind, secret: made.secret, passphrases: made.passphrases, purpose })
  return { link: data, urls: await linkUrls(kind, id, made.urlSecret) }
}

/** The calendar has as many links as the site allows. */
export class TooManyLinks extends Error {
  constructor(readonly limit: number) {
    super(`a calendar has at most ${limit} links`)
    this.name = 'TooManyLinks'
  }
}

/** A link's URLs again: a keyed link's secret opened from the members' copy. */
export async function showLink(session: Session, calendar: Calendar, link: LinkRow): Promise<LinkUrls> {
  if (link.kind === 'busy') return linkUrls('busy', link.id)
  if (!link.secret) throw new Error('the link has no secret')
  const keys = await loadKeys(calendar.id)
  const own = keys.find((key) => key.keyGeneration === link.secret!.keyGeneration)
  if (!own) throw new Error('no key of the link’s generation')
  const secret = await calendarLinkUrlSecret(
    await calendarAccount(session),
    calendar.id,
    { keyGeneration: own.keyGeneration, share: own.passphraseShare },
    link.id,
    link.secret.sealed,
  )
  return linkUrls(link.kind, link.id, secret)
}

/**
 * A link's label, opened with whichever of the calendar's generations sealed
 * it; null when it has none, or none of the owner's keys signed it.
 */
export function linkPurpose(account: MailAccount, calendar: Calendar, link: LinkRow): string | null {
  if (!link.purpose) return null
  for (const key of calendar.keyring.values()) {
    try {
      const opened = key.openLinkPurpose(link.purpose, calendar.id, link.id, account.ownPublicKeys)
      return opened.verified ? opened.purpose : null
    } catch {
      // Another generation's key, or not this link's: try the next.
    }
  }
  return null
}

export async function deleteLink(calendarId: string, linkId: string): Promise<void> {
  await api.delete(calendarPath(calendarId, `/links/${encodeURIComponent(linkId)}`))
}
