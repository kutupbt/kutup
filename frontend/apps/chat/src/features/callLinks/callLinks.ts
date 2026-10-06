import type { CallLinkCrypto, CallLinkInfo, CallLinkKeys } from '@kutup/chat-core/types'
import { loadChatWasm } from '@kutup/chat-core/wasm'
import { toBase64 } from '@kutup/crypto'
import api from '@kutup/session/client'
import { forgetHostToken, rememberHostToken } from './hostTokens'

// Meetings (docs/chat-calls.md, "Meetings"): a call anyone holding the link
// can join, with or without an account. Everything about one comes from the
// secret in its link's fragment, which no server sees. The Rust engine owns
// the derivations and the sealed formats; this is the browser's side of
// making, listing, opening and joining one.

export type MeetingInfo = CallLinkInfo

/** A meeting someone holds the link of: its secret and what derives from it. */
export interface OpenCallLink extends CallLinkKeys {
  /** Standard base64. */
  secret: string
  /** The part of the link after `#`. */
  fragment: string
}

/** One of the account's own meetings. */
export interface OwnedCallLink {
  roomId: string
  createdAt: string
  url: string
  info: MeetingInfo
  /** People who open the link wait until the owner lets them in. */
  waitingRoom: boolean
  /** Public; the owner's devices derive the meeting's secrets from it. */
  nonce: string
  /** The owner's proof of being the host (standard base64). */
  hostToken: string
}

interface StoredLink {
  roomId: string
  nonce: string
  info: string
  waitingRoom: boolean
  createdAt: string
}

/** Where a meeting opens: this server's chat app, the secret in the fragment. */
export function callLinkUrl(fragment: string): string {
  return `${window.location.origin}/call#${fragment}`
}

/**
 * The fragment of something a person pasted or opened: a whole link, or the
 * fragment alone. Null when it does not look like one.
 */
export function callLinkFragmentOf(value: string): string | null {
  const text = value.trim()
  const hash = text.indexOf('#')
  const fragment = hash >= 0 ? text.slice(hash + 1) : text
  // base64url of version (1) + secret (32): 44 characters.
  return /^[A-Za-z0-9_-]{44}$/.test(fragment) ? fragment : null
}

/** Open a link from its fragment; throws when it is not a meeting link. */
export async function openCallLink(fragment: string): Promise<OpenCallLink> {
  const wasm = await loadChatWasm()
  const secret = wasm.callLinkParse(fragment)
  return { secret, fragment, ...wasm.callLinkKeys(secret) }
}

async function ownerSecret(masterKey: Uint8Array, nonce: string): Promise<string> {
  return (await loadChatWasm()).callLinkOwnerSecret(toBase64(masterKey), nonce)
}

async function owned(masterKey: Uint8Array, stored: StoredLink): Promise<OwnedCallLink | null> {
  const wasm = await loadChatWasm()
  const secret = await ownerSecret(masterKey, stored.nonce)
  // A row this account's key does not explain is not shown as a meeting.
  if (wasm.callLinkKeys(secret).roomId !== stored.roomId) return null
  let info: MeetingInfo
  try {
    info = wasm.callLinkOpenInfo(secret, stored.info)
  } catch {
    return null
  }
  const { hostToken } = wasm.callLinkHostToken(toBase64(masterKey), stored.nonce)
  rememberHostToken(stored.roomId, hostToken)
  return {
    roomId: stored.roomId,
    createdAt: stored.createdAt,
    url: callLinkUrl(wasm.callLinkFragment(secret)),
    info,
    waitingRoom: stored.waitingRoom,
    nonce: stored.nonce,
    hostToken,
  }
}

/** Make a meeting and register it with this server. */
export async function createCallLink(
  masterKey: Uint8Array,
  info: MeetingInfo,
  waitingRoom = false,
  /** The room id of one of this account's links that the new one replaces, at once. */
  replaces?: string,
): Promise<OwnedCallLink> {
  const wasm = await loadChatWasm()
  const nonce = wasm.callLinkNonce()
  const secret = await ownerSecret(masterKey, nonce)
  const keys = wasm.callLinkKeys(secret)
  const { data } = await api.post<StoredLink>('/chat/call-links', {
    roomId: keys.roomId,
    nonce,
    accessTokenHash: keys.accessTokenHash,
    info: wasm.callLinkSealInfo(secret, info),
    hostTokenHash: wasm.callLinkHostToken(toBase64(masterKey), nonce).hostTokenHash,
    waitingRoom,
    ...(replaces ? { replaces } : {}),
  })
  const link = await owned(masterKey, data)
  if (!link) throw new Error('the server returned another meeting')
  return link
}

/** The account's meetings, newest first, as any of its devices derives them. */
export async function listCallLinks(masterKey: Uint8Array): Promise<OwnedCallLink[]> {
  const { data } = await api.get<{ links: StoredLink[] }>('/chat/call-links')
  const links = await Promise.all(data.links.map((stored) => owned(masterKey, stored)))
  return links.filter((link): link is OwnedCallLink => link !== null)
}

/** Change what one of the account's meetings is called or when it is. */
export async function updateCallLinkInfo(link: OwnedCallLink, info: MeetingInfo): Promise<OwnedCallLink> {
  const wasm = await loadChatWasm()
  const fragment = callLinkFragmentOf(link.url)
  if (!fragment) throw new Error('not a meeting link')
  const secret = wasm.callLinkParse(fragment)
  await api.put(`/chat/call-links/${link.roomId}/info`, { info: wasm.callLinkSealInfo(secret, info) })
  return { ...link, info }
}

/** Turn one of the account's meetings' waiting room on or off. */
export async function setWaitingRoom(masterKey: Uint8Array, link: OwnedCallLink, enabled: boolean): Promise<OwnedCallLink> {
  const wasm = await loadChatWasm()
  const { hostTokenHash } = wasm.callLinkHostToken(toBase64(masterKey), link.nonce)
  await api.put(`/chat/call-links/${link.roomId}/waiting-room`, { enabled, hostTokenHash })
  return { ...link, waitingRoom: enabled }
}

/**
 * Give a meeting a new link: the same title, time and waiting room under a
 * new secret. The old link stops working and whoever is in the meeting is
 * disconnected, so only the people the new link is sent to come back.
 */
export async function replaceCallLink(masterKey: Uint8Array, link: OwnedCallLink): Promise<OwnedCallLink> {
  // One request: the server deletes the old link in the transaction that
  // stores the new one, so the two never both work.
  const next = await createCallLink(masterKey, link.info, link.waitingRoom, link.roomId)
  forgetHostToken(link.roomId)
  return next
}

/** Delete a meeting: nobody can join through its link any more, and it ends for whoever is in it. */
export async function deleteCallLink(roomId: string): Promise<void> {
  await api.delete(`/chat/call-links/${roomId}`)
  forgetHostToken(roomId)
}

/** The room of the link whose fragment this is. */
export function callLinkRoomId(wasm: Pick<CallLinkCrypto, 'callLinkParse' | 'callLinkKeys'>, fragment: string): string {
  return wasm.callLinkKeys(wasm.callLinkParse(fragment)).roomId
}

/** Why the host refused, for the page to explain. */
export type CallLinkRefusal = 'gone' | 'busy' | 'unavailable' | 'turnedAway' | 'full' | 'removed' | 'endedByHost' | 'locked'

export class CallLinkRefused extends Error {
  constructor(readonly reason: CallLinkRefusal) {
    super(`meeting link refused: ${reason}`)
  }
}

/** The meeting has a waiting room: knock instead of asking for a token. */
export class WaitingRoomRequired extends Error {}
/** The meeting has no waiting room (any more): ask for a token. */
export class NoWaitingRoom extends Error {}
/**
 * The seat this browser presented is no longer its own to use: a host
 * removed it, or the identity is someone else's. A new seat is needed.
 */
export class SeatGone extends Error {
  constructor(readonly removed: boolean) {
    super('this seat in the meeting is gone')
  }
}

/**
 * This browser's place in a meeting: the random identity it joins under,
 * and the secret that binds the identity to this browser. The server mints
 * tokens for an identity only to the holder of its secret, so nobody takes
 * someone else's identity, and a reload comes back as the same participant
 * (still a co-host, if it was one). Kept per tab.
 */
export interface MeetingSeat {
  participantId: string
  seat: string
}

const seatKey = (roomId: string) => `kutup-meeting-seat:${roomId}`

function randomBytes(length: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(length))
}

export function meetingSeat(roomId: string): MeetingSeat {
  try {
    const stored = JSON.parse(sessionStorage.getItem(seatKey(roomId)) ?? 'null') as Partial<MeetingSeat> | null
    if (stored && typeof stored.participantId === 'string' && /^[0-9a-f]{32}$/.test(stored.participantId) && typeof stored.seat === 'string') {
      return { participantId: stored.participantId, seat: stored.seat }
    }
  } catch {
    // Unreadable: a new seat.
  }
  const seat: MeetingSeat = {
    participantId: Array.from(randomBytes(16), (byte) => byte.toString(16).padStart(2, '0')).join(''),
    seat: toBase64(randomBytes(32)),
  }
  try {
    sessionStorage.setItem(seatKey(roomId), JSON.stringify(seat))
  } catch {
    // Private browsing: the seat lasts as long as the page.
  }
  return seat
}

export function forgetMeetingSeat(roomId: string): void {
  try {
    sessionStorage.removeItem(seatKey(roomId))
  } catch {
    // Nothing was kept.
  }
}

/**
 * Ask the host as a holder of the link. No account is involved, so this
 * does not go through the signed-in API client.
 */
async function asHolder<T>(
  path: string,
  body: Record<string, unknown>,
  context: 'token' | 'knock' | 'other' = 'other',
  /** A signed-in joiner's access token, when they chose to show who they are. */
  vouchFor?: string | null,
): Promise<T> {
  let response: Response
  try {
    response = await fetch(`/api/chat/call-links/${path}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...(vouchFor ? { Authorization: `Bearer ${vouchFor}` } : {}) },
      credentials: 'omit',
      body: JSON.stringify(body),
    })
  } catch {
    throw new CallLinkRefused('unavailable')
  }
  if (response.status === 403 && context === 'token') throw new WaitingRoomRequired()
  if (response.status === 409 && context === 'token') throw new SeatGone(false)
  if (response.status === 410 && context === 'token') throw new SeatGone(true)
  if (response.status === 409 && context === 'knock') throw new NoWaitingRoom()
  if (response.status === 423) throw new CallLinkRefused('locked')
  if (response.status === 403) throw new CallLinkRefused('unavailable')
  if (response.status === 404) throw new CallLinkRefused('gone')
  if (response.status === 429) throw new CallLinkRefused(context === 'knock' ? 'full' : 'busy')
  if (!response.ok) throw new CallLinkRefused('unavailable')
  return (response.status === 204 ? undefined : await response.json()) as T
}

/** What the meeting is called and when it is, whether joiners wait to be let in, and whether it is locked. */
export async function fetchMeetingInfo(link: OpenCallLink): Promise<{ info: MeetingInfo; waitingRoom: boolean; locked: boolean }> {
  const { info, waitingRoom, locked } = await asHolder<{ info: string; waitingRoom: boolean; locked: boolean }>('info', {
    roomId: link.roomId,
    accessToken: link.accessToken,
  })
  try {
    return { info: (await loadChatWasm()).callLinkOpenInfo(link.secret, info), waitingRoom, locked }
  } catch {
    // Sealed by someone who does not hold this link: not a meeting to join.
    throw new CallLinkRefused('gone')
  }
}

export interface SfuAccess {
  url: string
  token: string
}

/**
 * An SFU token for the meeting's room, for this browser's seat. With a
 * waiting room only the owner's host token, or a seat already let in, gets
 * one this way; anyone else is told to knock (`WaitingRoomRequired`).
 * `vouchFor` is the joiner's access token when they are signed in and chose
 * to show the others their account.
 */
export function callLinkToken(
  link: OpenCallLink,
  seat: MeetingSeat,
  label: string,
  hostToken?: string | null,
  vouchFor?: string | null,
): Promise<SfuAccess> {
  return asHolder(
    'token',
    { roomId: link.roomId, accessToken: link.accessToken, ...seat, label, ...(hostToken ? { hostToken } : {}) },
    'token',
    vouchFor,
  )
}

/** A knock: what its knocker needs to ask how it went. */
export interface Knock {
  knockId: string
  ticket: string
}

/** Ask to be let into a meeting with a waiting room. */
export function knockMeeting(link: OpenCallLink, seat: MeetingSeat, label: string, vouchFor?: string | null): Promise<Knock> {
  return asHolder('knock', { roomId: link.roomId, accessToken: link.accessToken, ...seat, label }, 'knock', vouchFor)
}

export type KnockStatus = { status: 'waiting' } | { status: 'turnedAway' } | ({ status: 'admitted' } & SfuAccess)

/** How a knock went. Asking also tells the host the knocker is still there. */
export function knockStatus(link: OpenCallLink, knock: Knock): Promise<KnockStatus> {
  return asHolder('knock/status', { roomId: link.roomId, accessToken: link.accessToken, ...knock })
}

/** Someone waiting to be let in, as a host sees them. */
export interface WaitingPerson {
  knockId: string
  /** The name they chose; null when their label does not open. */
  name: string | null
  /** The account the server vouches for, when they are signed in and show it. */
  account: string | null
}

/**
 * How a browser says who it is to the meeting's server: the owner's host
 * token, or (for a co-host, and for anyone asking who the hosts are) its
 * own SFU token.
 */
export type HostProof = { hostToken: string } | { sfuToken: string }

function proven(link: OpenCallLink, proof: HostProof | null): Record<string, string> {
  return { roomId: link.roomId, accessToken: link.accessToken, ...proof }
}

/** Who is waiting, oldest first, for a host. */
export async function waitingPeople(link: OpenCallLink, proof: HostProof): Promise<WaitingPerson[]> {
  const { knocks } = await asHolder<{ knocks: { knockId: string; label: string; account?: string }[] }>('knocks', proven(link, proof))
  const wasm = await loadChatWasm()
  return knocks.map(({ knockId, label, account }) => {
    try {
      return { knockId, name: wasm.callLinkOpenName(link.secret, label), account: account ?? null }
    } catch {
      return { knockId, name: null, account: account ?? null }
    }
  })
}

/** Admit or turn away one person waiting, as a host. */
export function decideKnock(link: OpenCallLink, proof: HostProof, knockId: string, admit: boolean): Promise<void> {
  return asHolder('knocks/decide', { ...proven(link, proof), knockId, admit })
}

export type MeetingRole = 'owner' | 'coHost'

/** Who hosts a meeting that is on, and how it is set. */
export interface MeetingState {
  /** This browser's own role. */
  me: MeetingRole | null
  /** The hosts, by SFU identity. */
  roles: Map<string, MeetingRole>
  locked: boolean
  waitingRoom: boolean
  /**
   * No host is in the meeting right now. If it stays so for a short while,
   * the server makes its longest-present participant a co-host: ask again.
   */
  noHost: boolean
}

export async function meetingRoles(link: OpenCallLink, proof: HostProof | null): Promise<MeetingState> {
  const { me, roles, locked, waitingRoom, noHost } = await asHolder<{
    me?: MeetingRole
    roles: { participantId: string; role: MeetingRole }[]
    locked: boolean
    waitingRoom: boolean
    noHost: boolean
  }>('roles', proven(link, proof))
  return { me: me ?? null, roles: new Map(roles.map(({ participantId, role }) => [participantId, role])), locked, waitingRoom, noHost }
}

/** As the owner: make a participant a co-host, or stop them being one. */
export function setCoHost(link: OpenCallLink, hostToken: string, participantId: string, enabled: boolean): Promise<void> {
  return asHolder('co-hosts', { roomId: link.roomId, accessToken: link.accessToken, hostToken, participantId, enabled })
}

/**
 * As a host: remove a participant. The waiting room is turned on with it,
 * so they cannot come straight back in with the link.
 */
export function removeParticipant(link: OpenCallLink, proof: HostProof, participantId: string): Promise<void> {
  return asHolder('participants/remove', { ...proven(link, proof), participantId })
}

/** As the owner: end the meeting for everyone in it. */
export function endMeeting(link: OpenCallLink, hostToken: string): Promise<void> {
  return asHolder('end', { roomId: link.roomId, accessToken: link.accessToken, hostToken })
}

/** As a host: mute a participant's microphone, or (with no one named) everyone's who is not a host. */
export function muteParticipant(link: OpenCallLink, proof: HostProof, participantId: string | null): Promise<void> {
  return asHolder('participants/mute', { ...proven(link, proof), ...(participantId ? { participantId } : {}) })
}

/** As a host: stop a participant sharing their screen, or allow it again. */
export function setScreenShare(link: OpenCallLink, proof: HostProof, participantId: string, allowed: boolean): Promise<void> {
  return asHolder('participants/screen', { ...proven(link, proof), participantId, allowed })
}

/** As a host: lock the meeting (nobody new comes in) or unlock it. */
export function lockMeeting(link: OpenCallLink, proof: HostProof, locked: boolean): Promise<void> {
  return asHolder('lock', { ...proven(link, proof), locked })
}
