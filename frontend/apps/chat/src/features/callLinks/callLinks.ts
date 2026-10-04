import type { CallLinkInfo, CallLinkKeys } from '@kutup/chat-core/types'
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
export async function createCallLink(masterKey: Uint8Array, info: MeetingInfo, waitingRoom = false): Promise<OwnedCallLink> {
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

/** Delete a meeting: nobody can join through its link any more. */
export async function deleteCallLink(roomId: string): Promise<void> {
  await api.delete(`/chat/call-links/${roomId}`)
  forgetHostToken(roomId)
}

/** Why the host refused, for the page to explain. */
export type CallLinkRefusal = 'gone' | 'busy' | 'unavailable' | 'turnedAway' | 'full' | 'removed' | 'endedByHost'

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
 * Ask the host as a holder of the link. No account is involved, so this
 * does not go through the signed-in API client.
 */
async function asHolder<T>(path: string, body: Record<string, unknown>, context: 'token' | 'knock' | 'other' = 'other'): Promise<T> {
  let response: Response
  try {
    response = await fetch(`/api/chat/call-links/${path}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'omit',
      body: JSON.stringify(body),
    })
  } catch {
    throw new CallLinkRefused('unavailable')
  }
  if (response.status === 403 && context === 'token') throw new WaitingRoomRequired()
  if (response.status === 409 && context === 'knock') throw new NoWaitingRoom()
  if (response.status === 403) throw new CallLinkRefused('unavailable')
  if (response.status === 404) throw new CallLinkRefused('gone')
  if (response.status === 429) throw new CallLinkRefused(context === 'knock' ? 'full' : 'busy')
  if (!response.ok) throw new CallLinkRefused('unavailable')
  return (response.status === 204 ? undefined : await response.json()) as T
}

/** What the meeting is called and when it is, and whether joiners wait to be let in. */
export async function fetchMeetingInfo(link: OpenCallLink): Promise<{ info: MeetingInfo; waitingRoom: boolean }> {
  const { info, waitingRoom } = await asHolder<{ info: string; waitingRoom: boolean }>('info', {
    roomId: link.roomId,
    accessToken: link.accessToken,
  })
  try {
    return { info: (await loadChatWasm()).callLinkOpenInfo(link.secret, info), waitingRoom }
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
 * An SFU token for the meeting's room. With a waiting room only the owner's
 * host token gets one this way; anyone else is told to knock
 * (`WaitingRoomRequired`).
 */
export function callLinkToken(link: OpenCallLink, participantId: string, label: string, hostToken?: string | null): Promise<SfuAccess> {
  return asHolder(
    'token',
    { roomId: link.roomId, accessToken: link.accessToken, participantId, label, ...(hostToken ? { hostToken } : {}) },
    'token',
  )
}

/** A knock: what its knocker needs to ask how it went. */
export interface Knock {
  knockId: string
  ticket: string
}

/** Ask to be let into a meeting with a waiting room. */
export function knockMeeting(link: OpenCallLink, participantId: string, label: string): Promise<Knock> {
  return asHolder('knock', { roomId: link.roomId, accessToken: link.accessToken, participantId, label }, 'knock')
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
  const { knocks } = await asHolder<{ knocks: { knockId: string; label: string }[] }>('knocks', proven(link, proof))
  const wasm = await loadChatWasm()
  return knocks.map(({ knockId, label }) => {
    try {
      return { knockId, name: wasm.callLinkOpenName(link.secret, label) }
    } catch {
      return { knockId, name: null }
    }
  })
}

/** Admit or turn away one person waiting, as a host. */
export function decideKnock(link: OpenCallLink, proof: HostProof, knockId: string, admit: boolean): Promise<void> {
  return asHolder('knocks/decide', { ...proven(link, proof), knockId, admit })
}

export type MeetingRole = 'owner' | 'coHost'

/** The meeting's hosts by SFU identity, and this browser's own role. */
export async function meetingRoles(link: OpenCallLink, proof: HostProof | null): Promise<{ me: MeetingRole | null; roles: Map<string, MeetingRole> }> {
  const { me, roles } = await asHolder<{ me?: MeetingRole; roles: { participantId: string; role: MeetingRole }[] }>(
    'roles',
    proven(link, proof),
  )
  return { me: me ?? null, roles: new Map(roles.map(({ participantId, role }) => [participantId, role])) }
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
