import type { CallLinkInfo, CallLinkKeys } from '@kutup/chat-core/types'
import { loadChatWasm } from '@kutup/chat-core/wasm'
import { toBase64 } from '@kutup/crypto'
import api from '@kutup/session/client'

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
}

interface StoredLink {
  roomId: string
  nonce: string
  info: string
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
  return { roomId: stored.roomId, createdAt: stored.createdAt, url: callLinkUrl(wasm.callLinkFragment(secret)), info }
}

/** Make a meeting and register it with this server. */
export async function createCallLink(masterKey: Uint8Array, info: MeetingInfo): Promise<OwnedCallLink> {
  const wasm = await loadChatWasm()
  const nonce = wasm.callLinkNonce()
  const secret = await ownerSecret(masterKey, nonce)
  const keys = wasm.callLinkKeys(secret)
  const { data } = await api.post<StoredLink>('/chat/call-links', {
    roomId: keys.roomId,
    nonce,
    accessTokenHash: keys.accessTokenHash,
    info: wasm.callLinkSealInfo(secret, info),
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

/** Delete a meeting: nobody can join through its link any more. */
export async function deleteCallLink(roomId: string): Promise<void> {
  await api.delete(`/chat/call-links/${roomId}`)
}

/** Why the host refused, for the page to explain. */
export type CallLinkRefusal = 'gone' | 'busy' | 'unavailable'

export class CallLinkRefused extends Error {
  constructor(readonly reason: CallLinkRefusal) {
    super(`meeting link refused: ${reason}`)
  }
}

/**
 * Ask the host as a holder of the link. No account is involved, so this
 * does not go through the signed-in API client.
 */
async function asHolder<T>(path: string, body: Record<string, string>): Promise<T> {
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
  if (response.status === 404) throw new CallLinkRefused('gone')
  if (response.status === 429) throw new CallLinkRefused('busy')
  if (!response.ok) throw new CallLinkRefused('unavailable')
  return (await response.json()) as T
}

/** What the meeting is called and when it is, as its owner set them. */
export async function fetchMeetingInfo(link: OpenCallLink): Promise<MeetingInfo> {
  const { info } = await asHolder<{ info: string }>('info', { roomId: link.roomId, accessToken: link.accessToken })
  try {
    return (await loadChatWasm()).callLinkOpenInfo(link.secret, info)
  } catch {
    // Sealed by someone who does not hold this link: not a meeting to join.
    throw new CallLinkRefused('gone')
  }
}

/** An SFU token for the meeting's room. */
export function callLinkToken(link: OpenCallLink, participantId: string, label: string): Promise<{ url: string; token: string }> {
  return asHolder('token', { roomId: link.roomId, accessToken: link.accessToken, participantId, label })
}
