import type { CallLinkKeys } from '@kutup/chat-core/types'
import { loadChatWasm } from '@kutup/chat-core/wasm'
import { toBase64 } from '@kutup/crypto'
import api from '@kutup/session/client'

// Call links (docs/chat-calls.md): a call anyone holding the link can join,
// with or without an account. Everything about a link comes from the secret
// in its URL fragment, which no server sees. The Rust engine owns the
// derivations; this is the browser's side of making, listing, opening and
// joining one.

/** A link someone holds: its secret and what derives from it. */
export interface OpenCallLink extends CallLinkKeys {
  /** Standard base64. */
  secret: string
}

/** One of the account's own links. */
export interface OwnedCallLink {
  roomId: string
  createdAt: string
  url: string
}

interface StoredLink {
  roomId: string
  nonce: string
  createdAt: string
}

/** Where a link opens: this server's chat app, the secret in the fragment. */
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

/** Open a link from its fragment; throws when it is not a call link. */
export async function openCallLink(fragment: string): Promise<OpenCallLink> {
  const wasm = await loadChatWasm()
  const secret = wasm.callLinkParse(fragment)
  return { secret, ...wasm.callLinkKeys(secret) }
}

async function owned(masterKey: Uint8Array, stored: StoredLink): Promise<OwnedCallLink | null> {
  const wasm = await loadChatWasm()
  const secret = wasm.callLinkOwnerSecret(toBase64(masterKey), stored.nonce)
  // A row this account's key does not explain is not shown as a link.
  if (wasm.callLinkKeys(secret).roomId !== stored.roomId) return null
  return { roomId: stored.roomId, createdAt: stored.createdAt, url: callLinkUrl(wasm.callLinkFragment(secret)) }
}

/** Make a link and register it with this server. */
export async function createCallLink(masterKey: Uint8Array): Promise<OwnedCallLink> {
  const wasm = await loadChatWasm()
  const nonce = wasm.callLinkNonce()
  const keys = wasm.callLinkKeys(wasm.callLinkOwnerSecret(toBase64(masterKey), nonce))
  const { data } = await api.post<StoredLink>('/chat/call-links', {
    roomId: keys.roomId,
    nonce,
    accessTokenHash: keys.accessTokenHash,
  })
  const link = await owned(masterKey, data)
  if (!link) throw new Error('the server returned another link')
  return link
}

/** The account's links, newest first, as any of its devices derives them. */
export async function listCallLinks(masterKey: Uint8Array): Promise<OwnedCallLink[]> {
  const { data } = await api.get<{ links: StoredLink[] }>('/chat/call-links')
  const links = await Promise.all(data.links.map((stored) => owned(masterKey, stored)))
  return links.filter((link): link is OwnedCallLink => link !== null)
}

/** Delete a link: nobody can join through it any more. */
export async function deleteCallLink(roomId: string): Promise<void> {
  await api.delete(`/chat/call-links/${roomId}`)
}

/** Why a join was refused, for the page to explain. */
export type CallLinkRefusal = 'gone' | 'busy' | 'unavailable'

export class CallLinkRefused extends Error {
  constructor(readonly reason: CallLinkRefusal) {
    super(`call link refused: ${reason}`)
  }
}

/**
 * An SFU token for the link's room. No account is involved, so this does not
 * go through the signed-in API client.
 */
export async function callLinkToken(
  link: OpenCallLink,
  participantId: string,
  label: string,
): Promise<{ url: string; token: string }> {
  let response: Response
  try {
    response = await fetch('/api/chat/call-links/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'omit',
      body: JSON.stringify({ roomId: link.roomId, accessToken: link.accessToken, participantId, label }),
    })
  } catch {
    throw new CallLinkRefused('unavailable')
  }
  if (response.status === 404) throw new CallLinkRefused('gone')
  if (response.status === 429) throw new CallLinkRefused('busy')
  if (!response.ok) throw new CallLinkRefused('unavailable')
  return (await response.json()) as { url: string; token: string }
}
