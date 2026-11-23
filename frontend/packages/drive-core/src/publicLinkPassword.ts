// A password-protected public link, as its viewer opens it
// (docs/plans/drive-link-password.md). The fragment holds the link's secret;
// the password and the secret derive a proof (sent with the reads that show
// what the link holds) and the key that opens the link key. Shared by the
// Drive, Office and Photos link pages.

import {
  deriveLinkPasswordV1,
  openLinkPasswordKeyV1,
  type LinkPasswordParams,
} from '@kutup/crypto/publicLink'
import api from '@kutup/session/client'

/** The header the server checks a link's proof in. */
export const LINK_PROOF_HEADER = 'X-Kutup-Link-Proof'

/** Why a protected link did not open. */
export type LinkPasswordFailure = 'passwordRequired' | 'passwordWrong' | 'passwordLocked'

/** The server's answer to a read without, or with a wrong, proof; null for any other error. */
export function linkPasswordFailure(error: unknown): LinkPasswordFailure | null {
  const code = (error as { response?: { data?: { code?: unknown } } }).response?.data?.code
  if (code === 'linkPassword') return 'passwordRequired'
  if (code === 'linkPasswordWrong') return 'passwordWrong'
  if (code === 'linkPasswordLocked') return 'passwordLocked'
  return null
}

interface Unlocked {
  proof: string
  wrapKey: Uint8Array
}

// What the password derived, per link token, for this page's later reads.
const unlocked = new Map<string, Unlocked>()

/** Derives a link's proof and wrap key from its secret and `password`, for the reads that follow. */
export async function unlockLink(token: string, secret: Uint8Array, password: string): Promise<void> {
  const { data } = await api.get<LinkPasswordParams>(`/drive/public-links/${encodeURIComponent(token)}/password`)
  unlocked.set(token, await deriveLinkPasswordV1(secret, password, data))
}

// Every read of an unlocked link through the API client carries its proof:
// the listings, a note's state, a whiteboard's pictures, thumbnails. The
// content itself is read by the block reader, which takes `linkHeaders`.
const LINK_PATH = /\/drive\/public-links\/([^/?#]+)(?:[/?#]|$)/
api.interceptors.request.use((config) => {
  const token = LINK_PATH.exec(config.url ?? '')?.[1]
  const entry = token ? unlocked.get(decodeURIComponent(token)) : undefined
  if (entry && !config.headers.has(LINK_PROOF_HEADER)) config.headers.set(LINK_PROOF_HEADER, entry.proof)
  return config
})

/** How long until a locked link takes passwords again, in seconds (`Retry-After`); null when not said. */
export function linkRetryAfter(error: unknown): number | null {
  const response = (error as { response?: { headers?: Record<string, unknown>; data?: { retryAfterSeconds?: unknown } } }).response
  const header = Number(response?.headers?.['retry-after'])
  if (Number.isFinite(header) && header > 0) return header
  const body = Number(response?.data?.retryAfterSeconds)
  return Number.isFinite(body) && body > 0 ? body : null
}

/** Forgets a link's password (it was wrong, or changed). */
export function forgetLink(token: string): void {
  unlocked.delete(token)
}

/** The headers a link's gated reads carry: its proof, once unlocked. */
export function linkHeaders(token: string): Record<string, string> {
  const entry = unlocked.get(token)
  return entry ? { [LINK_PROOF_HEADER]: entry.proof } : {}
}

/** What the link's share answer says of its key. */
export interface LinkKeyInfo {
  id: string
  ownerAccountId: string
  keyRevision: number
  passwordLinkKeyEnvelope?: string
}

/**
 * The key the link's target is sealed under: the fragment's secret, or for a
 * protected link the link key the password opens.
 */
export async function linkKeyOf(token: string, share: LinkKeyInfo, secret: Uint8Array): Promise<Uint8Array> {
  if (!share.passwordLinkKeyEnvelope) return secret
  const entry = unlocked.get(token)
  if (!entry) throw new Error('the link is not unlocked')
  return openLinkPasswordKeyV1(share.passwordLinkKeyEnvelope, entry.wrapKey, {
    linkId: share.id,
    ownerAccountId: share.ownerAccountId,
    keyRevision: share.keyRevision,
  })
}
