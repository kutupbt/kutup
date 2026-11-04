// Profiles (docs/plans/unified-profile.md) from the crypto WASM: what Drive,
// Maps, Photos, Office and the Account app need of the account's and other
// people's profiles, without loading the Chat runtime
// (docs/plans/chat-crypto-move.md). Same calls as the Chat WASM's.

import { getCryptoWasm } from './rustWasm'

export interface AccountProfileView {
  displayName: string
  about?: string
  /** Standard base64. */
  avatar?: string
  avatarContentType?: string
  revision: string
}

export interface AccountProfileInput {
  displayName: string
  about?: string
  avatar?: string
  avatarContentType?: string
}

/** Where someone's profile is, from their profile key. */
export interface ProfileLookup {
  /** Standard base64 of the 32-byte profile key. */
  key: string
  version: string
  /** Standard base64; the `x-kutup-profile-access-key` header. */
  accessKey: string
}

/** The account's own profile key (to give the people it shares with), from its sealed profile. */
export async function accountProfileKey(masterKey: Uint8Array, current: unknown, account: string, binding: string): Promise<ProfileLookup> {
  return (await getCryptoWasm()).accountProfileKey(masterKey, current, account, binding)
}

/** Where to fetch someone's profile, from their profile key (standard base64). */
export async function profileLookup(key: string): Promise<ProfileLookup> {
  return (await getCryptoWasm()).profileLookup(key)
}

/** Someone's fetched profile, opened with their profile key. */
export async function profileOpenPeer(peer: string, encrypted: unknown, key: string): Promise<AccountProfileView> {
  return (await getCryptoWasm()).profileOpenPeer(peer, encrypted, key)
}

/** The account's own profile, opened from the master key. */
export async function accountProfileOpen(masterKey: Uint8Array, current: unknown, account: string, binding: string): Promise<AccountProfileView> {
  return (await getCryptoWasm()).accountProfileOpen(masterKey, current, account, binding)
}

/** The account's next profile revision, sealed from the master key: the exact upload. */
export async function accountProfileSeal(
  masterKey: Uint8Array,
  current: unknown | null,
  update: AccountProfileInput,
  account: string,
  binding: string,
): Promise<unknown> {
  return (await getCryptoWasm()).accountProfileSeal(masterKey, current, update, account, binding)
}
