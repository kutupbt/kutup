import { useQuery } from '@tanstack/react-query'
import { fromBase64, inspectExternalMailKey } from '@kutup/crypto'
import type { ContactEmailPgp, ContactKey } from '@kutup/contacts-core/model'
import { AddressDisabled, addressKeys, GroupAddress, NoKutupAddress, outsideKey, type OutsideKey } from './keys'

// How mail to one recipient is protected (docs/plans/mail.md, C3;
// docs/plans/contact-keys.md), decided as Proton decides it: Kutup
// addresses end to end with their key list; an outside address with keys
// the person trusted in Contacts, encrypted to the first of them that can
// encrypt; else with a key found through WKD, Proton or keys.openpgp.org,
// unless the address says not to; else in clear on the way (and
// zero-access in Sent).

export type Protection =
  /** `encryptionDisabled`: the address forwards outside, so its mail goes readable and is sealed when it arrives. */
  | { kind: 'kutup'; encryptionDisabled?: boolean }
  | { kind: 'pinned'; publicKey: string; fingerprint: string }
  | { kind: 'found'; publicKey: string; fingerprint: string; source: OutsideKey['source'] }
  /** Trusted keys, none of which can be used any more: sending waits until one is trusted again or they are removed. */
  | { kind: 'pinnedUnusable'; fingerprint: string }
  /** Its owner disabled the address: nothing can be sent to it. */
  | { kind: 'disabled' }
  /**
   * This server says an address on another domain is a Kutup user's (a
   * custom domain it holds) while Contacts trust other keys for it: nothing
   * is sent until the person settles it, never the server's word over theirs.
   */
  | { kind: 'pinnedConflict'; fingerprint: string }
  | { kind: 'none' }

/** What Contacts say about an outside address (mail-core `PinnedAddress`). */
export interface Pinned {
  keys: ContactKey[]
  pgp: ContactEmailPgp
}

/** Whether mail to the recipient is encrypted to an OpenPGP key. */
export function pgpKey(protection: Protection): string | null {
  return protection.kind === 'pinned' || protection.kind === 'found' ? protection.publicKey : null
}

/** Trusted keys that cannot be used any more (expired, revoked). */
export class PinnedKeyUnusable extends Error {
  constructor(readonly address: string) {
    super(`the keys trusted for ${address} can no longer be used`)
  }
}

/** A server-held address whose Contacts trust other keys (`pinnedConflict`). */
export class PinnedKeyConflict extends Error {
  constructor(readonly address: string) {
    super(`this server holds ${address}, but the keys trusted for it are others`)
  }
}

/** The key lookup for an outside address failed (not: found nothing). */
export class KeyLookupFailed extends Error {
  constructor(readonly address: string) {
    super(`could not look up a key for ${address}`)
  }
}

export async function protectionFor(address: string, domain: string, pinned: Pinned | undefined): Promise<Protection> {
  const lower = address.toLowerCase()
  if (lower.endsWith(`@${domain}`)) {
    // Whether its owner's key list says not to encrypt; a lookup that fails
    // here is reported when sending.
    const keys = await addressKeys(lower).catch((error: unknown) => (error instanceof AddressDisabled ? 'disabled' : null))
    if (keys === 'disabled') return { kind: 'disabled' }
    return keys?.encryptionDisabled ? { kind: 'kutup', encryptionDisabled: true } : { kind: 'kutup' }
  }
  // Another address this server holds (a custom domain): a Kutup address too,
  // unless Contacts trust other keys for it.
  try {
    const keys = await addressKeys(lower)
    const trusted = pinned?.keys ?? []
    if (trusted.length > 0) return { kind: 'pinnedConflict', fingerprint: trusted[0].fingerprint }
    return keys.encryptionDisabled ? { kind: 'kutup', encryptionDisabled: true } : { kind: 'kutup' }
  } catch (error) {
    if (error instanceof AddressDisabled) return { kind: 'disabled' }
    if (!(error instanceof NoKutupAddress) && !(error instanceof GroupAddress)) throw new KeyLookupFailed(lower)
  }
  // The person chose not to encrypt to this address.
  if (pinned?.pgp.encrypt === false) return { kind: 'none' }
  const trusted = pinned?.keys ?? []
  if (trusted.length > 0) {
    // The first trusted key that can still encrypt is used for sending.
    for (const key of trusted) {
      try {
        const info = await inspectExternalMailKey(fromBase64(key.publicKey), lower)
        return { kind: 'pinned', publicKey: info.publicKey, fingerprint: info.fingerprint }
      } catch {
        // Expired or revoked: the next one.
      }
    }
    return { kind: 'pinnedUnusable', fingerprint: trusted[0].fingerprint }
  }
  const found = await outsideKey(lower).catch(() => {
    throw new KeyLookupFailed(lower)
  })
  return found ? { kind: 'found', publicKey: found.publicKey, fingerprint: found.fingerprint, source: found.source } : { kind: 'none' }
}

/** How mail to `address` would be protected; looked up while the person writes. */
export function useProtection(address: string, domain: string, pinned: Pinned | undefined, enabled: boolean) {
  return useQuery({
    queryKey: ['mail', 'protection', address.toLowerCase(), pinned?.keys.map((k) => k.fingerprint).join(',') ?? null, pinned?.pgp.encrypt ?? null],
    enabled,
    staleTime: 15 * 60_000,
    retry: false,
    queryFn: () => protectionFor(address, domain, pinned),
  })
}
