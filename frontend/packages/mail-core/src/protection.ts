import { useQuery } from '@tanstack/react-query'
import { fromBase64, inspectExternalMailKey } from '@kutup/crypto'
import type { ContactKey } from '@kutup/contacts-core/model'
import { outsideKey, type OutsideKey } from './keys'

// How mail to one recipient is protected (docs/plans/mail.md, C3), decided
// as Proton decides it: Kutup addresses end to end with their key list; an
// outside address with a key the person pinned to the contact, encrypted
// to it; else with a key found through WKD, Proton or keys.openpgp.org;
// else in clear on the way (and zero-access in Sent).

export type Protection =
  | { kind: 'kutup' }
  | { kind: 'pinned'; publicKey: string; fingerprint: string }
  | { kind: 'found'; publicKey: string; fingerprint: string; source: OutsideKey['source'] }
  /** A pinned key that can no longer be used: sending waits until it is updated or removed. */
  | { kind: 'pinnedUnusable'; fingerprint: string }
  | { kind: 'none' }

/** Whether mail to the recipient is encrypted to an OpenPGP key. */
export function pgpKey(protection: Protection): string | null {
  return protection.kind === 'pinned' || protection.kind === 'found' ? protection.publicKey : null
}

/** A pinned key that cannot be used any more (expired, revoked). */
export class PinnedKeyUnusable extends Error {
  constructor(readonly address: string) {
    super(`the key pinned for ${address} can no longer be used`)
  }
}

/** The key lookup for an outside address failed (not: found nothing). */
export class KeyLookupFailed extends Error {
  constructor(readonly address: string) {
    super(`could not look up a key for ${address}`)
  }
}

export async function protectionFor(address: string, domain: string, pinned: ContactKey | undefined): Promise<Protection> {
  const lower = address.toLowerCase()
  if (lower.endsWith(`@${domain}`)) return { kind: 'kutup' }
  if (pinned) {
    // The person chose not to encrypt to this address.
    if (!pinned.encrypt) return { kind: 'none' }
    try {
      const info = await inspectExternalMailKey(fromBase64(pinned.publicKey), lower)
      return { kind: 'pinned', publicKey: info.publicKey, fingerprint: info.fingerprint }
    } catch {
      return { kind: 'pinnedUnusable', fingerprint: pinned.fingerprint }
    }
  }
  const found = await outsideKey(lower).catch(() => {
    throw new KeyLookupFailed(lower)
  })
  return found ? { kind: 'found', publicKey: found.publicKey, fingerprint: found.fingerprint, source: found.source } : { kind: 'none' }
}

/** How mail to `address` would be protected; looked up while the person writes. */
export function useProtection(address: string, domain: string, pinned: ContactKey | undefined, enabled: boolean) {
  return useQuery({
    queryKey: ['mail', 'protection', address.toLowerCase(), pinned?.fingerprint ?? null, pinned?.encrypt ?? null],
    enabled,
    staleTime: 15 * 60_000,
    retry: false,
    queryFn: () => protectionFor(address, domain, pinned),
  })
}
