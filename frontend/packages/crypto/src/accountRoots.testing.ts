// Roots for tests (docs/plans/identity-root.md): every root the given bytes,
// so an identity derived from them is the one tests derived from the same
// master key before the roots existed. Never used by the apps.

import type { AccountRoots, CallLinkRoot, DriveRoot, IdentityRoot, ObjectIdKey, PseudonymRoot } from './accountRoots'
import { toBase64 } from './base64'

/** Roots whose bytes are `key` (32 bytes, or one byte repeated). */
export function testRoots(key: Uint8Array | number): AccountRoots {
  const root = toBase64(typeof key === 'number' ? new Uint8Array(32).fill(key) : key)
  return {
    identityGeneration: 1,
    identityRoot: root as IdentityRoot,
    driveGeneration: 1,
    driveRoot: root as DriveRoot,
    pseudonymRoot: root as PseudonymRoot,
    callLinkRoot: root as CallLinkRoot,
    objectIdKey: root as ObjectIdKey,
  }
}

/** A vector's key bytes (base64) as an identity root: the derivation is the same. */
export function asIdentityRoot(base64: string): IdentityRoot {
  return base64 as IdentityRoot
}
