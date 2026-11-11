// Who signed a revision (docs/plans/drive-block-format.md §2, "The
// signature"). Every block-format revision's manifest is signed with its
// uploader's Drive signing key and names the uploader: an account id and
// the account's incarnation (the hash of its authority key). Opening a
// revision hands that signature here (`setManifestSignerCheck`), and it is
// checked against the identity pins (docs/plans/drive-identity-pins.md):
// the key the named account's pinned authority vouches for must have made
// it. As Drive's other signatures, a signature that doesn't hold warns; it
// never blocks the open.

import { deriveAccountIdentityKeys, setManifestSignerCheck, toBase64, type ManifestSignature } from '@kutup/crypto'
import { incarnationIdOfAuthority, pinAddress } from '@kutup/crypto/identityPins'
import { getSession } from '@kutup/session/store'
import { driveIdentityOf, type DriveIdentity } from './identity'
import { boundSigningKeyOf, pinsOfAccountId } from './identityPins'

/**
 * What the pins say of a revision's signature:
 * - `verified`: made by the key the named account's pinned authority (this
 *   incarnation) vouches for, or by this account's own key;
 * - `forged`: it names an account and incarnation whose key is known, and
 *   that key did not make it: someone with the file's key (a co-editor, or
 *   whoever they gave it to) wrote this under another person's name;
 * - `changed`: it names a pinned account under another incarnation than the
 *   pinned one, and not one the user accepted a change from: the account
 *   was reset (not accepted yet), or the name is being passed off;
 * - `unknown`: can't be told (an account never met, an incarnation left
 *   behind whose key is no longer published, a lookup that failed).
 *
 * `name`: the address the pin list knows the named account at.
 */
export type ManifestSignerVerdict =
  | { kind: 'verified' }
  | { kind: 'forged'; name: string | null }
  | { kind: 'changed'; name: string | null }
  | { kind: 'unknown' }

export async function manifestSignerVerdict(me: DriveIdentity, signature: ManifestSignature): Promise<ManifestSignerVerdict> {
  if (signature.accountId === me.userId) {
    // An earlier incarnation of this account: its key went with the reset.
    if (signature.incarnationId !== me.incarnationId) return { kind: 'unknown' }
    const own = await deriveAccountIdentityKeys(toBase64(me.masterKey))
    return signature.signedBy(own.driveSigningPublicKey) ? { kind: 'verified' } : { kind: 'forged', name: me.account }
  }
  let pins
  try {
    pins = await pinsOfAccountId(me, signature.accountId)
  } catch {
    return { kind: 'unknown' }
  }
  if (pins.length === 0) return { kind: 'unknown' }
  for (const pin of pins) {
    const incarnation = await incarnationIdOfAuthority(pin.authorityPublicKey).catch(() => null)
    if (incarnation !== signature.incarnationId) continue
    const key = await boundSigningKeyOf(me, pin)
    if (!key) return { kind: 'unknown' }
    return signature.signedBy(key) ? { kind: 'verified' } : { kind: 'forged', name: pinAddress(pin) ?? null }
  }
  // No pin of this account is at the incarnation named. One the user
  // accepted a change from is only old content; any other is a change.
  if (pins.some((pin) => pin.replaced?.includes(signature.incarnationId))) return { kind: 'unknown' }
  return { kind: 'changed', name: pinAddress(pins[0]) ?? null }
}

/** A signature to warn about: whose name it carries, and of which revision. */
export interface ManifestSignerWarning {
  kind: 'forged' | 'changed'
  name: string | null
  fileId: string
  revisionId: string
}

/**
 * Checks every revision this page opens against the pins, and tells `warn`
 * about each signature in doubt, once per revision. Nothing is checked
 * while signed out (a public link's reader has no pins). Returns the undo.
 */
export function watchManifestSigners(warn: (warning: ManifestSignerWarning) => void): () => void {
  const told = new Set<string>()
  const check = async (signature: ManifestSignature) => {
    const session = getSession()
    if (!session) return
    const verdict = await manifestSignerVerdict(await driveIdentityOf(session), signature)
    if (verdict.kind !== 'forged' && verdict.kind !== 'changed') return
    const key = `${signature.fileId}/${signature.revisionId}/${verdict.kind}`
    if (told.has(key)) return
    told.add(key)
    warn({ kind: verdict.kind, name: verdict.name, fileId: signature.fileId, revisionId: signature.revisionId })
  }
  setManifestSignerCheck(check)
  return () => setManifestSignerCheck(null)
}
