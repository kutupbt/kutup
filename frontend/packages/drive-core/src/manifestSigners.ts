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
import { claimedAuthorOf, type ClaimedAuthor } from './revisionAuthors'

export { claimRevisionAuthor, versionAuthor, type ClaimedAuthor } from './revisionAuthors'

/**
 * What the pins say of a revision's signature:
 * - `verified`: made by the key the named account's pinned authority (this
 *   incarnation) vouches for, or by this account's own key, and the account
 *   is the author the UI shows for the revision (when it shows one);
 * - `forged`: it names an account and incarnation whose key is known, and
 *   that key did not make it: someone with the file's key (a co-editor, or
 *   whoever they gave it to) wrote this under another person's name;
 * - `changed`: it names a pinned account (or this one) under another
 *   incarnation than the pinned (current) one, and not one the user
 *   accepted a change from: the account was reset (not accepted yet), or
 *   the name is being passed off;
 * - `authorMismatch`: a good signature, but by another account than the
 *   author the UI shows for the revision (the server's history names
 *   someone else): `name` is the signer, `claimed` the author shown;
 * - `unknown`: can't be told (an account never met, an incarnation left
 *   behind whose key is no longer published, a lookup that failed).
 *
 * `name`: the address the pin list knows the named account at.
 */
export type ManifestSignerVerdict =
  | { kind: 'verified' }
  | { kind: 'forged'; name: string | null }
  | { kind: 'changed'; name: string | null }
  | { kind: 'authorMismatch'; name: string | null; claimed: string | null }
  | { kind: 'unknown' }

/** A signer the pins (or this account) vouch for. */
interface Signer {
  accountId: string
  address: string | null
}

export async function manifestSignerVerdict(
  me: DriveIdentity,
  signature: ManifestSignature,
  claimed?: ClaimedAuthor | null,
): Promise<ManifestSignerVerdict> {
  const verdict = await signerOf(me, signature)
  if (!('signer' in verdict)) return verdict
  return claimed && !isClaimed(verdict.signer, claimed)
    ? { kind: 'authorMismatch', name: verdict.signer.address, claimed: claimedName(claimed) }
    : { kind: 'verified' }
}

function sameAddress(a: string, b: string): boolean {
  return a.trim().toLowerCase() === b.trim().toLowerCase()
}

/** Whether the signer is the author shown. An address can only be compared when the signer's is known. */
function isClaimed(signer: Signer, claimed: ClaimedAuthor): boolean {
  if ('accountId' in claimed) return signer.accountId === claimed.accountId
  return signer.address === null || sameAddress(signer.address, claimed.address)
}

function claimedName(claimed: ClaimedAuthor): string | null {
  return 'address' in claimed ? claimed.address : null
}

async function signerOf(me: DriveIdentity, signature: ManifestSignature): Promise<{ signer: Signer } | Exclude<ManifestSignerVerdict, { kind: 'verified' | 'authorMismatch' }>> {
  if (signature.accountId === me.userId) {
    // This account under another incarnation than its own now: its keys
    // went with a reset this device didn't make, or the name is passed off.
    if (signature.incarnationId !== me.incarnationId) return { kind: 'changed', name: me.account }
    const own = await deriveAccountIdentityKeys(toBase64(me.masterKey))
    return (await signature.signedBy(own.driveSigningPublicKey))
      ? { signer: { accountId: me.userId, address: me.account } }
      : { kind: 'forged', name: me.account }
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
    return (await signature.signedBy(key))
      ? { signer: { accountId: pin.account.accountId, address: pinAddress(pin) ?? null } }
      : { kind: 'forged', name: pinAddress(pin) ?? null }
  }
  // No pin of this account is at the incarnation named. One the user
  // accepted a change from is only old content; any other is a change.
  if (pins.some((pin) => pin.replaced?.includes(signature.incarnationId))) return { kind: 'unknown' }
  return { kind: 'changed', name: pinAddress(pins[0]) ?? null }
}

/** A signature to warn about: whose name it carries, and of which revision. */
export interface ManifestSignerWarning {
  kind: 'forged' | 'changed' | 'authorMismatch'
  name: string | null
  /** `authorMismatch`: the author the UI shows, when it is an address. */
  claimed?: string | null
  fileId: string
  revisionId: string
}

/**
 * Checks every revision this page opens against the pins (and against the
 * author the UI shows for it, `claimRevisionAuthor`), and tells `warn`
 * about each signature in doubt, once per revision. Nothing is checked
 * while signed out (a public link's reader has no pins). The check runs
 * once the revision is open, after its bytes were handed over: it warns,
 * never blocks. Returns the undo.
 */
export function watchManifestSigners(warn: (warning: ManifestSignerWarning) => void): () => void {
  const told = new Set<string>()
  const check = async (signature: ManifestSignature) => {
    const session = getSession()
    if (!session) return
    const claimed = claimedAuthorOf(signature.fileId, signature.revisionId)
    const verdict = await manifestSignerVerdict(await driveIdentityOf(session), signature, claimed)
    if (verdict.kind === 'verified' || verdict.kind === 'unknown') return
    const key = `${signature.fileId}/${signature.revisionId}/${verdict.kind}`
    if (told.has(key)) return
    told.add(key)
    warn({
      kind: verdict.kind,
      name: verdict.name,
      ...(verdict.kind === 'authorMismatch' ? { claimed: verdict.claimed } : {}),
      fileId: signature.fileId,
      revisionId: signature.revisionId,
    })
  }
  setManifestSignerCheck(check)
  return () => setManifestSignerCheck(null)
}
