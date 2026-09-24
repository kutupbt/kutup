import { fromBase64, toBase64 } from './base64'
import { getCryptoWasm } from './rustWasm'

/**
 * A folder's keys across its epochs (docs/plans/drive-share-revocation.md).
 * Rotating a folder adds an epoch whose record carries the previous key
 * sealed under the new one; the current key walks down to every older key,
 * each step checked against the owner-signed statement chain (in Rust).
 */

/** One epoch of `GET /collections/{id}/epochs` (and its public/federated twins). */
export interface EpochLinkV1 {
  epoch: number
  epochStatement: string
  epochStatementHash: string
  previousKeyEnvelope?: string
}

/**
 * Every key of the folder, oldest first (`keys[e - 1]` is epoch `e`).
 * Throws unless the history is complete, owner-signed, chained, and every
 * key matches its commitment — a server cannot hand back a substitute.
 */
export async function unlockCollectionKeyring(
  currentKey: Uint8Array,
  collectionId: string,
  ownerUserId: string,
  ownerAuthorityPublicKey: string,
  chain: EpochLinkV1[],
): Promise<Uint8Array[]> {
  const module = await getCryptoWasm()
  return module
    .unlockCollectionKeyring(
      toBase64(currentKey),
      collectionId,
      ownerUserId,
      ownerAuthorityPublicKey,
      chain.map((link) => ({
        epoch: link.epoch,
        epochStatement: link.epochStatement,
        ...(link.previousKeyEnvelope ? { previousKeyEnvelope: link.previousKeyEnvelope } : {}),
      })),
    )
    .map((key) => fromBase64(key))
}

/** The key of `epoch − 1` sealed under the key of `epoch`, for a rotation. */
export async function sealPreviousCollectionKey(
  previousKey: Uint8Array,
  key: Uint8Array,
  collectionId: string,
  ownerUserId: string,
  epoch: number,
): Promise<string> {
  const module = await getCryptoWasm()
  return module.sealPreviousCollectionKey(toBase64(previousKey), toBase64(key), collectionId, ownerUserId, epoch)
}
