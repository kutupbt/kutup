import type { IdentityRoot } from './accountRoots'
import { toBase64 } from './base64'
import { getCryptoWasm } from './rustWasm'

/** A collection's epoch statement, signed by the account's authority (from its identity root). */
export async function createCollectionEpochStatement(
  identityRoot: IdentityRoot,
  collectionKey: Uint8Array,
  collectionId: string,
  ownerUserId: string,
  epoch: number,
  previousStatementHash?: string,
): Promise<string> {
  const module = await getCryptoWasm()
  return module.createCollectionEpochStatement(
    identityRoot,
    toBase64(collectionKey),
    collectionId,
    ownerUserId,
    epoch,
    previousStatementHash ?? '',
  )
}

export async function verifyCollectionEpochStatement(
  statementBase64: string,
  authorityPublicKeyBase64: string,
  collectionKey: Uint8Array,
  collectionId: string,
  ownerUserId: string,
  epoch: number,
  previousStatementHash?: string,
): Promise<string> {
  const module = await getCryptoWasm()
  return module.verifyCollectionEpochStatement(
    statementBase64,
    authorityPublicKeyBase64,
    toBase64(collectionKey),
    collectionId,
    ownerUserId,
    epoch,
    previousStatementHash ?? '',
  )
}
