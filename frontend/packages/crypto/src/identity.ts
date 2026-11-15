import type { IdentityRoot } from './accountRoots'
import { getCryptoWasm } from './rustWasm'

export interface AccountIdentityKeysV1 {
  authorityPublicKey: string
  authorityKeyId: string
  incarnationId: string
  driveHpkePublicKey: string
  driveHpkePrivateKey: string
  driveSigningPublicKey: string
}

/** The account's identity keys, from its identity root (`session.roots.identityRoot`). */
export async function deriveAccountIdentityKeys(identityRoot: IdentityRoot): Promise<AccountIdentityKeysV1> {
  return (await getCryptoWasm()).deriveAccountIdentityKeys(identityRoot)
}
