import { getCryptoWasm } from './rustWasm'

export interface AccountIdentityKeysV1 {
  authorityPublicKey: string
  authorityKeyId: string
  incarnationId: string
  driveHpkePublicKey: string
  driveHpkePrivateKey: string
  driveSigningPublicKey: string
}

export async function deriveAccountIdentityKeys(
  masterKeyBase64: string,
): Promise<AccountIdentityKeysV1> {
  return (await getCryptoWasm()).deriveAccountIdentityKeys(masterKeyBase64)
}
