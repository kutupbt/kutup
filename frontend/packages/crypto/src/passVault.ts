import { getCryptoWasm } from './rustWasm'

// Kutup Pass vault secrets (docs/plans/pass.md, "Vault secrets"): what opens
// a vault (a password, a key file, or both), sealed under the master key and
// bound to the vault's file id, in Rust (kutup-crypto `pass_vault`).

/** What opens one vault; the key file in base64. */
export interface PassVaultSecret {
  password: string | null
  keyFile: string | null
}

export async function sealPassVaultSecret(
  masterKeyBase64: string,
  binding: string,
  fileId: string,
  secret: PassVaultSecret,
): Promise<string> {
  return (await getCryptoWasm()).sealPassVaultSecret(masterKeyBase64, binding, fileId, secret.password, secret.keyFile)
}

export async function openPassVaultSecret(
  envelope: string,
  masterKeyBase64: string,
  binding: string,
  fileId: string,
): Promise<PassVaultSecret> {
  return (await getCryptoWasm()).openPassVaultSecret(envelope, masterKeyBase64, binding, fileId)
}
