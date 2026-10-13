// The Kutup Pass part of re-binding an account (docs/plans/account-identity.md,
// "Re-sealing"): every vault secret the account keeps (docs/plans/pass.md,
// "Vault secrets"), vaults in the trash included, opened with the old binding
// and sealed again with the new one, for `POST /api/user/rebind`'s
// `passVaultSecrets`. The server applies it only whole, with every record
// named. A record that does not open with the old binding opened nothing
// already (Kutup Pass treats it as absent); it is dropped (`envelope: null`)
// rather than holding up the rebind.

import { toBase64 } from '@kutup/crypto/base64'
import { openPassVaultSecret, sealPassVaultSecret } from '@kutup/crypto/passVault'
import api from './client'

export interface PassVaultSecretRebind {
  fileId: string
  /** The re-sealed envelope (base64); null drops the record. */
  envelope: string | null
}

interface SecretRow {
  fileId: string
  envelope: string
}

export async function rebindPassVaultSecrets(masterKey: Uint8Array, fromBinding: string, toBinding: string): Promise<PassVaultSecretRebind[]> {
  const { data } = await api.get<SecretRow[]>('/pass/vault-secrets', { params: { all: true } })
  const key = toBase64(masterKey)
  const out: PassVaultSecretRebind[] = []
  for (const row of data) {
    let secret
    try {
      secret = await openPassVaultSecret(row.envelope, key, fromBinding, row.fileId)
    } catch {
      out.push({ fileId: row.fileId, envelope: null })
      continue
    }
    const envelope = await sealPassVaultSecret(key, toBinding, row.fileId, secret)
    // It must open again, with the new binding, to the same secret.
    const again = await openPassVaultSecret(envelope, key, toBinding, row.fileId).catch(() => null)
    if (!again || JSON.stringify(again) !== JSON.stringify(secret)) throw new Error('a re-sealed vault key does not open')
    out.push({ fileId: row.fileId, envelope })
  }
  return out
}
