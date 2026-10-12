// Vault secrets (docs/plans/pass.md, "Vault secrets"): what opens a vault,
// kept in the account sealed under the master key, so a vault opens with the
// Kutup sign-in, as Proton Pass does. The server stores them unreadable.

import { useQuery, useQueryClient } from '@tanstack/react-query'
import { fromBase64, toBase64 } from '@kutup/crypto/base64'
import { openPassVaultSecret, sealPassVaultSecret } from '@kutup/crypto/passVault'
import api from '@kutup/session/client'
import type { Session } from '@kutup/session/store'
import { keyFileSecret } from '../vault/client'
import type { VaultKeyInput } from '../vault/types'

interface SecretRow {
  fileId: string
  envelope: string
  updatedAt: string
}

export const secretsKey = ['pass', 'vault-secrets'] as const

export function useVaultSecrets() {
  return useQuery({
    queryKey: secretsKey,
    queryFn: async () => (await api.get<SecretRow[]>('/pass/vault-secrets')).data,
  })
}

/** The kept key of vault `fileId`, if the account keeps one that opens. */
export async function keptKey(session: Session, rows: SecretRow[] | undefined, fileId: string): Promise<VaultKeyInput | null> {
  const row = rows?.find((r) => r.fileId === fileId)
  if (!row) return null
  try {
    const secret = await openPassVaultSecret(row.envelope, toBase64(session.masterKey), session.email, fileId)
    return { password: secret.password, keyFile: secret.keyFile ? fromBase64(secret.keyFile) : null }
  } catch {
    // Sealed for another account or vault: as if there were none.
    return null
  }
}

export function useKeepVaultKey() {
  const queryClient = useQueryClient()
  return async (session: Session, fileId: string, key: VaultKeyInput): Promise<void> => {
    const keyFile = key.keyFile ? await keyFileSecret(key.keyFile) : null
    const envelope = await sealPassVaultSecret(toBase64(session.masterKey), session.email, fileId, {
      password: key.password,
      keyFile: keyFile ? toBase64(keyFile) : null,
    })
    await api.put(`/pass/vault-secrets/${fileId}`, { envelope })
    await queryClient.invalidateQueries({ queryKey: secretsKey })
  }
}

export function useForgetVaultKey() {
  const queryClient = useQueryClient()
  return async (fileId: string): Promise<void> => {
    await api.delete(`/pass/vault-secrets/${fileId}`)
    await queryClient.invalidateQueries({ queryKey: secretsKey })
  }
}
