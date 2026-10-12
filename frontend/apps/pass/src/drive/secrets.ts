// Vault secrets (docs/plans/pass.md, "Vault secrets"): what opens a vault,
// kept in the account sealed under the master key, so a vault opens with the
// Kutup sign-in, as Proton Pass does. The server stores them unreadable.
// They are bound to the account's envelope binding, which the account app
// changes once when it re-seals the account (docs/plans/account-identity.md):
// a page opened before that refreshes the binding and tries once more.

import { useQuery, useQueryClient } from '@tanstack/react-query'
import { fromBase64, toBase64 } from '@kutup/crypto/base64'
import { openPassVaultSecret, sealPassVaultSecret } from '@kutup/crypto/passVault'
import { isBindingChanged, refreshEnvelopeBinding } from '@kutup/session/binding'
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

async function openRow(session: Session, row: SecretRow, binding: string, fileId: string): Promise<VaultKeyInput> {
  const secret = await openPassVaultSecret(row.envelope, toBase64(session.masterKey), binding, fileId)
  return { password: secret.password, keyFile: secret.keyFile ? fromBase64(secret.keyFile) : null }
}

/** The kept key of vault `fileId`, if the account keeps one that opens. */
export async function keptKey(session: Session, rows: SecretRow[] | undefined, fileId: string): Promise<VaultKeyInput | null> {
  const row = rows?.find((r) => r.fileId === fileId)
  if (!row) return null
  try {
    return await openRow(session, row, session.envelopeBinding, fileId)
  } catch {
    // The account may have been re-sealed since this page read its binding
    // or the list: read both again, once.
  }
  try {
    const binding = await refreshEnvelopeBinding()
    const fresh = (await api.get<SecretRow[]>('/pass/vault-secrets')).data.find((r) => r.fileId === fileId)
    return fresh ? await openRow(session, fresh, binding, fileId) : null
  } catch {
    // Sealed for another account or vault, or Kutup out of reach: as if
    // there were none.
    return null
  }
}

/** Keeps the key of vault `fileId` in the account. */
export async function keepVaultKey(session: Session, fileId: string, key: VaultKeyInput): Promise<void> {
  const keyFile = key.keyFile ? await keyFileSecret(key.keyFile) : null
  const secret = { password: key.password, keyFile: keyFile ? toBase64(keyFile) : null }
  const keep = async (binding: string) =>
    api.put(`/pass/vault-secrets/${fileId}`, { envelope: await sealPassVaultSecret(toBase64(session.masterKey), binding, fileId, secret) })
  try {
    await keep(session.envelopeBinding)
  } catch (error) {
    // Re-sealed since this page read the binding: seal for the new one, once.
    if (!isBindingChanged(error)) throw error
    await keep(await refreshEnvelopeBinding())
  }
}

export function useKeepVaultKey() {
  const queryClient = useQueryClient()
  return async (session: Session, fileId: string, key: VaultKeyInput): Promise<void> => {
    await keepVaultKey(session, fileId, key)
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
