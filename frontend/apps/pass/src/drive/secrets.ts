// Vault secrets (docs/plans/pass.md, "Vault secrets"): what opens a vault,
// kept in the account sealed under the master key, so a vault opens with the
// Kutup sign-in, as Proton Pass does. The server stores them unreadable.
// They are bound to the account's envelope binding, which the account app
// changes once when it re-seals the account (docs/plans/account-identity.md):
// a page opened before that refreshes the binding and tries once more.

import { useQuery, useQueryClient } from '@tanstack/react-query'
import { fromBase64, toBase64 } from '@kutup/crypto/base64'
import { openPassVaultSecret, sealPassVaultSecret, type PassVaultSecret } from '@kutup/crypto/passVault'
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

async function openRow(session: Session, rows: SecretRow[] | undefined, fileId: string): Promise<PassVaultSecret | null> {
  const row = rows?.find((r) => r.fileId === fileId)
  if (!row) return null
  try {
    return await openPassVaultSecret(row.envelope, toBase64(session.masterKey), session.envelopeBinding, fileId)
  } catch {
    // Sealed for another account or vault: as if there were none.
    return null
  }
}

/**
 * The kept key of vault `fileId`, if the account keeps one that opens: the
 * password as its SHA-256 (what is kept of a password the person chose).
 */
export async function keptKey(session: Session, rows: SecretRow[] | undefined, fileId: string): Promise<VaultKeyInput | null> {
  const secret = await openRow(session, rows, fileId)
  if (!secret) return null
  return {
    password: null,
    passwordHash: secret.passwordHash ? fromBase64(secret.passwordHash) : null,
    keyFile: secret.keyFile ? fromBase64(secret.keyFile) : null,
  }
}

/** The vault's key to show, when Kutup Pass generated it (for KeePass apps). */
export async function keptGeneratedPassword(session: Session, rows: SecretRow[] | undefined, fileId: string): Promise<string | null> {
  return (await openRow(session, rows, fileId))?.generatedPassword ?? null
}

/**
 * Keeps the key of vault `fileId` in the account. A password the person
 * chose is kept only as its SHA-256; a `generated` one as it is, to be shown.
 */
export async function keepVaultKey(session: Session, fileId: string, key: VaultKeyInput, generated = false): Promise<void> {
  if (key.password === null && key.passwordHash) throw new Error('a kept key is kept from the password')
  const keyFile = key.keyFile ? await keyFileSecret(key.keyFile) : null
  const secret = { password: key.password, keyFile: keyFile ? toBase64(keyFile) : null, generated }
  await api.put(`/pass/vault-secrets/${fileId}`, {
    envelope: await sealPassVaultSecret(toBase64(session.masterKey), session.envelopeBinding, fileId, secret),
  })
}

export function useKeepVaultKey() {
  const queryClient = useQueryClient()
  return async (session: Session, fileId: string, key: VaultKeyInput, generated = false): Promise<void> => {
    await keepVaultKey(session, fileId, key, generated)
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
