// Vault secrets (docs/plans/pass.md, "Vault secrets"): what opens a vault,
// kept in the account sealed under the master key, so a vault opens with the
// Kutup sign-in, as Proton Pass does. The server stores them unreadable,
// bound to the account's key binding and the vault (docs/plans/account-identity.md).

import { useQuery, useQueryClient } from '@tanstack/react-query'
import { fromBase64 } from '@kutup/crypto/base64'
import api from '@kutup/session/client'
import type { Session } from '@kutup/session/store'
import { openKept, type KeptKey, type VaultHandle } from '../vault/client'
import type { VaultKeyInput } from '../vault/types'

// What is kept, and how, is decided once, in Rust (kutup_pass::kept, through
// the Pass worker); this file only moves records to and from the server.

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

async function openRow(session: Session, rows: SecretRow[] | undefined, fileId: string): Promise<KeptKey | null> {
  const row = rows?.find((r) => r.fileId === fileId)
  if (!row) return null
  try {
    return await openKept(row.envelope, session.masterKey, session.envelopeBinding, fileId)
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

/**
 * What kind of key the account keeps for vault `fileId`: one Kutup Pass
 * generated (kept nowhere else unless saved), one the person chose, or
 * `unknown` when it does not open here (to be treated as generated).
 */
export async function keptKeyKind(session: Session, rows: SecretRow[] | undefined, fileId: string): Promise<'generated' | 'chosen' | 'unknown' | 'none'> {
  if (!rows?.some((r) => r.fileId === fileId)) return 'none'
  const secret = await openRow(session, rows, fileId)
  if (!secret) return 'unknown'
  return secret.generatedPassword ? 'generated' : 'chosen'
}

/** The vault's key to show, when Kutup Pass generated it (for KeePass apps). */
export async function keptGeneratedPassword(session: Session, rows: SecretRow[] | undefined, fileId: string): Promise<string | null> {
  return (await openRow(session, rows, fileId))?.generatedPassword ?? null
}

/** Stores a kept key (from {@link VaultHandle.keepKey}) for vault `fileId`. */
export async function putKeptKey(fileId: string, envelope: string): Promise<void> {
  await api.put(`/pass/vault-secrets/${fileId}`, { envelope })
}

/**
 * Keeps the key of the vault open in `vault` (the key it was opened or made
 * with) for `fileId`. A password the person chose is kept only as its
 * SHA-256; a `generated` one as it is, to be shown.
 */
export async function keepVaultKey(session: Session, fileId: string, vault: VaultHandle, generated = false): Promise<void> {
  await putKeptKey(fileId, await vault.keepKey(session.masterKey, session.envelopeBinding, fileId, generated))
}

export function useKeepVaultKey() {
  const queryClient = useQueryClient()
  return async (session: Session, fileId: string, vault: VaultHandle, generated = false): Promise<void> => {
    await keepVaultKey(session, fileId, vault, generated)
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
