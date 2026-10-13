// Vault secrets (docs/plans/pass.md, "Vault secrets"): what opens a vault,
// kept in the account sealed under the master key, so a vault opens with the
// Kutup sign-in, as Proton Pass does. The server stores them unreadable,
// bound to the account's key binding and the vault (docs/plans/account-identity.md).

import { useQuery, useQueryClient } from '@tanstack/react-query'
import { isAxiosError } from 'axios'
import { revisionGuard } from '@kutup/crypto'
import { fromBase64 } from '@kutup/crypto/base64'
import api from '@kutup/session/client'
import type { Session } from '@kutup/session/store'
import { openKept, type KeptKey, type VaultHandle } from '../vault/client'
import type { VaultKeyInput } from '../vault/types'

// What is kept, and how, is decided once, in Rust (kutup_pass::kept, through
// the Pass worker); this file only moves records to and from the server.
// A kept key carries its revision (docs/plans/sealed-revisions.md): one older
// than this browser has seen is not used, and a new one is stored only on top
// of the one it replaces.

interface SecretRow {
  fileId: string
  envelope: string
  /** The revision in the envelope's header, as the server read it. */
  revision: number
  updatedAt: string
}

/** What the revision guard calls a vault's kept key. */
const KEPT_SCOPE = 'pass-vault-secret'

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
    const kept = await openKept(row.envelope, session.masterKey, session.envelopeBinding, fileId)
    // Older than one this browser has seen: the server replaying an old key.
    await revisionGuard(session).accept(KEPT_SCOPE, fileId, kept.revision)
    return kept
  } catch {
    // Sealed for another account or vault, or replayed: as if there were none.
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

/** A kept key sealed for a vault, ready to store. */
export interface SealedKey {
  envelope: string
  revision: number
  /** The revision it replaces (0: none). */
  base: number
}

function conflict(error: unknown): number | null {
  if (!isAxiosError(error) || error.response?.status !== 409) return null
  const body = error.response.data as { code?: string; revision?: number } | undefined
  return body?.code === 'revision_conflict' ? (body.revision ?? 0) : null
}

/**
 * Stores a kept key for vault `fileId`. Stored already (a retry after an
 * answer that was lost) counts as stored.
 */
export async function putKeptKey(session: Session, fileId: string, sealed: SealedKey): Promise<void> {
  try {
    await api.put(`/pass/vault-secrets/${fileId}`, { envelope: sealed.envelope, baseRevision: sealed.base })
  } catch (error) {
    if (conflict(error) !== sealed.revision) throw error
  }
  await revisionGuard(session).accept(KEPT_SCOPE, fileId, sealed.revision)
}

/** Seals the key of the vault open in `vault` to replace the kept one at `base`. */
export async function sealVaultKey(session: Session, fileId: string, vault: VaultHandle, base: number, generated = false): Promise<SealedKey> {
  const revision = await revisionGuard(session).next(KEPT_SCOPE, fileId, base)
  const envelope = await vault.keepKey(session.masterKey, session.envelopeBinding, fileId, revision, generated)
  return { envelope, revision, base }
}

/**
 * Keeps the key of the vault open in `vault` (the key it was opened or made
 * with) for `fileId`, on top of the key kept now; when another device kept
 * one meanwhile, once more on top of that. A password the person chose is
 * kept only as its SHA-256; a `generated` one as it is, to be shown.
 */
export async function keepVaultKey(session: Session, fileId: string, vault: VaultHandle, generated = false): Promise<void> {
  const keptNow = async () => (await api.get<SecretRow[]>('/pass/vault-secrets')).data.find((r) => r.fileId === fileId)?.revision ?? 0
  for (let attempt = 0; ; attempt++) {
    try {
      await putKeptKey(session, fileId, await sealVaultKey(session, fileId, vault, await keptNow(), generated))
      return
    } catch (error) {
      if (attempt > 0 || conflict(error) === null) throw error
    }
  }
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
