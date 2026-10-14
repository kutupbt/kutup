// Vault secrets (docs/plans/pass.md, "Vault secrets"): what opens a vault,
// kept in the account sealed under the master key, so a vault opens with the
// Kutup sign-in, as Proton Pass does. The server stores them unreadable,
// bound to the account's key binding and the vault (docs/plans/account-identity.md).

import { useQuery, useQueryClient } from '@tanstack/react-query'
import { revisionGuard } from '@kutup/crypto'
import { fromBase64 } from '@kutup/crypto/base64'
import {
  accountHead,
  HeadBlockedError,
  NotInVerifiedIndexError,
  type VerifiedIndex,
} from '@kutup/session/accountHead'
import api from '@kutup/session/client'
import { getSession, type Session } from '@kutup/session/store'
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
  /**
   * The revision the account head vouches for (docs/plans/rollback-protection.md),
   * when it covers the vault secrets: the key must open at exactly this one.
   */
  vouched?: number
}

/** What the revision guard calls a vault's kept key. */
const KEPT_SCOPE = 'pass-vault-secret'

export const secretsKey = ['pass', 'vault-secrets'] as const

/** The vault secrets are the account head's `passSecrets` scope, one value per vault file. */
const HEAD_SCOPE = 'passSecrets'

function headFor(session: Session) {
  return accountHead(session)
}

/**
 * The head's index of the vault secrets, or null when it cannot vouch (this
 * app is blocked on another history: reads go on, held to this browser's own
 * guard, and the banner says why).
 */
async function secretsIndex(session: Session): Promise<VerifiedIndex | null> {
  try {
    return await (await headFor(session)).verifiedIndex(HEAD_SCOPE)
  } catch (error) {
    if (error instanceof HeadBlockedError) return null
    throw error
  }
}

/**
 * The account's vault secrets, held to the head: a list with one more or one
 * fewer than the head vouches for is refused (read again once first, for a
 * write landing between the two reads), and each row carries the revision it
 * must open at. Refused, no kept key is used: vaults open with their password.
 */
export async function loadVaultSecrets(session: Session): Promise<SecretRow[]> {
  for (let attempt = 0; ; attempt++) {
    const index = await secretsIndex(session)
    const rows = (await api.get<SecretRow[]>('/pass/vault-secrets')).data
    try {
      index?.expectListing(rows.map((row) => row.fileId))
    } catch (error) {
      if (error instanceof NotInVerifiedIndexError && attempt === 0) continue
      throw error
    }
    return rows.map((row) => (index?.covered ? { ...row, vouched: index.revision(row.fileId) } : row))
  }
}

export function useVaultSecrets() {
  return useQuery({
    queryKey: secretsKey,
    queryFn: () => {
      const session = getSession()
      if (!session) throw new Error('not signed in')
      return loadVaultSecrets(session)
    },
  })
}

async function openRow(session: Session, rows: SecretRow[] | undefined, fileId: string): Promise<KeptKey | null> {
  const row = rows?.find((r) => r.fileId === fileId)
  if (!row) return null
  try {
    const kept = await openKept(row.envelope, session.masterKey, session.envelopeBinding, fileId)
    // Not the one the account head vouches for: rolled back, or brought back.
    if (row.vouched !== undefined && kept.revision !== row.vouched) return null
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

/**
 * Stores a kept key for vault `fileId`, with the next account head. Stored
 * already (a retry after an answer that was lost) counts as stored: the
 * head's index then lists this very revision, and nothing is sent again.
 */
export async function putKeptKey(session: Session, fileId: string, sealed: SealedKey): Promise<void> {
  await (await headFor(session)).listedWrite(HEAD_SCOPE, (index) =>
    Promise.resolve(
      index.revision(fileId) === sealed.revision
        ? null
        : {
            changes: [[fileId, sealed.revision]] as const,
            send: async (head: string) => {
              await api.put(`/pass/vault-secrets/${fileId}`, { envelope: sealed.envelope, baseRevision: sealed.base, head })
            },
          },
    ),
  )
  // Stored: remembering it here is best effort (a store that fails only
  // means this browser trusts the next read, as a fresh one does).
  await revisionGuard(session)
    .accept(KEPT_SCOPE, fileId, sealed.revision)
    .catch(() => undefined)
}

/** Seals the key of the vault open in `vault` to replace the kept one at `base`. */
export async function sealVaultKey(session: Session, fileId: string, vault: VaultHandle, base: number, generated = false): Promise<SealedKey> {
  const revision = await revisionGuard(session).next(KEPT_SCOPE, fileId, base)
  const envelope = await vault.keepKey(session.masterKey, session.envelopeBinding, fileId, revision, generated)
  return { envelope, revision, base }
}

/**
 * Keeps the key of the vault open in `vault` (the key it was opened or made
 * with) for `fileId`, on top of the key kept now, with the next account head.
 * When another device kept one meanwhile: done if it is this same key;
 * otherwise again on top of it (this vault's key is the one just used). A
 * password the person chose is kept only as its SHA-256; a `generated` one
 * as it is, to be shown.
 */
export async function keepVaultKey(session: Session, fileId: string, vault: VaultHandle, generated = false): Promise<void> {
  let kept: number | null = null
  await (await headFor(session)).listedWrite(HEAD_SCOPE, async (index, attempt) => {
    const now = (await api.get<SecretRow[]>('/pass/vault-secrets')).data.find((r) => r.fileId === fileId)
    if (attempt > 1 && now && (await vault.keptKeyIsMine(now.envelope, session.masterKey, session.envelopeBinding, fileId))) {
      // Another device kept this same key first: nothing to do.
      kept = now.revision
      return null
    }
    const sealed = await sealVaultKey(session, fileId, vault, now?.revision ?? 0, generated)
    if (index.revision(fileId) === sealed.revision) return null
    return {
      changes: [[fileId, sealed.revision]],
      send: async (head) => {
        await api.put(`/pass/vault-secrets/${fileId}`, { envelope: sealed.envelope, baseRevision: sealed.base, head })
        kept = sealed.revision
      },
    }
  })
  if (kept !== null) await revisionGuard(session).accept(KEPT_SCOPE, fileId, kept)
}

export function useKeepVaultKey() {
  const queryClient = useQueryClient()
  return async (session: Session, fileId: string, vault: VaultHandle, generated = false): Promise<void> => {
    await keepVaultKey(session, fileId, vault, generated)
    await queryClient.invalidateQueries({ queryKey: secretsKey })
  }
}

/** Forgets the kept key of vault `fileId`, with the next account head (gone already: nothing to do). */
export async function forgetVaultKey(session: Session, fileId: string): Promise<void> {
  await (await headFor(session)).listedWrite(HEAD_SCOPE, (index) =>
    Promise.resolve(
      index.revision(fileId) === undefined
        ? null
        : {
            changes: [[fileId, null]] as const,
            send: async (head: string) => {
              await api.delete(`/pass/vault-secrets/${fileId}`, { data: { head } })
            },
          },
    ),
  )
}

export function useForgetVaultKey() {
  const queryClient = useQueryClient()
  return async (fileId: string): Promise<void> => {
    const session = getSession()
    if (!session) throw new Error('not signed in')
    await forgetVaultKey(session, fileId)
    await queryClient.invalidateQueries({ queryKey: secretsKey })
  }
}
