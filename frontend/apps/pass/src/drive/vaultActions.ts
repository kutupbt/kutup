// What the vault list does to a vault as a file (docs/plans/pass-parity.md,
// "Vault management from the vault list"): download it, copy it, move it.
// Each works while the vault is locked: Drive's layer is opened with the
// folder's key, never the vault's.

import { useQueryClient } from '@tanstack/react-query'
import { foldersKey } from '@kutup/drive-core/folders'
import type { Folder } from '@kutup/drive-core/model'
import { moveFile } from '@kutup/drive-core/move'
import type { Session } from '@kutup/session/store'
import { VaultHandle } from '../vault/client'
import { keepVaultKey, keptKey, keptKeyKind, type SecretRow } from './secrets'
import { readCurrentVault, refreshVaultFile, useCreateVaultFile, vaultTitle, type VaultFile } from './vaults'

/**
 * Saves the vault's current `.kdbx` as a download. Only Drive's layer is
 * opened: the file stays protected by the vault's own key, which is never
 * put in or beside it.
 */
export async function downloadVault(vault: VaultFile): Promise<void> {
  const file = await refreshVaultFile(vault.folder, vault.file)
  const { contents } = await readCurrentVault(file)
  const blob = new Blob([contents as BlobPart], { type: 'application/x-keepass2' })
  const url = URL.createObjectURL(blob)
  try {
    const link = document.createElement('a')
    link.href = url
    link.download = `${vaultTitle(file.name) || 'vault'}.kdbx`
    document.body.append(link)
    link.click()
    link.remove()
  } finally {
    // After the click has handed the blob to the download.
    setTimeout(() => URL.revokeObjectURL(url), 30_000)
  }
}

/** What a copy came to: its file, and whether the account keeps its key (opens with the sign-in). */
export interface Duplicated {
  fileId: string
  keyKept: boolean
}

/**
 * Copies a vault into its own folder under a free name ("Name (1)"). It
 * shares the vault's key: when the account keeps that key, it is kept for
 * the copy too (opened with it once, in the worker, to seal it for the new
 * file), so the copy opens with the sign-in as well.
 */
export function useDuplicateVault() {
  const createFile = useCreateVaultFile()
  return async (vault: VaultFile, session: Session, secrets: SecretRow[] | undefined): Promise<Duplicated> => {
    const file = await refreshVaultFile(vault.folder, vault.file)
    const { contents } = await readCurrentVault(file)
    const fileId = await createFile(vault.folder, vaultTitle(file.name) || 'vault', contents)
    const key = await keptKey(session, secrets, file.id)
    if (!key) return { fileId, keyKept: false }
    const generated = (await keptKeyKind(session, secrets, file.id)) === 'generated'
    let handle: VaultHandle | null = null
    try {
      handle = await VaultHandle.open(contents, key)
      await keepVaultKey(session, fileId, handle, generated)
      return { fileId, keyKept: true }
    } catch {
      // The copy is there; it opens with the vault's key as it is.
      return { fileId, keyKept: false }
    } finally {
      await handle?.close().catch(() => undefined)
    }
  }
}

/** Folders a vault may go to: open ones this account can write to, not its own. */
export function moveTargets(folders: readonly Folder[], vault: VaultFile): Folder[] {
  return folders
    .filter(
      (f) =>
        f.id !== vault.folder.id &&
        f.key &&
        f.canUpload &&
        (f.source === 'owned' || f.source === 'shared') &&
        f.ownerUserId === vault.folder.ownerUserId,
    )
    .sort((a, b) => Number(b.isRoot) - Number(a.isRoot) || (a.name ?? '').localeCompare(b.name ?? ''))
}

/** Moves a vault: its file keeps its id, so its kept key still opens it. */
export function useMoveVault() {
  const queryClient = useQueryClient()
  return async (vault: VaultFile, to: Folder): Promise<void> => {
    const file = await refreshVaultFile(vault.folder, vault.file)
    await moveFile(vault.folder, file, to)
    await Promise.all([
      queryClient.invalidateQueries({ queryKey: ['files'] }),
      queryClient.invalidateQueries({ queryKey: foldersKey }),
    ])
  }
}
