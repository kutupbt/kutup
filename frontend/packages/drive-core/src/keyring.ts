import { unlockCollectionKeyring, type EpochLinkV1 } from '@kutup/crypto/collectionKeyring'
import { fileKeyAtV1 } from '@kutup/crypto/fileKeyring'
import type { DriveObjectExpected, DriveObjectToOpen } from '@kutup/crypto'
import api from '@kutup/session/client'
import { folderLocation, type DriveFile, type Folder } from './model'

/**
 * Keys across a folder's epochs (docs/plans/drive-share-revocation.md). A
 * folder whose owner removed someone has moved to a new key; a file whose key
 * is still wrapped at an older epoch opens with that epoch's key, which the
 * current key unlocks through the folder's signed history. Most folders have
 * one epoch and never reach the network here.
 *
 * A file's own older keys (from re-keys) come from the file's chain instead
 * (`fileKeyAt`), independent of any folder (docs/plans/drive-move.md).
 */

/** What finding a folder's keys needs: its current key and where its history is. */
export type KeyringFolder = Pick<
  Folder,
  'id' | 'source' | 'remoteShareId' | 'key' | 'keyEpoch' | 'ownerUserId' | 'ownerAuthorityPublicKey' | 'epochStatementHash'
>

const keyrings = new Map<string, Promise<Uint8Array[]>>()

async function history(folder: KeyringFolder): Promise<EpochLinkV1[]> {
  const location = folderLocation(folder)
  const { data } = await api.get<EpochLinkV1[]>(
    location.kind === 'local'
      ? `/collections/${location.collectionId}/epochs`
      : `/drive/federation/shares/${location.shareId}/epochs`,
  )
  return data
}

/** Every key of the folder, oldest first, verified; cached per epoch. */
function keyring(folder: KeyringFolder): Promise<Uint8Array[]> {
  const cacheKey = `${folder.id}:${folder.epochStatementHash}`
  let pending = keyrings.get(cacheKey)
  if (!pending) {
    const key = folder.key
    if (!key) return Promise.reject(new Error('folder is not open'))
    pending = history(folder).then((chain) => {
      if (chain.length !== folder.keyEpoch || chain.at(-1)?.epochStatementHash !== folder.epochStatementHash) {
        throw new Error('folder key history does not end at the current epoch')
      }
      return unlockCollectionKeyring(key, folder.id, folder.ownerUserId, folder.ownerAuthorityPublicKey, chain)
    })
    pending.catch(() => keyrings.delete(cacheKey))
    keyrings.set(cacheKey, pending)
  }
  return pending
}

/** The folder's key at `epoch`: its own for the current one, else from its history. */
export async function folderKeyAt(folder: KeyringFolder, epoch: number): Promise<Uint8Array> {
  if (!folder.key) throw new Error('folder is not open')
  if (epoch === folder.keyEpoch) return folder.key
  if (!Number.isSafeInteger(epoch) || epoch < 1 || epoch > folder.keyEpoch) {
    throw new Error('no such folder key epoch')
  }
  return (await keyring(folder))[epoch - 1]
}

const fileKeys = new Map<string, Promise<Uint8Array>>()

/**
 * The file key of `generation`: the current one, or an older one through the
 * file's own chain (docs/plans/drive-move.md) — no folder key involved, so it
 * works wherever the file has moved.
 */
export async function fileKeyAt(file: DriveFile, generation: number): Promise<Uint8Array> {
  if (!file.fileKey) throw new Error('file is not open')
  if (generation === file.keyGeneration) return file.fileKey
  if (!Number.isSafeInteger(generation) || generation < 1 || generation > file.keyGeneration) {
    throw new Error('no such file key generation')
  }
  const newest = file.keyHistory.at(-1)?.previousKeyEnvelope ?? ''
  const cacheKey = `${file.id}:${file.keyGeneration}:${generation}:${newest}`
  let pending = fileKeys.get(cacheKey)
  if (!pending) {
    pending = fileKeyAtV1(file.fileKey, file.id, file.keyGeneration, file.keyHistory, generation)
    pending.catch(() => fileKeys.delete(cacheKey))
    fileKeys.set(cacheKey, pending)
  }
  return pending
}

/** What a Drive object of a file is sealed for: the file and its key generation. */
export interface DriveFileBinding {
  fileId: string
  generation: number
}

/** A key and the binding of an object of `file` sealed under `generation`. */
export async function sealedAt(
  file: DriveFile,
  generation: number,
): Promise<{ fileKey: Uint8Array; context: DriveFileBinding }> {
  return {
    fileKey: await fileKeyAt(file, generation),
    context: { fileId: file.id, generation },
  }
}

/**
 * The file's current content: the key of the generation it was sealed under
 * and what it must be, the revision and manifest digest its metadata commits
 * to and the metadata's size (docs/plans/drive-block-format.md §2).
 */
export async function currentContentOf(file: DriveFile): Promise<{ fileKey: Uint8Array; expected: DriveObjectExpected }> {
  if (!file.content) throw new Error('file is not open')
  const generation = file.contentKeyGeneration
  return {
    fileKey: await fileKeyAt(file, generation),
    expected: { fileId: file.id, generation, content: file.content, size: file.size },
  }
}

/**
 * A version from the file's history (or a note's snapshot), by its id (its
 * revision) and its sealed content record from the listing: it opens
 * against the digest and size the record commits to
 * (docs/plans/drive-block-format.md §2).
 */
export async function versionContentOf(
  file: DriveFile,
  version: { id: string; keyGeneration: number; revisionContentEnvelope: string | null },
): Promise<{ fileKey: Uint8Array; expected: DriveObjectExpected }> {
  return {
    fileKey: await fileKeyAt(file, version.keyGeneration),
    expected: {
      fileId: file.id,
      generation: version.keyGeneration,
      revisionId: version.id,
      revisionContentEnvelope: version.revisionContentEnvelope,
    },
  }
}

/** A note's or place list's saved state, relayed from the server the file is on. */
export interface RelayedState {
  keyGeneration: number
  /** Base64. */
  state: string
  /** The version the state is, and its sealed content record. */
  versionId: string
  revisionContentEnvelope: string | null
}

/** A relayed state as the version it is. */
export function relayedVersion(saved: RelayedState): { id: string; keyGeneration: number; revisionContentEnvelope: string | null } {
  return { id: saved.versionId, keyGeneration: saved.keyGeneration, revisionContentEnvelope: saved.revisionContentEnvelope }
}

/**
 * The file's original upload (`/files/{id}/original`), which no listing
 * names: it opens against the revision and sealed record served with it.
 */
export async function originalContentOf(file: DriveFile): Promise<{ fileKey: Uint8Array; expected: DriveObjectToOpen }> {
  return {
    fileKey: await fileKeyAt(file, file.originalKeyGeneration),
    expected: { fileId: file.id, generation: file.originalKeyGeneration, served: true },
  }
}
