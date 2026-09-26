import { unlockCollectionKeyring, type EpochLinkV1 } from '@kutup/crypto/collectionKeyring'
import { fileKeyAtV1 } from '@kutup/crypto/fileKeyring'
import type { FileBlobContextV1 } from '@kutup/crypto/fileBlob'
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

/** A key and the binding context for a blob of `file` sealed under `generation`. */
export async function sealedAt(
  file: DriveFile,
  generation: number,
): Promise<{ fileKey: Uint8Array; context: FileBlobContextV1 }> {
  return {
    fileKey: await fileKeyAt(file, generation),
    context: { fileId: file.id, generation },
  }
}
