import { openDriveEnvelope, DRIVE_ENVELOPE_PURPOSE } from '@kutup/crypto/driveEnvelope'
import { unlockCollectionKeyring, type EpochLinkV1 } from '@kutup/crypto/collectionKeyring'
import type { FileBlobContextV1 } from '@kutup/crypto/fileBlob'
import api from '@kutup/session/client'
import { folderLocation, type DriveFile, type Folder } from './model'

/**
 * Keys across a folder's epochs (docs/plans/drive-share-revocation.md). A
 * folder whose owner removed someone has moved to a new key; what was stored
 * before stays sealed under older keys, which the current key unlocks
 * through the folder's signed history. Most folders have one epoch and never
 * reach the network here.
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

/** The file key something of `file` sealed at `epoch` opens with. */
export async function fileKeyAt(folder: Folder, file: DriveFile, epoch: number): Promise<Uint8Array> {
  if (epoch === file.keyEpoch) {
    if (!file.fileKey) throw new Error('file is not open')
    return file.fileKey
  }
  const entry = file.keyHistory.find((e) => e.epoch === epoch)
  if (!entry) throw new Error('no file key for that epoch')
  const cacheKey = `${file.id}:${epoch}:${entry.fileKeyEnvelope}`
  let pending = fileKeys.get(cacheKey)
  if (!pending) {
    pending = folderKeyAt(folder, epoch).then((collectionKey) =>
      openDriveEnvelope(entry.fileKeyEnvelope, collectionKey, {
        purpose: DRIVE_ENVELOPE_PURPOSE.fileKey,
        epoch,
        revision: 1n,
        objectId: file.id,
        parentId: file.collectionId,
      }),
    )
    pending.catch(() => fileKeys.delete(cacheKey))
    fileKeys.set(cacheKey, pending)
  }
  return pending
}

/** A key and the binding context for a blob of `file` sealed at `epoch`. */
export async function sealedAt(
  folder: Folder,
  file: DriveFile,
  epoch: number,
): Promise<{ fileKey: Uint8Array; context: FileBlobContextV1 }> {
  return {
    fileKey: await fileKeyAt(folder, file, epoch),
    context: { fileId: file.id, collectionId: file.collectionId, epoch },
  }
}
