import { fromBase64, openFileMetadataV1, openPublicLinkCollectionKeyV1 } from '@kutup/crypto'
import { openAlbumFileKeyV1 } from '@kutup/crypto/album'
import { DRIVE_ENVELOPE_PURPOSE, openDriveEnvelope } from '@kutup/crypto/driveEnvelope'
import { toDriveFile } from '@kutup/drive-core/files'
import { fileKeyAt } from '@kutup/drive-core/keyring'
import type { DriveFile } from '@kutup/drive-core/model'
import { thumbnailUrl } from '@kutup/drive-core/thumbnails'
import { fetchDecryptedChunks } from '@kutup/files/download/fetchDecrypt'
import { mediaKindOf } from '@kutup/files/media'
import type { MediaMetadataV1 } from '@kutup/crypto'
import { resolveApiBase } from '@kutup/session/apiBase'
import api from '@kutup/session/client'
import type { FileRow } from '@kutup/session/api-types'
import { joinLivePhotos, type Photo } from '../library/library'
import { newestFirst } from '../library/timeline'

// An album's public link (docs/plans/photos.md): the album key sealed under
// a link key that lives only in the URL fragment, so the server never holds
// it; the page opens the album and its photos in the browser.

export type PublicFailure = 'missingKey' | 'notFound' | 'expired' | 'badKey' | 'notAlbum' | 'other'

export class PublicAlbumError extends Error {
  constructor(public readonly failure: PublicFailure) {
    super(failure)
  }
}

interface ShareInfo {
  shareType: string
  targetId: string
  collectionKeyEnvelope: string
  collectionKeyEpoch: number
  ownerUserId: string
  expiresAt: string | null
  collectionKind?: string
  nameEnvelope?: string
  nameRevision?: number
}

interface PublicItem {
  file: Omit<FileRow, 'uploaderUserId' | 'updatedAt' | 'thumbnails'>
  thumbnails: DriveFile['thumbnails']
  fileKeyEnvelope: string
  keyGeneration: number
  albumEpoch: number
}

/** A photo as the link page shows it: a library photo without a folder of its own. */
export type PublicPhoto = Photo

export interface PublicAlbum {
  name: string
  photos: PublicPhoto[]
}

/** The link's key, from the fragment (`#key=…`), which browsers never send. */
function linkKey(): Uint8Array | null {
  try {
    const key = new URLSearchParams(window.location.hash.slice(1)).get('key')
    const bytes = key ? fromBase64(key) : null
    return bytes && bytes.length === 32 ? bytes : null
  } catch {
    return null
  }
}

const base = (token: string) => `/share/${encodeURIComponent(token)}`

export async function loadPublicAlbum(token: string): Promise<PublicAlbum> {
  const key = linkKey()
  if (!key) throw new PublicAlbumError('missingKey')
  let share: ShareInfo
  try {
    share = (await api.get<ShareInfo>(base(token))).data
  } catch (error) {
    const status = (error as { response?: { status?: number } }).response?.status
    throw new PublicAlbumError(status === 404 ? 'notFound' : status === 410 ? 'expired' : 'other')
  }
  if (share.collectionKind !== 'album' || !share.nameEnvelope || !share.nameRevision) throw new PublicAlbumError('notAlbum')
  let albumKey: Uint8Array
  let name: string
  try {
    albumKey = await openPublicLinkCollectionKeyV1(share.collectionKeyEnvelope, key, {
      collectionId: share.targetId,
      ownerUserId: share.ownerUserId,
      epoch: share.collectionKeyEpoch,
    })
    name = new TextDecoder().decode(
      await openDriveEnvelope(share.nameEnvelope, albumKey, {
        purpose: DRIVE_ENVELOPE_PURPOSE.collectionName,
        epoch: share.collectionKeyEpoch,
        revision: BigInt(share.nameRevision),
        objectId: share.targetId,
        parentId: share.ownerUserId,
      }),
    )
  } catch {
    throw new PublicAlbumError('badKey')
  }
  const { data } = await api.get<PublicItem[]>(`${base(token)}/album`)
  const photos = await Promise.all(
    data.map(async (item): Promise<PublicPhoto | null> => {
      try {
        if (item.keyGeneration !== item.file.keyGeneration) return null
        const fileKey = await openAlbumFileKeyV1(item.fileKeyEnvelope, albumKey, {
          fileId: item.file.id,
          albumId: share.targetId,
          albumEpoch: item.albumEpoch,
          generation: item.keyGeneration,
        })
        const metadata = await openFileMetadataV1(item.file, fileKey)
        const kind = mediaKindOf(metadata.name, metadata.mimeType)
        if (!kind) return null
        const file = toDriveFile({ ...item.file, thumbnails: item.thumbnails }, { fileKey, metadata })
        const media: MediaMetadataV1 | null = file.media
        const taken = media?.takenAt
        return {
          id: file.id,
          // No folder here: the link reaches the photo, nothing around it.
          folder: {
            source: 'shared', id: item.file.collectionId, parentId: null, name: null, key: null, keyEpoch: item.file.keyEpoch,
            ownerUserId: share.ownerUserId, ownerAuthorityPublicKey: '', epochStatementHash: '', nameRevision: 1, color: null,
            createdAt: item.file.createdAt, updatedAt: item.file.createdAt, ownerAccount: null,
            canUpload: false, canDelete: false, canManage: false, isRoot: false,
          },
          file,
          kind,
          media,
          takenAt: taken ?? Date.parse(item.file.createdAt),
          takenOffset: taken !== undefined ? media?.takenOffset : undefined,
          dated: taken !== undefined,
        }
      } catch {
        return null
      }
    }),
  )
  return { name, photos: newestFirst(joinLivePhotos(photos.filter((p): p is PublicPhoto => Boolean(p)))) }
}

/** A photo's thumbnail through the link. */
export function publicThumbnail(token: string, photo: PublicPhoto, variant: 'sm' | 'lg'): Promise<string | null> {
  return thumbnailUrl(photo.file, variant, `${base(token)}/thumbnails/${photo.id}/${variant}`)
}

/** A photo's content through the link, decrypted as it streams. */
export async function readPublicOriginal(token: string, photo: PublicPhoto, signal?: AbortSignal): Promise<Blob> {
  const file = photo.file
  const key = await fileKeyAt(file, file.contentKeyGeneration)
  const url = `${await resolveApiBase()}${base(token)}/download/${file.id}`
  const parts: BlobPart[] = []
  for await (const { plain } of fetchDecryptedChunks(url, key, { fileId: file.id, generation: file.contentKeyGeneration }, '', signal)) {
    parts.push(new Blob([plain as BlobPart]))
  }
  return new Blob(parts, { type: file.mimeType })
}
