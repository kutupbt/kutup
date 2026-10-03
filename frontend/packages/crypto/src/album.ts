import { openDriveEnvelope, sealDriveEnvelope, DRIVE_ENVELOPE_PURPOSE } from './driveEnvelope'

/**
 * A photo in an album (docs/plans/photos.md): the album holds a reference
 * to the file and the file's key sealed under the album's key, bound to the
 * file, the album, the album's key epoch and the file key's generation.
 */
export interface AlbumFileContextV1 {
  fileId: string
  albumId: string
  albumEpoch: number
  generation: number
}

function context(c: AlbumFileContextV1) {
  return {
    purpose: DRIVE_ENVELOPE_PURPOSE.albumFileKey,
    epoch: c.albumEpoch,
    revision: BigInt(c.generation),
    objectId: c.fileId,
    parentId: c.albumId,
  } as const
}

export function sealAlbumFileKeyV1(fileKey: Uint8Array, albumKey: Uint8Array, c: AlbumFileContextV1): Promise<string> {
  return sealDriveEnvelope(fileKey, albumKey, context(c))
}

/** Open only as exactly the file, album, epoch and generation its row names. */
export function openAlbumFileKeyV1(envelope: string, albumKey: Uint8Array, c: AlbumFileContextV1): Promise<Uint8Array> {
  return openDriveEnvelope(envelope, albumKey, context(c))
}
