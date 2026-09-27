import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { createOwnedCollectionV1, openFileMetadataV1, renameOwnedCollectionV1 } from '@kutup/crypto'
import { openAlbumFileKeyV1, sealAlbumFileKeyV1 } from '@kutup/crypto/album'
import { rotateFolder, type FolderAccess, type Removal } from '@kutup/drive-core/access'
import { toDriveFile } from '@kutup/drive-core/files'
import { openRemote, openRow, type CollectionRowWithTimes, type FolderIndex, type IncomingShare } from '@kutup/drive-core/folders'
import { useDriveIdentity, type DriveIdentity } from '@kutup/drive-core/identity'
import type { Folder } from '@kutup/drive-core/model'
import type { FileRow } from '@kutup/session/api-types'
import api from '@kutup/session/client'
import { joinLivePhotos, toPhoto, type Photo } from '../library/library'
import { newestFirst } from '../library/timeline'

// Albums (docs/plans/photos.md): collections of kind `album` that hold
// references to photos. Each item is a file and its key sealed under the
// album key; the photo stays one file wherever it is, counted once. An album
// is opened, shared and re-keyed as a Drive folder is (it is one to
// drive-core), so its owner shares it with people who may view it or add
// their own photos to it, and with people on other servers, who view it
// through their own server (`/drive/federation/shares/:id/album`).

export interface Album {
  /** The album as a collection: its key, epoch, owner and this account's rights. */
  folder: Folder
  id: string
  name: string
  key: Uint8Array
  itemCount: number
  /** This account made it. */
  owned: boolean
  /** This account may put its own photos in. */
  canAdd: boolean
  /** `user@server` of whoever shared it (not for your own). */
  ownerAccount: string | null
  updatedAt: string
}

interface AlbumItemWire {
  file: FileRow
  fileKeyEnvelope: string
  keyGeneration: number
  albumEpoch: number
  addedBy?: string
  addedAt: string
}

/** An album on another server that its owner stopped sharing with you (or deleted). */
export class AlbumGone extends Error {
  constructor() {
    super('album no longer shared')
  }
}

/** An item of an album on another server, as its owner's server lists it. */
interface RemoteAlbumItemWire {
  file: Omit<FileRow, 'thumbnails'>
  thumbnails: FileRow['thumbnails']
  fileKeyEnvelope: string
  keyGeneration: number
  albumEpoch: number
}

interface AlbumKeyWire {
  fileId: string
  fileKeyEnvelope: string
  keyGeneration: number
  albumEpoch: number
}

export const albumsKey = ['albums'] as const
export const albumItemsKey = (id: string) => ['album-items', id] as const

function toAlbum(folder: Folder, itemCount: number): Album | null {
  if (!folder.key || !folder.name) return null
  return {
    folder,
    id: folder.id,
    name: folder.name,
    key: folder.key,
    itemCount,
    owned: folder.canManage,
    canAdd: folder.canUpload,
    ownerAccount: folder.ownerAccount,
    updatedAt: folder.updatedAt,
  }
}

export function useAlbums() {
  const identity = useDriveIdentity()
  return useQuery({
    queryKey: [...albumsKey, identity.data?.userId],
    enabled: identity.isSuccess,
    queryFn: async (): Promise<Album[]> => {
      const me = identity.data!
      const [local, remote] = await Promise.all([
        api.get<(CollectionRowWithTimes & { itemCount: number })[]>('/albums'),
        api.get<IncomingShare[]>('/drive/federation/shares', { params: { kind: 'album' } }),
      ])
      const opened = await Promise.all([
        ...local.data.map(async (row) => toAlbum(await openRow(row, me), row.itemCount)),
        // From another server: shown once it verifies; its count comes with its photos.
        ...remote.data.map(async (share) => {
          const folder = await openRemote(share, me)
          return folder ? toAlbum(folder, 0) : null
        }),
      ])
      return opened.filter((a): a is Album => Boolean(a)).sort((a, b) => b.updatedAt.localeCompare(a.updatedAt))
    },
  })
}

/**
 * Where an album's photo is: its folder when this account has it, else a
 * stand-in that grants nothing (someone else's photo, seen through the
 * album: it can be viewed and downloaded, not changed, moved or shared).
 */
function folderFor(index: FolderIndex | undefined, row: FileRow, album: Album): Folder {
  const known = album.folder.source === 'remote' ? undefined : index?.byId.get(row.collectionId)
  if (known) return known
  return {
    // On another server, the photo is read through the album's share there.
    ...(album.folder.source === 'remote' ? { source: 'remote' as const, remoteShareId: album.folder.remoteShareId } : { source: 'shared' as const }),
    id: row.collectionId,
    parentId: null,
    name: null,
    key: null,
    keyEpoch: row.keyEpoch,
    ownerUserId: '',
    ownerAuthorityPublicKey: '',
    epochStatementHash: '',
    nameRevision: 1,
    color: null,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
    ownerAccount: album.ownerAccount,
    canUpload: false,
    canDelete: false,
    canManage: false,
    isRoot: false,
  }
}

/** An album's photos, opened with its key. Items sealed at an older file key are re-sealed by whoever has the current one. */
export function useAlbumItems(album: Album | undefined, index: FolderIndex | undefined, library: readonly Photo[]) {
  const queryClient = useQueryClient()
  return useQuery({
    queryKey: [...albumItemsKey(album?.id ?? ''), album?.folder.keyEpoch],
    enabled: Boolean(album),
    retry: (count, error) => !(error instanceof AlbumGone) && count < 2,
    queryFn: async (): Promise<Photo[]> => {
      const a = album!
      if (a.folder.source === 'remote') return remoteAlbumItems(a, () => queryClient.invalidateQueries({ queryKey: albumsKey }))
      const { data } = await api.get<AlbumItemWire[]>(`/albums/${a.id}/items`)
      const stale: Photo[] = []
      const photos = await Promise.all(
        data.map(async (item): Promise<Photo | null> => {
          const current = item.keyGeneration === item.file.keyGeneration
          if (!current) {
            // The photo moved to a new key since it was added: its owner
            // re-seals it from the library's copy, which has the current key.
            const mine = library.find((p) => p.id === item.file.id)
            if (mine && a.canAdd) stale.push(mine)
            return mine ? { ...mine, addedBy: item.addedBy } : null
          }
          try {
            const fileKey = await openAlbumFileKeyV1(item.fileKeyEnvelope, a.key, {
              fileId: item.file.id,
              albumId: a.id,
              albumEpoch: item.albumEpoch,
              generation: item.keyGeneration,
            })
            const metadata = await openFileMetadataV1(item.file, fileKey)
            const photo = toPhoto(folderFor(index, item.file, a), toDriveFile(item.file, { fileKey, metadata }))
            return photo ? { ...photo, addedBy: item.addedBy } : null
          } catch {
            return null
          }
        }),
      )
      if (stale.length) {
        void addToAlbum(a, stale).then(() => queryClient.invalidateQueries({ queryKey: albumItemsKey(a.id) }))
      }
      return newestFirst(joinLivePhotos(photos.filter((p): p is Photo => Boolean(p))))
    },
  })
}

/**
 * The photos of an album on another server. When its owner has moved it to
 * a new key since this server last looked, the share is refreshed first
 * (the new key comes sealed to this account, its epoch chain checked), and
 * the album list reloads with it.
 */
async function remoteAlbumItems(album: Album, reloadAlbums: () => Promise<void>): Promise<Photo[]> {
  const shareId = album.folder.remoteShareId!
  let data: RemoteAlbumItemWire[]
  try {
    data = (await api.get<RemoteAlbumItemWire[]>(`/drive/federation/shares/${shareId}/album`)).data
  } catch (error) {
    if ((error as { response?: { status?: number } }).response?.status === 404) throw new AlbumGone()
    throw error
  }
  if (data.some((item) => item.albumEpoch > album.folder.keyEpoch)) {
    await api.post(`/drive/federation/shares/${shareId}/refresh`)
    await reloadAlbums()
    return []
  }
  const photos = await Promise.all(
    data.map(async (item): Promise<Photo | null> => {
      try {
        if (item.keyGeneration !== item.file.keyGeneration) return null
        const fileKey = await openAlbumFileKeyV1(item.fileKeyEnvelope, album.key, {
          fileId: item.file.id,
          albumId: album.id,
          albumEpoch: item.albumEpoch,
          generation: item.keyGeneration,
        })
        const row: FileRow = { ...item.file, thumbnails: item.thumbnails }
        const metadata = await openFileMetadataV1(row, fileKey)
        return toPhoto(folderFor(undefined, row, album), toDriveFile(row, { fileKey, metadata }))
      } catch {
        return null
      }
    }),
  )
  return newestFirst(joinLivePhotos(photos.filter((p): p is Photo => Boolean(p))))
}

/** Seal each photo's current key under the album key and add them. */
export async function addToAlbum(album: Album, photos: readonly Photo[]): Promise<void> {
  const parts = photos.flatMap((p) => (p.live ? [p, p.live] : [p]))
  for (let i = 0; i < parts.length; i += 500) {
    const items = await Promise.all(
      parts.slice(i, i + 500).flatMap((p) =>
        p.file.fileKey
          ? [
              sealAlbumFileKeyV1(p.file.fileKey, album.key, {
                fileId: p.id,
                albumId: album.id,
                albumEpoch: album.folder.keyEpoch,
                generation: p.file.keyGeneration,
              }).then((fileKeyEnvelope) => ({ fileId: p.id, fileKeyEnvelope, keyGeneration: p.file.keyGeneration })),
            ]
          : [],
      ),
    )
    if (items.length) await api.post(`/albums/${album.id}/items`, { items })
  }
}

/**
 * Take people or links away from an album: a rotation, as for a folder, with
 * every photo's key re-sealed under the new album key in the same request.
 */
export async function rotateAlbum(album: Album, me: DriveIdentity, access: FolderAccess, removed: Removal): Promise<void> {
  const { data: keys } = await api.get<AlbumKeyWire[]>(`/albums/${album.id}/keys`)
  const fileKeys = await Promise.all(
    keys.map(async (k) => ({
      k,
      fileKey: await openAlbumFileKeyV1(k.fileKeyEnvelope, album.key, {
        fileId: k.fileId,
        albumId: album.id,
        albumEpoch: k.albumEpoch,
        generation: k.keyGeneration,
      }),
    })),
  )
  await rotateFolder(album.folder, me, access, removed, async (key, epoch) => ({
    albumItems: await Promise.all(
      fileKeys.map(async ({ k, fileKey }) => ({
        fileId: k.fileId,
        fileKeyEnvelope: await sealAlbumFileKeyV1(fileKey, key, {
          fileId: k.fileId,
          albumId: album.id,
          albumEpoch: epoch,
          generation: k.keyGeneration,
        }),
      })),
    ),
  }))
}

/** A new album, empty. */
export async function createAlbum(me: DriveIdentity, name: string): Promise<Album> {
  const created = await createOwnedCollectionV1(me.masterKey, me.userId, name.trim(), null)
  await api.post('/albums', created.payload)
  const now = new Date().toISOString()
  return toAlbum(
    {
      source: 'owned',
      id: created.payload.id,
      parentId: null,
      name: name.trim(),
      key: created.collectionKey,
      keyEpoch: 1,
      ownerUserId: me.userId,
      ownerAuthorityPublicKey: me.authorityPublicKey,
      epochStatementHash: created.epochStatementHash,
      nameRevision: 1,
      color: null,
      createdAt: now,
      updatedAt: now,
      ownerAccount: null,
      canUpload: true,
      canDelete: true,
      canManage: true,
      isRoot: false,
    },
    0,
  )!
}

function useAlbumMutation<T>(fn: (input: T, me: DriveIdentity) => Promise<unknown>) {
  const queryClient = useQueryClient()
  const identity = useDriveIdentity()
  return useMutation({
    mutationFn: async (input: T) => {
      if (!identity.data) throw new Error('not ready')
      return fn(input, identity.data)
    },
    onSuccess: async () => {
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: albumsKey }),
        queryClient.invalidateQueries({ queryKey: ['album-items'] }),
        queryClient.invalidateQueries({ queryKey: ['folder-access'] }),
      ])
    },
  })
}

export function useCreateAlbum() {
  return useAlbumMutation(async ({ name, photos }: { name: string; photos?: readonly Photo[] }, me) => {
    const album = await createAlbum(me, name)
    if (photos?.length) await addToAlbum(album, photos)
    return album.id
  })
}

export function useAddToAlbum() {
  return useAlbumMutation(({ album, photos }: { album: Album; photos: readonly Photo[] }) => addToAlbum(album, photos))
}

export function useRemoveFromAlbum() {
  return useAlbumMutation(({ album, photos }: { album: Album; photos: readonly Photo[] }) =>
    api.post(`/albums/${album.id}/items/remove`, { fileIds: photos.flatMap((p) => (p.live ? [p.id, p.live.id] : [p.id])) }),
  )
}

export function useRenameAlbum() {
  return useAlbumMutation(async ({ album, name }: { album: Album; name: string }) => {
    const next = await renameOwnedCollectionV1(
      { id: album.id, ownerUserId: album.folder.ownerUserId, keyEpoch: album.folder.keyEpoch, nameRevision: album.folder.nameRevision },
      album.key,
      name.trim(),
    )
    await api.put(`/collections/${album.id}`, next)
  })
}

export function useDeleteAlbum() {
  return useAlbumMutation(({ album }: { album: Album }) => api.delete(`/albums/${album.id}`))
}

/** Leave an album shared with you; the photos you put in leave with you. */
export function useLeaveAlbum() {
  return useAlbumMutation(({ album }: { album: Album }) =>
    album.folder.source === 'remote'
      ? api.delete(`/drive/federation/shares/${album.folder.remoteShareId}`)
      : api.delete(`/albums/${album.id}/membership`),
  )
}

export function useRemoveAlbumAccess() {
  return useAlbumMutation(async ({ album, removed }: { album: Album; removed: Removal }, me) => {
    // Built from access as it is now: anyone added since stays.
    const { data: access } = await api.get<FolderAccess>(`/collections/${album.id}/access`)
    await rotateAlbum(album, me, access, removed)
  })
}
