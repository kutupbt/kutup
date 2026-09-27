import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { createOwnedCollectionV1, openFileMetadataV1, openOwnedCollectionV1, renameOwnedCollectionV1 } from '@kutup/crypto'
import { openAlbumFileKeyV1, sealAlbumFileKeyV1 } from '@kutup/crypto/album'
import { toDriveFile } from '@kutup/drive-core/files'
import type { FolderIndex } from '@kutup/drive-core/folders'
import { useDriveIdentity, type DriveIdentity } from '@kutup/drive-core/identity'
import type { Folder } from '@kutup/drive-core/model'
import type { FileRow } from '@kutup/session/api-types'
import api from '@kutup/session/client'
import { joinLivePhotos, toPhoto, type Photo } from '../library/library'
import { newestFirst } from '../library/timeline'

// Albums (docs/plans/photos.md): collections of kind `album` that hold
// references to photos. Each item is a file and its key sealed under the
// album key; the photo stays one file wherever it is, counted once.

interface AlbumWire {
  id: string
  ownerUserId: string
  nameEnvelope: string
  ownerKeyEnvelope: string
  keyEpoch: number
  nameRevision: number
  epochStatement: string
  epochStatementHash: string
  itemCount: number
  createdAt: string
  updatedAt: string
}

export interface Album {
  id: string
  name: string
  key: Uint8Array
  keyEpoch: number
  nameRevision: number
  ownerUserId: string
  itemCount: number
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

export const albumsKey = ['albums'] as const
export const albumItemsKey = (id: string) => ['album-items', id] as const

export function useAlbums() {
  const identity = useDriveIdentity()
  return useQuery({
    queryKey: [...albumsKey, identity.data?.userId],
    enabled: identity.isSuccess,
    queryFn: async (): Promise<Album[]> => {
      const me = identity.data!
      const { data } = await api.get<AlbumWire[]>('/albums')
      const opened = await Promise.all(
        data.map(async (row): Promise<Album | null> => {
          try {
            const { collectionKey, name } = await openOwnedCollectionV1(row, me.masterKey)
            return {
              id: row.id,
              name,
              key: collectionKey,
              keyEpoch: row.keyEpoch,
              nameRevision: row.nameRevision,
              ownerUserId: row.ownerUserId,
              itemCount: row.itemCount,
              updatedAt: row.updatedAt,
            }
          } catch {
            return null
          }
        }),
      )
      return opened.filter((a): a is Album => Boolean(a)).sort((a, b) => b.updatedAt.localeCompare(a.updatedAt))
    },
  })
}

/** Where an album's photo is: its folder when this account has it, else a stand-in for the album. */
function folderFor(index: FolderIndex | undefined, row: FileRow, album: Album): Folder {
  const known = index?.byId.get(row.collectionId)
  if (known) return known
  return {
    source: 'owned',
    id: row.collectionId,
    parentId: null,
    name: album.name,
    key: null,
    keyEpoch: row.keyEpoch,
    ownerUserId: album.ownerUserId,
    ownerAuthorityPublicKey: '',
    epochStatementHash: '',
    nameRevision: 1,
    color: null,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
    ownerAccount: null,
    canUpload: false,
    canDelete: false,
    canManage: false,
    isRoot: false,
  }
}

/** An album's photos, opened with its key. Items sealed at an older file key are re-sealed (their owner may). */
export function useAlbumItems(album: Album | undefined, index: FolderIndex | undefined, library: readonly Photo[]) {
  const queryClient = useQueryClient()
  return useQuery({
    queryKey: [...albumItemsKey(album?.id ?? ''), album?.keyEpoch],
    enabled: Boolean(album),
    queryFn: async (): Promise<Photo[]> => {
      const a = album!
      const { data } = await api.get<AlbumItemWire[]>(`/albums/${a.id}/items`)
      const stale: Photo[] = []
      const photos = await Promise.all(
        data.map(async (item): Promise<Photo | null> => {
          const current = item.keyGeneration === item.file.keyGeneration
          if (!current) {
            // The photo moved to a new key since it was added: re-seal it
            // from the library's copy, which has the current key.
            const mine = library.find((p) => p.id === item.file.id)
            if (mine) stale.push(mine)
            return mine ?? null
          }
          try {
            const fileKey = await openAlbumFileKeyV1(item.fileKeyEnvelope, a.key, {
              fileId: item.file.id,
              albumId: a.id,
              albumEpoch: item.albumEpoch,
              generation: item.keyGeneration,
            })
            const metadata = await openFileMetadataV1(item.file, fileKey)
            return toPhoto(folderFor(index, item.file, a), toDriveFile(item.file, { fileKey, metadata }))
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
                albumEpoch: album.keyEpoch,
                generation: p.file.keyGeneration,
              }).then((fileKeyEnvelope) => ({ fileId: p.id, fileKeyEnvelope, keyGeneration: p.file.keyGeneration })),
            ]
          : [],
      ),
    )
    if (items.length) await api.post(`/albums/${album.id}/items`, { items })
  }
}

/** A new album, empty; the album as it now is. */
export async function createAlbum(me: DriveIdentity, name: string): Promise<Album> {
  const created = await createOwnedCollectionV1(me.masterKey, me.userId, name.trim(), null)
  await api.post('/albums', created.payload)
  return {
    id: created.payload.id,
    name: name.trim(),
    key: created.collectionKey,
    keyEpoch: 1,
    nameRevision: 1,
    ownerUserId: me.userId,
    itemCount: 0,
    updatedAt: new Date().toISOString(),
  }
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
      { id: album.id, ownerUserId: album.ownerUserId, keyEpoch: album.keyEpoch, nameRevision: album.nameRevision },
      album.key,
      name.trim(),
    )
    await api.put(`/collections/${album.id}`, next)
  })
}

export function useDeleteAlbum() {
  return useAlbumMutation(({ album }: { album: Album }) => api.delete(`/albums/${album.id}`))
}
