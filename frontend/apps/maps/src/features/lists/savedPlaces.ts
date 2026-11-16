import { useQueries } from '@tanstack/react-query'
import { listVersions } from '@kutup/collab/api'
import { currentContentOf, relayedVersion, versionContentOf, type RelayedState } from '@kutup/drive-core/keyring'
import { contentPath, fileLocation, remoteStatePath, type DriveFile, type Folder } from '@kutup/drive-core/model'
import { fromBase64, openDriveObject } from '@kutup/crypto'
import { parseListJson, stateToListJson, uploadPlaceId, type Place } from '@kutup/map/list'
import api from '@kutup/session/client'
import type { ListEntry } from './lists'

/** The places a list was created with (its upload), for a list never saved. */
export async function uploadedPlaces(file: DriveFile, folder?: Pick<Folder, 'source' | 'remoteShareId' | 'remoteFileShareId'>): Promise<Place[]> {
  const path = folder ? contentPath(fileLocation(folder), file.id) : `/files/${file.id}/download`
  const { data } = await api.get<ArrayBuffer>(path, { responseType: 'arraybuffer' })
  // The file's own content, against what its metadata commits to.
  const opened = await currentContentOf(file)
  // A list's first content: places without an id get the same one on every
  // peer (and in the CLI), so seeds made at once are one.
  return parseListJson(await openDriveObject(new Uint8Array(data), opened.fileKey, opened.expected), (index) =>
    uploadPlaceId(file.id, index),
  )
}

/**
 * A list's places as last saved: its newest version, else its upload. Not
 * live (edits of the last half minute may not be saved yet); opening the
 * list joins the live session.
 */
export async function savedPlaces(file: DriveFile, folder?: Pick<Folder, 'source' | 'remoteShareId' | 'remoteFileShareId'>): Promise<Place[]> {
  // On another server: its saved state relayed through this one.
  const remote = folder ? remoteStatePath(fileLocation(folder), file.id) : null
  if (remote) {
    let saved: RelayedState
    try {
      saved = (await api.get<RelayedState>(remote)).data
    } catch (error) {
      if ((error as { response?: { status?: number } }).response?.status === 404) return uploadedPlaces(file, folder)
      throw error
    }
    // A saved state relayed with its sealed content record.
    const opened = await versionContentOf(file, relayedVersion(saved))
    return parseListJson(stateToListJson(await openDriveObject(fromBase64(saved.state), opened.fileKey, opened.expected)))
  }
  const latest = (await listVersions(file.id))[0]
  if (!latest || latest.sizeBytes === 0) return uploadedPlaces(file)
  const { data } = await api.get<ArrayBuffer>(`/files/${file.id}/versions/${latest.id}/download`, { responseType: 'arraybuffer' })
  const opened = await versionContentOf(file, latest)
  const state = await openDriveObject(new Uint8Array(data), opened.fileKey, opened.expected)
  return parseListJson(stateToListJson(state))
}

export const savedPlacesKey = (fileId: string) => ['list-places', fileId] as const

/** Every list's saved places, each loaded on its own (one slow list holds up nothing). */
export function useSavedPlaces(lists: ListEntry[]) {
  const openable = lists.filter((l) => l.file.fileKey)
  const results = useQueries({
    queries: openable.map((entry) => ({
      queryKey: [...savedPlacesKey(entry.file.id), entry.file.keyGeneration],
      queryFn: () => savedPlaces(entry.file, entry.folder),
      staleTime: 60_000,
    })),
  })
  const byFile = new Map<string, Place[]>()
  results.forEach((result, i) => {
    const entry = openable[i]
    if (entry && result.data) byFile.set(entry.file.id, result.data)
  })
  return { byFile, loading: results.some((r) => r.isPending) }
}

// Clearly different hues, none close to the selected pin's blue, in the
// order lists are given them.
const PALETTE = ['#dc2626', '#16a34a', '#d97706', '#7c3aed', '#0891b2', '#db2777', '#65a30d', '#ea580c', '#4338ca', '#92400e']

/**
 * Each list's colour on the map: by the order the lists were made (oldest
 * first), so the first ten never share or resemble one.
 */
export function listColors(fileIds: { id: string; createdAt: string }[]): Map<string, string> {
  const ordered = [...fileIds].sort((a, b) => a.createdAt.localeCompare(b.createdAt) || a.id.localeCompare(b.id))
  return new Map(ordered.map((f, i) => [f.id, PALETTE[i % PALETTE.length]]))
}

/** For a list not (yet) among them. */
export const FALLBACK_COLOR = '#64748b'
