import { isAxiosError } from 'axios'
import { renameFileRecordV1, renameOwnedCollectionV1 } from '@kutup/crypto'
import { hashBlob } from '@kutup/crypto/contentHash'
import {
  contentHash as contentHashOf,
  folderHashKey,
  nameHash as nameHashOf,
  topLevelHashKey,
} from '@kutup/crypto/driveNames'
import { UploadNameTaken } from '@kutup/files/upload/streamUpload'
import api from '@kutup/session/client'
import { loadFolderFiles } from './files'
import { folderKeyAt, type KeyringFolder } from './keyring'
import { fileMetadataOf, folderLocation, type DriveFile, type Folder } from './model'
import { rekeyFile } from './rekey'

/**
 * Names unique in a folder (docs/plans/drive-unique-names.md). Every write
 * that names something sends the name's hash under its place's hash key —
 * the folder's, from its first key, or the account's for top-level folders
 * — and the server keeps the hashes apart without reading a name. A file's
 * content hash, under the same key, lets an upload of a file already there
 * be skipped.
 */

/** Where a name lives: in a folder, or at the account's top level. */
export type NamePlace = { kind: 'folder'; folder: KeyringFolder } | { kind: 'top'; masterKey: Uint8Array }

const folderKeys = new Map<string, Promise<Uint8Array>>()
let topKey: { masterKey: Uint8Array; key: Promise<Uint8Array> } | null = null

function hashKey(place: NamePlace): Promise<Uint8Array> {
  if (place.kind === 'top') {
    if (topKey?.masterKey !== place.masterKey) topKey = { masterKey: place.masterKey, key: topLevelHashKey(place.masterKey) }
    return topKey.key
  }
  const { folder } = place
  // The first key, reached through the folder's history: the same through
  // every rotation, so the cache is per folder.
  let pending = folderKeys.get(folder.id)
  if (!pending) {
    pending = folderKeyAt(folder, 1).then((first) => folderHashKey(first, folder.id))
    pending.catch(() => folderKeys.delete(folder.id))
    folderKeys.set(folder.id, pending)
  }
  return pending
}

export const inFolder = (folder: KeyringFolder): NamePlace => ({ kind: 'folder', folder })
export const atTopLevel = (masterKey: Uint8Array): NamePlace => ({ kind: 'top', masterKey })

/** The hash `name` is kept unique by in `place`. */
export async function nameHashIn(place: NamePlace, name: string): Promise<string> {
  return nameHashOf(await hashKey(place), name)
}

/** The hash a file's content is recognised by in `folder`, from its SHA-256 (base64). */
export async function contentHashIn(folder: KeyringFolder, contentSha256: string): Promise<string> {
  return contentHashOf(await hashKey(inFolder(folder)), contentSha256)
}

/**
 * The form two names are compared in on this device: NFC, Unicode's
 * default lowercase, NFC — what `kutup_crypto::drive_names::canonical_name`
 * does (both lowercase without a locale; tested against it). The hashes
 * themselves always come from Rust.
 */
export function canonicalName(name: string): string {
  return name.normalize('NFC').toLowerCase().normalize('NFC')
}

/** What holds a taken name, as the server says. */
export interface NameHolder {
  kind: 'file' | 'folder'
  id: string
  contentHash: string | null
}

/** The name is taken in that place (`409 name_taken`). */
export class NameTaken extends Error {
  constructor(readonly holder: NameHolder | null) {
    super('an item with this name is already here')
  }
}

/** The holder of a `409 name_taken` from a response body; null if it is not one. */
export function nameTakenFromBody(status: number, body: unknown): NameTaken | null {
  if (status !== 409 || !body || typeof body !== 'object') return null
  const { code, holder } = body as { code?: unknown; holder?: Partial<NameHolder> }
  if (code !== 'name_taken') return null
  const valid = holder && (holder.kind === 'file' || holder.kind === 'folder') && typeof holder.id === 'string'
  return new NameTaken(valid ? { kind: holder.kind!, id: holder.id!, contentHash: holder.contentHash ?? null } : null)
}

/** `error` as a `NameTaken` when it is one (an API call or an upload refused for the name). */
export function asNameTaken(error: unknown): NameTaken | null {
  if (error instanceof NameTaken) return error
  if (error instanceof UploadNameTaken) return new NameTaken(error.holder)
  if (isAxiosError(error) && error.response) return nameTakenFromBody(error.response.status, error.response.data)
  return null
}

/**
 * The first of `name (2)`, `name (3)`, … not in `taken` (canonical names);
 * a file's extension stays at the end. A name already ending in a number in
 * brackets counts on from it.
 */
export function freeName(name: string, taken: ReadonlySet<string>): string {
  if (!taken.has(canonicalName(name))) return name
  const dot = name.lastIndexOf('.')
  const [stem, extension] = dot > 0 ? [name.slice(0, dot), name.slice(dot)] : [name, '']
  const numbered = /^(.*) \((\d+)\)$/.exec(stem)
  const base = numbered ? numbered[1] : stem
  for (let n = numbered ? Number(numbered[2]) + 1 : 2; ; n++) {
    const candidate = `${base} (${n})${extension}`
    if (!taken.has(canonicalName(candidate))) return candidate
  }
}

/** `name` without the ` (n)` `freeName` adds before its extension. */
export function unnumberedName(name: string): string {
  const dot = name.lastIndexOf('.')
  const [stem, extension] = dot > 0 ? [name.slice(0, dot), name.slice(dot)] : [name, '']
  return `${stem.replace(/ \(\d+\)$/, '')}${extension}`
}

/** The canonical names in a folder: its files' and its subfolders'. */
export function namesIn(files: Pick<DriveFile, 'name'>[], subfolders: Pick<Folder, 'name'>[]): Set<string> {
  const names = new Set<string>()
  for (const item of [...files, ...subfolders]) if (item.name) names.add(canonicalName(item.name))
  return names
}

/** What is directly in a folder, as listed and decrypted. */
export interface FolderListing {
  files: DriveFile[]
  subfolders: Folder[]
}

/** What an upload of `file` into a folder comes to, against its listing. */
export type UploadPlan =
  /** The name is free. */
  | { kind: 'free' }
  /** A file with the name and the same content is there: nothing to send. */
  | { kind: 'same'; holder: DriveFile }
  /** Something else holds the name: the person chooses. */
  | { kind: 'taken'; holder: { kind: 'file'; file: DriveFile } | { kind: 'folder'; folder: Folder } }

/**
 * Whether `file` can go into `folder` under its name. A file with that name
 * and the same size whose content hash is known has the local file hashed
 * (SHA-256, the whole file read once) to tell an identical file from a
 * different one; one without a content hash (uploaded before this, or
 * edited since) is always a choice, never skipped silently.
 */
export async function planUpload(folder: Folder, file: File, listing: FolderListing, signal?: AbortSignal): Promise<UploadPlan> {
  const name = canonicalName(file.name)
  const subfolder = listing.subfolders.find((f) => f.name !== null && canonicalName(f.name) === name)
  if (subfolder) return { kind: 'taken', holder: { kind: 'folder', folder: subfolder } }
  const holder = listing.files.find((f) => f.name !== null && canonicalName(f.name) === name)
  if (!holder) return { kind: 'free' }
  if (holder.contentHash && holder.size === file.size && folder.key) {
    const digest = await hashBlob(file, signal)
    if ((await contentHashIn(folder, digest)) === holder.contentHash) return { kind: 'same', holder }
  }
  return { kind: 'taken', holder: { kind: 'file', file: holder } }
}

/**
 * Record what a just-uploaded file's content is recognised by in its folder
 * (`PUT /files/:id/content-hash`). Best effort: without it, a later upload
 * of the same file asks instead of being skipped. Folders on other servers
 * keep no content hash yet.
 */
export async function recordContentHash(folder: Folder, fileId: string, contentSha256: string | null): Promise<void> {
  if (!contentSha256 || !folder.key || folderLocation(folder).kind !== 'local') return
  try {
    await api.put(`/files/${fileId}/content-hash`, { contentHash: await contentHashIn(folder, contentSha256) })
  } catch (error) {
    console.warn('names: could not record a content hash', error)
  }
}

/**
 * Upload `file` into `folder` under its name, sent with the name's hash;
 * if the server finds the name taken, under the next free name
 * (`name (2)`…) instead. For uploads that never replace anything (a photo
 * whose camera reused a name, a new document), so nothing is asked. Its
 * content hash is recorded once it is stored.
 */
export async function uploadUnderFreeName<T extends { fileId: string; contentSha256: string | null }>(
  folder: Folder,
  file: File,
  upload: (file: File, nameHash: string) => Promise<T>,
): Promise<T> {
  let attempt = file
  const tried = new Set<string>()
  for (;;) {
    try {
      const uploaded = await upload(attempt, await nameHashIn(inFolder(folder), attempt.name))
      await recordContentHash(folder, uploaded.fileId, uploaded.contentSha256)
      return uploaded
    } catch (error) {
      if (!asNameTaken(error) || tried.size >= 5) throw error
      tried.add(canonicalName(attempt.name))
      const taken = namesIn(await loadFolderFiles(folder), [])
      for (const name of tried) taken.add(name)
      attempt = new File([file], freeName(file.name, taken), { type: file.type, lastModified: file.lastModified })
    }
  }
}

/** The most items the server fills in at once. */
const FILL_BATCH = 500

interface Pending {
  kind: 'file' | 'folder'
  id: string
  name: string
  createdAt: string
}

/**
 * Items made before names were kept unique (or by a client that sent no
 * hash) get their hashes, oldest first; one whose name an earlier item
 * holds is renamed `name (2)` and takes that name's hash. Only the folder's
 * owner does this — they can rename everything in it. Quietly gives up on
 * anything it cannot do: the next visit tries again.
 *
 * `place` is the folder the items are in, or the top level for the owner's
 * top-level folders (then `files` is empty).
 */
export async function fillInNames(
  place: NamePlace,
  files: DriveFile[],
  subfolders: Folder[],
  ownerUserId: string,
  folderForFiles: Folder | null,
): Promise<boolean> {
  const pending: Pending[] = [
    ...files.filter((f) => !f.nameHash && f.name).map((f) => ({ kind: 'file' as const, id: f.id, name: f.name!, createdAt: f.createdAt })),
    ...subfolders
      .filter((f) => !f.nameHash && f.name && f.source === 'owned')
      .map((f) => ({ kind: 'folder' as const, id: f.id, name: f.name!, createdAt: f.createdAt })),
  ].sort((a, b) => a.createdAt.localeCompare(b.createdAt))
  if (pending.length === 0) return false
  const path = place.kind === 'top' ? '/drive/top-level-name-hashes' : `/collections/${place.folder.id}/name-hashes`
  const clashing: Pending[] = []
  for (let at = 0; at < pending.length; at += FILL_BATCH) {
    const batch = pending.slice(at, at + FILL_BATCH)
    const withHashes = await Promise.all(batch.map(async (item) => ({ item, nameHash: await nameHashIn(place, item.name) })))
    const { data } = await api.post<{ clashes: { id: string }[] }>(path, {
      files: withHashes.filter((x) => x.item.kind === 'file').map((x) => ({ id: x.item.id, nameHash: x.nameHash })),
      folders: withHashes.filter((x) => x.item.kind === 'folder').map((x) => ({ id: x.item.id, nameHash: x.nameHash })),
    })
    const clashed = new Set(data.clashes.map((c) => c.id))
    clashing.push(...batch.filter((item) => clashed.has(item.id)))
  }
  if (clashing.length === 0) return true
  const taken = namesIn(files, subfolders)
  for (const item of clashing) {
    const name = freeName(item.name, taken)
    taken.add(canonicalName(name))
    const nameHash = await nameHashIn(place, name)
    try {
      if (item.kind === 'file') {
        const listed = files.find((f) => f.id === item.id)
        if (!listed || !folderForFiles) continue
        const file = await rekeyFile(folderForFiles, listed)
        if (!file.fileKey) continue
        const next = await renameFileRecordV1(
          { id: file.id, keyGeneration: file.keyGeneration, metadataRevision: file.metadataRevision },
          file.fileKey,
          fileMetadataOf(file, { name }),
        )
        await api.put(`/files/${file.id}`, { ...next, nameHash })
      } else {
        const folder = subfolders.find((f) => f.id === item.id)
        if (!folder?.key) continue
        const next = await renameOwnedCollectionV1(
          { id: folder.id, ownerUserId, keyEpoch: folder.keyEpoch, nameRevision: folder.nameRevision },
          folder.key,
          name,
        )
        await api.put(`/collections/${folder.id}`, { ...next, nameHash })
      }
    } catch (error) {
      console.warn('names: could not rename a duplicate', error)
    }
  }
  return true
}
