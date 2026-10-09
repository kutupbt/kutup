// The account's one storage pool (docs/api.md, `GET /api/user/storage`): what
// fills it, as the server charges it, split further by file kind using the
// names this browser decrypts. Shared by the Account storage page and the
// storage summary in the Drive, Photos and Office sidebars.

import { useQueries, useQuery } from '@tanstack/react-query'
import api from '@kutup/session/client'
import { useRequiredSession } from '@kutup/session/store'
import { folderFilesKey, loadFolderFiles } from './files'
import { useFolders } from './folders'
import { FILE_KINDS, type FileKind } from './kinds'
import type { DriveFile, Folder } from './model'

export const storageKey = ['storage'] as const

export interface StorageUsage {
  quotaBytes: number
  usedBytes: number
  reservedBytes: number
  drive: {
    filesBytes: number
    filesCount: number
    trashBytes: number
    trashCount: number
    versionsBytes: number
    thumbnailsBytes: number
    assetsBytes: number
  }
  chat: {
    mediaBytes: number
    historyBytes: number
    historyMediaBytes: number
  }
}

export function useStorageUsage(enabled = true) {
  return useQuery({
    queryKey: storageKey,
    enabled,
    queryFn: async () => (await api.get<StorageUsage>('/user/storage')).data,
  })
}

/** Where the pool stands, as Proton grades it: warning from 80 %, danger when full. */
export type StorageLevel = 'ok' | 'warning' | 'danger'

export function storageLevel(usage: Pick<StorageUsage, 'quotaBytes' | 'usedBytes' | 'reservedBytes'>): StorageLevel {
  if (usage.quotaBytes <= 0) return 'danger'
  const ratio = (usage.usedBytes + usage.reservedBytes) / usage.quotaBytes
  return ratio >= 1 ? 'danger' : ratio >= 0.8 ? 'warning' : 'ok'
}

export type UsageCategoryId = FileKind | 'files' | 'trash' | 'versions' | 'previews' | 'chatMedia' | 'chatHistory' | 'reserved'

export interface UsageCategory {
  id: UsageCategoryId
  bytes: number
  /** Files in it, where the browser counted them. */
  count?: number
  /** A CSS colour (a theme token). */
  color: string
}

const COLOR: Record<Exclude<UsageCategoryId, FileKind>, string> = {
  files: 'var(--primary)',
  trash: 'var(--usage-trash)',
  versions: 'var(--usage-versions)',
  previews: 'var(--usage-previews)',
  chatMedia: 'var(--usage-chat)',
  chatHistory: 'var(--usage-chat-history)',
  reserved: 'var(--usage-reserved)',
}

export function categoryColor(id: UsageCategoryId): string {
  return id in COLOR ? COLOR[id as keyof typeof COLOR] : `var(--kind-${id})`
}

/** Plaintext bytes and count of the caller's files, by kind. */
export type KindTotals = Map<FileKind, { bytes: number; count: number }>

/**
 * What fills the pool, largest first, empty categories left out. The server
 * knows only one figure for files; when `kinds` is known it is shared out
 * among them in proportion, so the parts still add up to what is charged.
 */
export function usageCategories(usage: StorageUsage, kinds?: KindTotals | null): UsageCategory[] {
  const { drive, chat } = usage
  const categories: UsageCategory[] = []
  const plain = kinds ? [...kinds.values()].reduce((total, k) => total + k.bytes, 0) : 0
  if (kinds && plain > 0) {
    let left = drive.filesBytes
    const kindsBySize = FILE_KINDS.flatMap((kind) => {
      const total = kinds.get(kind)
      return total ? [{ kind, ...total }] : []
    }).sort((a, b) => b.bytes - a.bytes)
    kindsBySize.forEach((k, i) => {
      // The last takes the rounding remainder.
      const bytes = i === kindsBySize.length - 1 ? left : Math.round((drive.filesBytes * k.bytes) / plain)
      left -= bytes
      categories.push({ id: k.kind, bytes, count: k.count, color: categoryColor(k.kind) })
    })
  } else {
    categories.push({ id: 'files', bytes: drive.filesBytes, count: drive.filesCount, color: COLOR.files })
  }
  categories.push(
    { id: 'trash', bytes: drive.trashBytes, count: drive.trashCount, color: COLOR.trash },
    { id: 'versions', bytes: drive.versionsBytes, color: COLOR.versions },
    { id: 'previews', bytes: drive.thumbnailsBytes + drive.assetsBytes, color: COLOR.previews },
    { id: 'chatMedia', bytes: chat.mediaBytes, color: COLOR.chatMedia },
    { id: 'chatHistory', bytes: chat.historyBytes + chat.historyMediaBytes, color: COLOR.chatHistory },
    { id: 'reserved', bytes: usage.reservedBytes, color: COLOR.reserved },
  )
  return categories.filter((c) => c.bytes > 0).sort((a, b) => b.bytes - a.bytes)
}

export interface OwnFile {
  folder: Folder
  file: DriveFile
}

/**
 * The caller's own files that are not in the trash, from every folder this
 * account can read: what is charged to it, including what it put in other
 * people's folders. Each folder is listed once, through the same cached
 * queries the folder pages use.
 */
export function useOwnFiles(enabled = true) {
  const session = useRequiredSession()
  const folders = useFolders()
  const readable = enabled ? (folders.data?.all ?? []).filter((f) => f.key) : []
  const lists = useQueries({
    queries: readable.map((folder) => ({
      queryKey: folderFilesKey(folder),
      queryFn: () => loadFolderFiles(folder),
    })),
  })
  const files: OwnFile[] = []
  const seen = new Set<string>()
  lists.forEach((list, i) => {
    const folder = readable[i]
    if (!folder) return
    for (const file of list.data ?? []) {
      if (file.uploaderUserId !== session.userId || !file.name || seen.has(file.id)) continue
      seen.add(file.id)
      files.push({ folder, file })
    }
  })
  return {
    files,
    loading: enabled && (folders.isPending || lists.some((l) => l.isPending)),
    failed: folders.isError || lists.some((l) => l.isError),
  }
}

export function kindTotals(files: OwnFile[]): KindTotals {
  const totals: KindTotals = new Map()
  for (const { file } of files) {
    const total = totals.get(file.kind) ?? { bytes: 0, count: 0 }
    total.bytes += file.size
    total.count += 1
    totals.set(file.kind, total)
  }
  return totals
}

/** Files worth looking at to free space: 10 MB and up (as sizes are shown), largest first. */
export const LARGE_FILE_BYTES = 10 * 1024 * 1024

export function largeFiles(files: OwnFile[], limit = 100): OwnFile[] {
  return files
    .filter(({ file }) => file.size >= LARGE_FILE_BYTES)
    .sort((a, b) => b.file.size - a.file.size)
    .slice(0, limit)
}

/** `GET /api/user/storage/versions`: the caller's deletable versions by age. */
export interface VersionAge {
  ageDays: number
  keepForever: boolean
  bytes: number
  count: number
}

export const versionAgesKey = ['storage', 'versions'] as const

export function useVersionAges(enabled = true) {
  return useQuery({
    queryKey: versionAgesKey,
    enabled,
    queryFn: async () => (await api.get<VersionAge[]>('/user/storage/versions')).data,
  })
}

/** What deleting versions at least `days` old would free. */
export function versionsOlderThan(ages: VersionAge[], days: number, includeKeptForever: boolean) {
  let bytes = 0
  let count = 0
  for (const age of ages) {
    if (age.ageDays < days || (age.keepForever && !includeKeptForever)) continue
    bytes += age.bytes
    count += age.count
  }
  return { bytes, count }
}

/** Deletes the caller's versions at least `days` old, batch by batch. */
export async function pruneVersions(days: number, includeKeptForever: boolean) {
  let deletedCount = 0
  let freedBytes = 0
  for (;;) {
    const { data } = await api.post<{ deletedCount: number; freedBytes: number; more: boolean }>(
      '/user/storage/versions/prune',
      { olderThanDays: days, includeKeptForever },
    )
    deletedCount += data.deletedCount
    freedBytes += data.freedBytes
    if (!data.more || data.deletedCount === 0) return { deletedCount, freedBytes }
  }
}
