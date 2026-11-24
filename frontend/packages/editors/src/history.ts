// A file's version history as Drive shows it (Proton Drive's
// `RevisionsModal`): every revision the server still holds, newest first,
// the one the file's metadata commits to marked current. Whole files list
// their whole-file versions and the original upload; notes, code files and
// place lists list their saved Yjs states (and the upload they began from).

import { deleteVersion, listVersions, patchVersion, type VersionRow } from '@kutup/collab/api'
import type { AccountRef } from '@kutup/crypto/accountRef'
import type { DriveFile } from '@kutup/drive-core/model'
import { isListName } from '@kutup/map/list'
import { editorKindFor } from '@kutup/drive-core/editorKind'

export { deleteVersion, listVersions, patchVersion, type VersionRow }

/** The id `DELETE …/versions/{vid}` takes for the original upload. */
export const ORIGINAL = 'original'

export interface HistoryEntry {
  /** A version id, or {@link ORIGINAL} for the first upload. */
  id: string
  /** `file`: the whole file; `yjs`: a note's (or code file's, place list's) saved state. */
  kind: 'file' | 'yjs'
  createdAt: string
  /** Who saved it, by permanent id: on this server, or `remoteAuthor` on another one. */
  authorAccountId: string | null
  remoteAuthor: AccountRef | null
  /** As stored (sealed): what it counts towards storage. */
  sizeBytes: number
  label: string | null
  keepForever: boolean
  keyGeneration: number
  revisionContentEnvelope: string | null
  /** What the file holds now. */
  current: boolean
}

/** Whether a file's content is Yjs state (a note or code file, a place list), not its bytes. */
export function holdsYjsState(name: string | null): boolean {
  return name !== null && (editorKindFor(name) === 'text' || isListName(name))
}

/** A version row's `remoteAuthor`, which the server sends as `{ server, accountId }`. */
function remoteAuthorOf(row: VersionRow): AccountRef | null {
  const value = row.remoteAuthor as unknown
  if (value && typeof value === 'object') {
    const { server, accountId } = value as Partial<AccountRef>
    if (typeof server === 'string' && typeof accountId === 'string') return { server, accountId }
  }
  return null
}

function fromRow(row: VersionRow): HistoryEntry {
  return {
    id: row.id,
    kind: row.kind,
    createdAt: row.createdAt,
    authorAccountId: row.authorAccountId || null,
    remoteAuthor: remoteAuthorOf(row),
    sizeBytes: row.sizeBytes,
    label: row.label,
    keepForever: row.keepForever,
    keyGeneration: row.keyGeneration,
    revisionContentEnvelope: row.revisionContentEnvelope,
    current: false,
  }
}

/**
 * The history of `file` from its version rows (newest first, as listed):
 * the revisions of the kind its content is, and the original upload while
 * it is kept. The current entry is the one the sealed metadata commits to
 * (a whole file's content revision, a note's saved state); failing that,
 * the newest.
 */
export function fileHistory(
  file: Pick<DriveFile, 'name' | 'content' | 'stateRevisionId' | 'originalRevisionId' | 'originalPruned' | 'uploaderAccountId' | 'createdAt' | 'originalKeyGeneration' | 'originalSizeBytes'>,
  rows: readonly VersionRow[],
): HistoryEntry[] {
  const yjs = holdsYjsState(file.name)
  const kind = yjs ? 'yjs' : 'file'
  const entries = rows.filter((row) => row.kind === kind).map(fromRow)
  if (!file.originalPruned && file.originalRevisionId) {
    entries.push({
      id: ORIGINAL,
      kind: 'file',
      createdAt: file.createdAt,
      authorAccountId: file.uploaderAccountId,
      remoteAuthor: null,
      sizeBytes: file.originalSizeBytes ?? 0,
      label: null,
      keepForever: false,
      keyGeneration: file.originalKeyGeneration,
      revisionContentEnvelope: null,
      current: false,
    })
  }
  entries.sort((a, b) => Date.parse(b.createdAt) - Date.parse(a.createdAt))
  const committed = yjs ? file.stateRevisionId : file.content?.revisionId
  const current =
    entries.find((e) => (e.id === ORIGINAL ? file.originalRevisionId : e.id) === committed) ??
    // A note never saved has its upload as its content.
    (yjs ? (entries.find((e) => e.kind === 'yjs') ?? entries[0]) : entries[0])
  if (current) current.current = true
  return entries
}

/**
 * Who may delete `entry` (the server's rule, `DELETE …/versions/{vid}`):
 * the file's owner, or whoever saved it (the original: whoever uploaded
 * it); never the current content, and the original only once a whole-file
 * version replaced it.
 */
export function mayDeleteEntry(
  entry: HistoryEntry,
  history: readonly HistoryEntry[],
  me: string,
  owner: string,
): boolean {
  if (entry.current) return false
  if (entry.id === ORIGINAL && !history.some((e) => e.kind === 'file' && e.id !== ORIGINAL)) return false
  return me === owner || (entry.remoteAuthor === null && entry.authorAccountId === me)
}

export interface HistoryGroup {
  /** `today`, `yesterday`, `weekday`, `lastWeek`, `month` or `year`: what the title says. */
  kind: 'today' | 'yesterday' | 'weekday' | 'lastWeek' | 'month' | 'year'
  /** Stable key (`d3`, `m10`, `2025`). */
  key: string
  /** The day, month or year it names, for the title (`weekday`, `month`, `year`). */
  date: Date
  entries: HistoryEntry[]
}

function startOfDay(date: Date): Date {
  return new Date(date.getFullYear(), date.getMonth(), date.getDate())
}

/** Monday of the week `date` is in (weeks start on Monday, as in Turkey and most of Europe). */
function startOfWeek(date: Date): Date {
  const day = startOfDay(date)
  day.setDate(day.getDate() - ((day.getDay() + 6) % 7))
  return day
}

/**
 * The earlier versions in groups, as Proton's `getCategorizedRevisions`:
 * today, yesterday, each other day of this week, last week, each other month
 * of this year, then each year. Order kept (newest first).
 */
export function groupHistory(entries: readonly HistoryEntry[], now = new Date()): HistoryGroup[] {
  const today = startOfDay(now).getTime()
  const yesterday = new Date(today)
  yesterday.setDate(yesterday.getDate() - 1)
  const thisWeek = startOfWeek(now)
  const lastWeek = new Date(thisWeek)
  lastWeek.setDate(lastWeek.getDate() - 7)
  const groups = new Map<string, HistoryGroup>()
  for (const entry of entries) {
    const at = new Date(entry.createdAt)
    const day = startOfDay(at).getTime()
    let kind: HistoryGroup['kind']
    let key: string
    if (day >= today) [kind, key] = ['today', 'today']
    else if (day >= yesterday.getTime()) [kind, key] = ['yesterday', 'yesterday']
    else if (day >= thisWeek.getTime()) [kind, key] = ['weekday', `d${at.getDay()}`]
    else if (day >= lastWeek.getTime()) [kind, key] = ['lastWeek', 'lastWeek']
    else if (at.getFullYear() === now.getFullYear()) [kind, key] = ['month', `m${at.getMonth()}`]
    else [kind, key] = ['year', String(at.getFullYear())]
    const group = groups.get(key)
    if (group) group.entries.push(entry)
    else groups.set(key, { kind, key, date: at, entries: [entry] })
  }
  return [...groups.values()]
}
