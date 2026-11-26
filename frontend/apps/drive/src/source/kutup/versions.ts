// Kutup's version history (docs/plans/drive-versions.md), as the Drive screens
// use it through the source: the rows, merged with what the file holds now;
// restoring re-seals the chosen revision as the newest version.

import { useQuery, useQueryClient } from '@tanstack/react-query'
import { useAccountName } from '@kutup/drive-core/accountName'
import { useDriveIdentity } from '@kutup/drive-core/identity'
import type { DriveFile, Folder } from '@kutup/drive-core/model'
import { personOfAccount, usePeople } from '@kutup/drive-core/people'
import type { HistoryEntryView, VersionHistory } from '@kutup/drive-source/source'
import { readRevision } from '@kutup/editors/content'
import { deleteVersion, fileHistory, holdsYjsState, listVersions, mayDeleteEntry, patchVersion, type HistoryEntry } from '@kutup/editors/history'
import api from '@kutup/session/client'
import { useRequiredSession } from '@kutup/session/store'
import { thumbnailAfterUpload } from './thumbnails/schedule'
import { canReplace, replaceContent } from './uploads/replace'

/** The query of a file's version rows. */
const versionsKey = (fileId: string) => ['versions', fileId] as const

export function useKutupVersionHistory(folder: Folder, file: DriveFile): VersionHistory {
  const session = useRequiredSession()
  const queryClient = useQueryClient()
  const rows = useQuery({ queryKey: versionsKey(file.id), queryFn: () => listVersions(file.id) })
  const refresh = () =>
    Promise.all([
      queryClient.invalidateQueries({ queryKey: versionsKey(file.id) }),
      queryClient.invalidateQueries({ queryKey: ['files'] }),
    ]).then(() => undefined)
  return {
    // The rows merged with what the file holds now, as the dialog showed them.
    history: { data: rows.data ? fileHistory(file, rows.data) : undefined, isPending: rows.isPending, isError: rows.isError, error: rows.error },
    mayRestore: !holdsYjsState(file.name) && canReplace(folder, file),
    mayDelete: (entry, all) => mayDeleteEntry(entry as HistoryEntry, all as HistoryEntry[], session.accountId, folder.ownerAccountId),
    restore: async (entry) => {
      if (!file.name) throw new Error('file is not open')
      const blob = await readRevision(file, entry as HistoryEntry)
      const restored = new File([blob], file.name, { type: file.mimeType })
      const outcome = await replaceContent(folder, file, restored, { signal: new AbortController().signal })
      if (!('done' in outcome)) return { problem: outcome.problem }
      thumbnailAfterUpload(outcome.done, restored)
      await refresh()
      return { done: true }
    },
    keep: async (entry, keepForever) => {
      await patchVersion(file.id, entry.id, { keepForever })
      await queryClient.invalidateQueries({ queryKey: versionsKey(file.id) })
    },
    remove: async (entry) => {
      await deleteVersion(file.id, entry.id)
      await refresh()
    },
  }
}

/** Who saved a revision: their profile name once they gave it, else their address. */
export function useKutupAuthorName(view: HistoryEntryView): string | null {
  const entry = view as HistoryEntry
  const identity = useDriveIdentity()
  const server = identity.data?.accountRef.server
  const account = entry.remoteAuthor ?? (entry.authorAccountId && server ? { server, accountId: entry.authorAccountId } : null)
  const address = useAccountName(account)
  const people = usePeople()
  return account && address.data ? personOfAccount(people.data, account, address.data).name : null
}

/** How long the owner's earlier versions are kept (Drive → Settings changes it). */
export function useKutupVersionRetention(): { days: number } | null {
  const me = useQuery({
    queryKey: ['me'],
    queryFn: async () => (await api.get<{ versionRetentionDays: number; versionRetentionChoices: number[] }>('/account')).data,
  })
  return me.data ? { days: me.data.versionRetentionDays } : null
}
