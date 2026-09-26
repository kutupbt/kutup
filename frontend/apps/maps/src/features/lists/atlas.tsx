import { useQueryClient } from '@tanstack/react-query'
import { useCallback, useMemo, useState, type ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import type * as Y from 'yjs'
import { getCursorColor } from '@kutup/collab/identity'
import { deterministicSeed, openCollabSession } from '@kutup/collab/session'
import { filesKey } from '@kutup/drive-core/files'
import { useDriveIdentity } from '@kutup/drive-core/identity'
import { fileKeyAt } from '@kutup/drive-core/keyring'
import { collabBase, fileLocation, type DriveFile, type Folder } from '@kutup/drive-core/model'
import { rekeyFile } from '@kutup/drive-core/rekey'
import { fillDoc, placesMap, replacePlaces } from '@kutup/map/list'
import { useRequiredSession } from '@kutup/session/store'
import { AtlasContext, ListBusy, type Atlas, type OpenList, type ShownPlace } from './atlasContext'
import { useLists, type ListEntry } from './lists'
import { FALLBACK_COLOR, listColors, savedPlacesKey, uploadedPlaces, useSavedPlaces } from './savedPlaces'

/**
 * Join a list's live session as an editor, make one change, save it as a
 * version (so everyone's map, and the home map, show it) and leave. Anyone
 * with the list open sees the change as it happens.
 */
async function editOnce(
  file: DriveFile,
  folder: Folder,
  change: (doc: Y.Doc) => void,
  identity: { username: string | null; deviceId: number | null; color: string },
  labels: { preRestore: () => string; restored: () => string },
): Promise<void> {
  if (!file.fileKey) throw new Error('file is not open')
  const initial = await uploadedPlaces(file, folder)
  const location = fileLocation(folder)
  const controller = new AbortController()
  let settle: { resolve: () => void; reject: (error: Error) => void } | null = null
  const ready = new Promise<void>((resolve, reject) => (settle = { resolve, reject }))
  // Awaited below; until then a rejection is not unhandled.
  ready.catch(() => undefined)
  const timer = setTimeout(() => settle?.reject(new ListBusy()), 20_000)
  const session = await openCollabSession({
    fileId: file.id,
    base: location.kind === 'local' ? undefined : collabBase(location, file.id),
    fileKey: file.fileKey,
    keyGeneration: file.keyGeneration,
    fileKeyAt: (generation) => fileKeyAt(file, generation),
    readOnly: false,
    username: identity.username,
    storedDeviceId: identity.deviceId,
    cursorColor: identity.color,
    seed: {
      update: () => deterministicSeed(file.id, (doc) => fillDoc(doc, initial)),
      isEmpty: (doc) => placesMap(doc).size === 0,
    },
    replaceContent: replacePlaces,
    labels,
    onStatus: (status) => {
      if (status === 'ready') settle?.resolve()
      else if (status === 'error') settle?.reject(new ListBusy())
    },
    signal: controller.signal,
  })
  if (!session) {
    clearTimeout(timer)
    throw new ListBusy()
  }
  try {
    await ready
    change(session.doc)
    await session.flush()
    await session.trigger?.forceSave()
  } finally {
    clearTimeout(timer)
    controller.abort()
    session.close()
  }
}

export function AtlasProvider({ children }: { children: ReactNode }) {
  const { t } = useTranslation()
  const queryClient = useQueryClient()
  const account = useRequiredSession()
  const identity = useDriveIdentity()
  const { lists, loading, error } = useLists()
  const saved = useSavedPlaces(lists)
  const [open, setOpen] = useState<OpenList | null>(null)
  const [shown, showPlace] = useState<ShownPlace | null>(null)

  const placesOf = useCallback(
    (fileId: string) => (open?.fileId === fileId ? open.places : saved.byFile.get(fileId)),
    [open, saved.byFile],
  )

  const editable = useCallback(
    (entry: ListEntry) =>
      Boolean(
        entry.file.fileKey &&
          entry.folder.canUpload &&
          (!entry.shared || entry.shared.state === 'ready'),
      ),
    [],
  )

  const write = useCallback(
    async (entry: ListEntry, change: (doc: Y.Doc) => void) => {
      if (open && open.fileId === entry.file.id) {
        change(open.doc)
        return
      }
      let file = entry.file
      // Written only under the folder's current key (someone may have left
      // it); folders here only (a remote one is re-keyed at home).
      const local = entry.folder.source === 'owned' || entry.folder.source === 'shared'
      if (local && file.keyEpoch < entry.folder.keyEpoch) {
        file = await rekeyFile(entry.folder, file)
        void queryClient.invalidateQueries({ queryKey: filesKey(entry.folder.id) })
      }
      await editOnce(
        file,
        entry.folder,
        change,
        { username: account.username, deviceId: account.currentDeviceId, color: account.color ?? getCursorColor() },
        {
          preRestore: () => t('list.preRestoreLabel', { time: new Date().toLocaleString() }),
          restored: () => t('list.restoredLabel', { time: new Date().toLocaleString() }),
        },
      )
      await queryClient.invalidateQueries({ queryKey: savedPlacesKey(entry.file.id) })
    },
    [open, queryClient, account.username, account.currentDeviceId, account.color, t],
  )

  const colors = useMemo(() => listColors(lists.map((l) => ({ id: l.file.id, createdAt: l.file.createdAt }))), [lists])
  const colorOf = useCallback((fileId: string) => colors.get(fileId) ?? FALLBACK_COLOR, [colors])

  const atlas = useMemo<Atlas>(
    () => ({
      lists,
      loading,
      error,
      placesOf,
      savedLoading: saved.loading,
      open,
      setOpen,
      shown,
      showPlace,
      editable,
      write,
      me: identity.data?.account ?? null,
      colorOf,
    }),
    [lists, loading, error, placesOf, saved.loading, open, shown, editable, write, identity.data?.account, colorOf],
  )
  return <AtlasContext.Provider value={atlas}>{children}</AtlasContext.Provider>
}
