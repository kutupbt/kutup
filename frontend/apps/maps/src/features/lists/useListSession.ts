import { useQueryClient } from '@tanstack/react-query'
import { useEffect, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import type * as Y from 'yjs'
import { getCursorColor } from '@kutup/collab/identity'
import { deterministicSeed, openCollabSession, type CollabSession } from '@kutup/collab/session'
import { fileKeyAt } from '@kutup/drive-core/keyring'
import { collabBase, fileLocation, type DriveFile, type Folder } from '@kutup/drive-core/model'
import { fillDoc, placesMap, placesOf, replacePlaces, type Place } from '@kutup/map/list'
import { QuotaExceededError } from '@kutup/session/errors'
import { useRequiredSession } from '@kutup/session/store'
import { listVersions } from '@kutup/collab/api'
import { drawListThumbnail, listThumbnailScheduler, type ListLook } from './listThumbnail'
import { savedPlacesKey, uploadedPlaces } from './savedPlaces'

export type ListStatus = 'connecting' | 'ready' | 'error'

export interface ListSession {
  status: ListStatus
  places: Place[]
  /** The live document; null until the session is up. */
  doc: Y.Doc | null
  session: CollabSession | null
  /** Other people in the list now. */
  collaborators: number
}

/**
 * A place list, live: everyone's changes as they happen, sealed under the
 * file's key and relayed like a note's (docs/plans/maps.md, step 4). Saved
 * as a version after a pause, as notes are. `file` must be the file as it
 * opened (a new key would reopen the session).
 *
 * Its saves redraw the list's picture in Drive with `look` (read when drawn),
 * and a list opened without an up-to-date picture gets one.
 */
export function useListSession(file: DriveFile | null, readOnly: boolean, folder: Folder | undefined, look: ListLook): ListSession {
  const { t } = useTranslation()
  const queryClient = useQueryClient()
  const account = useRequiredSession()
  const [status, setStatus] = useState<ListStatus>('connecting')
  const [places, setPlaces] = useState<Place[]>([])
  const [collaborators, setCollaborators] = useState(0)
  const [live, setLive] = useState<{ doc: Y.Doc; session: CollabSession } | null>(null)
  // Read once: a colour or device change must not tear the session down.
  const identity = useRef({ username: account.username, deviceId: account.currentDeviceId, color: account.color ?? getCursorColor() })
  const lookRef = useRef(look)
  lookRef.current = look

  useEffect(() => {
    if (!file?.fileKey) return
    const fileKey = file.fileKey
    const controller = new AbortController()
    let session: CollabSession | null = null
    let unobserve: (() => void) | null = null
    // Changed here since the last save: saved on leaving, so the home map
    // (which shows saved places) is right at once.
    let dirty = false
    // Pictures are drawn by editors of lists on this server, sealed under
    // the folder's current key only (as Drive's are).
    const location = folder ? fileLocation(folder) : ({ kind: 'local' } as const)
    const pictureTarget = { fileId: file.id, fileKey, keyGeneration: file.keyGeneration }
    const pictures =
      !readOnly && location.kind === 'local' && (!folder || file.keyEpoch === folder.keyEpoch)
        ? listThumbnailScheduler(pictureTarget, () => lookRef.current)
        : null
    // No picture yet, or one from an older version: drawn once the list is
    // up, by someone who may manage it (readers of a shared folder do not
    // spend its owner's quota), as Drive's backfill does.
    const needsPicture =
      pictures !== null &&
      (!file.thumbnails.sm || file.thumbnailStale) &&
      (!folder || folder.canManage || file.uploaderUserId === account.userId)
    let pictured = false
    let ready = false
    // Once the session is up and has replayed (in either order).
    const picture = () => {
      if (!needsPicture || pictured || !ready || !session) return
      pictured = true
      const doc = session.doc
      void listVersions(file.id)
        .then((versions) => {
          if (!controller.signal.aborted) {
            drawListThumbnail(pictureTarget, versions[0]?.id ?? 'original', placesOf(doc), lookRef.current)
          }
        })
        .catch(() => undefined)
    }
    setStatus('connecting')
    void (async () => {
      try {
        const initial = await uploadedPlaces(file, folder)
        if (controller.signal.aborted) return
        session = await openCollabSession({
          fileId: file.id,
          // A list on another server: live through this one (docs/plans/collab-federation.md).
          base: location.kind === 'local' ? undefined : collabBase(location, file.id),
          fileKey,
          keyGeneration: file.keyGeneration,
          fileKeyAt: (generation) => fileKeyAt(file, generation),
          readOnly,
          username: identity.current.username,
          storedDeviceId: identity.current.deviceId,
          cursorColor: identity.current.color,
          seed: {
            update: () => deterministicSeed(file.id, (doc) => fillDoc(doc, initial)),
            isEmpty: (doc) => placesMap(doc).size === 0,
          },
          replaceContent: replacePlaces,
          labels: {
            preRestore: () => t('list.preRestoreLabel', { time: new Date().toLocaleString() }),
            restored: () => t('list.restoredLabel', { time: new Date().toLocaleString() }),
          },
          onSnapshot: (versionId, explicit) => {
            if (session) pictures?.saved(versionId, explicit, placesOf(session.doc))
          },
          onSaveError: (error) => {
            if (error instanceof QuotaExceededError) toast.error(t('list.quota'))
          },
          onStatus: (next) => {
            setStatus(next)
            if (next === 'ready') {
              ready = true
              picture()
            }
          },
          onCollaborators: setCollaborators,
          signal: controller.signal,
        })
        if (!session) return
        const doc = session.doc
        const map = placesMap(doc)
        const refresh = () => setPlaces(placesOf(doc))
        const markDirty = (_update: Uint8Array, origin: unknown) => {
          if (origin !== 'remote') dirty = true
        }
        map.observeDeep(refresh)
        doc.on('update', markDirty)
        unobserve = () => {
          map.unobserveDeep(refresh)
          doc.off('update', markDirty)
        }
        refresh()
        setLive({ doc, session })
        picture()
      } catch {
        if (!controller.signal.aborted) setStatus('error')
      }
    })()
    return () => {
      controller.abort()
      pictures?.flush()
      unobserve?.()
      setLive(null)
      const leaving = session
      if (!leaving) return
      if (!dirty || !leaving.trigger) return leaving.close()
      void leaving
        .flush()
        .then(() => leaving.trigger?.forceSave())
        .catch(() => undefined)
        .finally(() => {
          leaving.close()
          void queryClient.invalidateQueries({ queryKey: savedPlacesKey(file.id) })
        })
    }
    // The file as it opened; see above.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [file?.id, file?.keyGeneration, readOnly])

  return { status, places, doc: live?.doc ?? null, session: live?.session ?? null, collaborators }
}
