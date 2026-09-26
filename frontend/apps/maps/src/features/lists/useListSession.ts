import { useEffect, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import type * as Y from 'yjs'
import { getCursorColor } from '@kutup/collab/identity'
import { deterministicSeed, openCollabSession, type CollabSession } from '@kutup/collab/session'
import { decryptFileBlobV1 } from '@kutup/crypto/fileBlob'
import { fileKeyAt, sealedAt } from '@kutup/drive-core/keyring'
import type { DriveFile } from '@kutup/drive-core/model'
import { fillDoc, parseListJson, placesMap, placesOf, replacePlaces, type Place } from '@kutup/map/list'
import api from '@kutup/session/client'
import { QuotaExceededError } from '@kutup/session/errors'
import { useRequiredSession } from '@kutup/session/store'

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

/** The places a list was created with (its upload), for a list never saved. */
async function uploadedPlaces(file: DriveFile): Promise<Place[]> {
  const { data } = await api.get<ArrayBuffer>(`/files/${file.id}/download`, { responseType: 'arraybuffer' })
  const sealed = await sealedAt(file, file.contentKeyGeneration)
  return parseListJson(await decryptFileBlobV1(new Uint8Array(data), sealed.fileKey, sealed.context))
}

/**
 * A place list, live: everyone's changes as they happen, sealed under the
 * file's key and relayed like a note's (docs/plans/maps.md, step 4). Saved
 * as a version after a pause, as notes are. `file` must be the file as it
 * opened (a new key would reopen the session).
 */
export function useListSession(file: DriveFile | null, readOnly: boolean): ListSession {
  const { t } = useTranslation()
  const account = useRequiredSession()
  const [status, setStatus] = useState<ListStatus>('connecting')
  const [places, setPlaces] = useState<Place[]>([])
  const [collaborators, setCollaborators] = useState(0)
  const [live, setLive] = useState<{ doc: Y.Doc; session: CollabSession } | null>(null)
  // Read once: a colour or device change must not tear the session down.
  const identity = useRef({ username: account.username, deviceId: account.currentDeviceId, color: account.color ?? getCursorColor() })

  useEffect(() => {
    if (!file?.fileKey) return
    const fileKey = file.fileKey
    const controller = new AbortController()
    let session: CollabSession | null = null
    let unobserve: (() => void) | null = null
    setStatus('connecting')
    void (async () => {
      try {
        const initial = await uploadedPlaces(file)
        if (controller.signal.aborted) return
        session = await openCollabSession({
          fileId: file.id,
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
          onSaveError: (error) => {
            if (error instanceof QuotaExceededError) toast.error(t('list.quota'))
          },
          onStatus: setStatus,
          onCollaborators: setCollaborators,
          signal: controller.signal,
        })
        if (!session) return
        const doc = session.doc
        const map = placesMap(doc)
        const refresh = () => setPlaces(placesOf(doc))
        map.observeDeep(refresh)
        unobserve = () => map.unobserveDeep(refresh)
        refresh()
        setLive({ doc, session })
      } catch {
        if (!controller.signal.aborted) setStatus('error')
      }
    })()
    return () => {
      controller.abort()
      unobserve?.()
      session?.close()
      setLive(null)
    }
    // The file as it opened; see above.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [file?.id, file?.keyGeneration, readOnly])

  return { status, places, doc: live?.doc ?? null, session: live?.session ?? null, collaborators }
}
