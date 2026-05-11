// SPDX-FileCopyrightText: 2026 kutup contributors
// SPDX-License-Identifier: AGPL-3.0-only
//
// WhiteboardEditor — React wrapper around Excalidraw with kutup collab.
//
// Save: extracts the scene via the imperative API, serializes via
// serializeAsJSON, returns the JSON bytes (parent encrypts + uploads).
//
// Collab: when local elements mutate, broadcast only the changed ones
// (compared by versionNonce against our last-broadcast snapshot). On
// receipt, decrypt → reconcileElements → updateScene with
// CaptureUpdateAction.NEVER so the merge doesn't pollute Excalidraw's
// undo history. We suppress outbound during apply via a ref guard so we
// never echo a remote change back to its origin.
//
// EXCALIDRAW_OP is ephemeral on the wire — canonical state lives in
// snapshot blobs. Persisting deltas would replay all element history
// on reconnect and clobber a freshly-restored scene.
//
// Presence: pointer position + selectedElementIds broadcast via
// EXCALIDRAW_CURSOR (also ephemeral). Receivers update the Excalidraw
// appState.collaborators map so peers see each other's cursor + the
// translucent rectangles around peer-selected elements.

import {
  forwardRef,
  Suspense,
  lazy,
  useEffect,
  useImperativeHandle,
  useMemo,
  useRef,
  type Ref,
} from 'react'
import {
  serializeAsJSON,
  reconcileElements,
  CaptureUpdateAction,
} from '@excalidraw/excalidraw'
import type {
  ExcalidrawImperativeAPI,
  ExcalidrawInitialDataState,
  BinaryFileData,
  DataURL,
} from '@excalidraw/excalidraw/types'
import type {
  OrderedExcalidrawElement,
  ExcalidrawImageElement,
  FileId,
} from '@excalidraw/excalidraw/element/types'
import { useAppDispatch, useAppSelector } from '@/store'
import { setDeviceId } from '@/store/authSlice'
import { CollabTransport, type HelloMsg, type PeerInfo } from '@/collab/transport'
import { pack, unpack, KIND, type Frame } from '@/collab/envelope'
import {
  encryptExcalidrawOp, decryptExcalidrawOp,
  encryptExcalidrawCursor, decryptExcalidrawCursor,
} from '@/collab/cryptoFrame'
import { ed25519Sign } from '@/collab/sign'
import {
  generateDeviceKeypair, loadKeypair, saveKeypair, encodePubKeyB64,
} from '@/collab/devices'
import { randomSenderSeqPrefix, buildAwarenessName } from '@/collab/identity'
import { registerDevice } from '@/api/collab'
import { uploadAsset, fetchAsset, QuotaExceededError } from '@/api/whiteboardAssets'
import { useTheme } from '@/hooks/useTheme'
import { toast } from 'sonner'
import { useTranslation } from 'react-i18next'

import '@excalidraw/excalidraw/index.css'

const Excalidraw = lazy(() =>
  import('@excalidraw/excalidraw').then((m) => ({ default: m.Excalidraw })),
)

export interface WhiteboardEditorHandle {
  save: () => Promise<{ bytes: Uint8Array }>
}

interface Props {
  fileId: string
  filename: string
  collectionMaster: Uint8Array
  initialBytes?: Uint8Array
}

// Module-level cache of registerDevice promises — same pattern as
// OfficeEditor. Prevents duplicate device rows when two tabs of the
// same file load concurrently.
const _devicePromiseCache = new Map<string, Promise<number>>()
function ensureRegistered(pubKeyB64: string, label: string): Promise<number> {
  let p = _devicePromiseCache.get(pubKeyB64)
  if (!p) {
    p = registerDevice(pubKeyB64, label).then(r => r.deviceId)
    _devicePromiseCache.set(pubKeyB64, p)
  }
  return p
}

interface CursorPayload {
  color: string | null
  username: string | null
  userId: string | null
  pointer?: { x: number; y: number; tool: 'pointer' | 'laser' }
  button?: 'up' | 'down'
  selectedElementIds?: Record<string, true>
}

function WhiteboardEditorBase(
  { fileId, initialBytes, collectionMaster }: Props,
  ref: Ref<WhiteboardEditorHandle>,
) {
  const apiRef = useRef<ExcalidrawImperativeAPI | null>(null)
  const dispatch = useAppDispatch()
  const { t } = useTranslation()
  const accessToken = useAppSelector(s => s.auth.accessToken)
  const storedDeviceId = useAppSelector(s => s.auth.currentDeviceId)
  const userColor = useAppSelector(s => s.auth.color)
  const username = useAppSelector(s => s.auth.username)
  const userId = useAppSelector(s => s.auth.userId)
  const [theme] = useTheme()

  // Push kutup's theme into Excalidraw on every change. The `theme` prop
  // below seeds the initial canvas; this effect keeps subsequent toggles
  // in sync. Users can still flip the canvas independently via
  // Excalidraw's own top-right toggle — the next kutup toggle re-syncs.
  useEffect(() => {
    apiRef.current?.updateScene({ appState: { theme } })
  }, [theme])

  // Mirror identity into refs so the cursor sender (bound once on mount)
  // picks up live colour-picker changes without remounting the WS.
  const userColorRef = useRef(userColor); userColorRef.current = userColor
  const usernameRef = useRef(username);   usernameRef.current = username
  const userIdRef = useRef(userId);       userIdRef.current = userId

  // Collab state held in refs so callbacks see latest without rebinding.
  const transportRef = useRef<CollabTransport | null>(null)
  const deviceIdRef = useRef<number | null>(null)
  const keypairRef = useRef<{ publicKey: Uint8Array; privateKey: Uint8Array } | null>(null)
  const docKeyIdRef = useRef<number>(1)
  const lastSeenSeqRef = useRef<number>(0)
  const outboundSeqRef = useRef<bigint>(randomSenderSeqPrefix())

  // Per-element versionNonce snapshot of what we've already broadcast.
  // Used to compute "changed since last broadcast" diffs in onChange.
  const lastBroadcastRef = useRef<Map<string, number>>(new Map())

  // Set during applyRemote → updateScene; suppresses the onChange echo
  // that would otherwise re-broadcast the remote elements right back.
  const applyingRemoteRef = useRef(false)

  // Debounce outbound broadcast — onChange fires per mouse-move during
  // a free-draw. 200ms catches the trailing edge of a stroke.
  const broadcastTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null)

  // Presence (cursor + selection): peer state keyed by senderDeviceId.
  // Pushed into Excalidraw via api.updateScene({ collaborators }).
  const collaboratorsRef = useRef<Map<string, Record<string, unknown>>>(new Map())

  // Local pointer + selection sources, kept in refs so the throttled
  // sender always reads the latest values.
  const localPointerRef = useRef<{ x: number; y: number; tool: 'pointer' | 'laser' } | null>(null)
  const localButtonRef = useRef<'up' | 'down'>('up')
  const localSelectionRef = useRef<Record<string, true>>({})
  const lastSelectionKeyRef = useRef<string>('{}')

  // Trailing-edge throttle for cursor broadcast — mouse-move fires at
  // ~60 Hz, that's too much WS traffic. 50ms keeps motion fluid without
  // saturating the relay.
  const presenceTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null)

  // ---- Image asset sync (Excalidraw-native pattern) -------------------
  // Image binaries are NOT broadcast through the WS. Instead, we follow
  // upstream Excalidraw's status-driven flow:
  //   1. Image element appears with status "pending" + binary in
  //      appState.files. We encrypt the binary client-side and PUT it to
  //      /api/files/:fileId/assets/:assetId, then flip the element's
  //      status to "saved" via updateScene.
  //   2. The status flip bumps versionNonce → broadcasts via the normal
  //      EXCALIDRAW_OP channel.
  //   3. A peer receiving an image element with status "saved" whose
  //      fileId is missing from its local cache GETs the asset, decrypts,
  //      and api.addFiles to inject the binary. Excalidraw rerenders the
  //      element automatically.
  // assetSavedRef: fileIds we know to be "saved" (uploaded by us OR
  //   loaded from the snapshot OR already broadcast by a peer). Used to
  //   skip both the upload-side scan and re-flip churn.
  const assetSavedRef = useRef<Set<string>>(new Set())
  // pendingUploadsRef: fileIds with an in-flight uploadAsset Promise.
  //   Dedupes re-entrant calls from rapid onChange ticks.
  const pendingUploadsRef = useRef<Set<string>>(new Set())
  // fetchedAssetsRef: fileIds we've already fetched (or are fetching) so
  //   repeated reconciles don't fire N redundant GETs.
  const fetchedAssetsRef = useRef<Set<string>>(new Set())

  const initialData = useMemo<ExcalidrawInitialDataState | null>(() => {
    if (!initialBytes || initialBytes.length === 0) return null
    try {
      const text = new TextDecoder().decode(initialBytes)
      const json = JSON.parse(text)
      const appState = { ...(json.appState ?? {}) }
      delete appState.collaborators
      // Seed lastBroadcast from the loaded scene so we don't immediately
      // re-broadcast everything on mount.
      const map = new Map<string, number>()
      for (const el of (json.elements ?? []) as OrderedExcalidrawElement[]) {
        map.set(el.id, el.version ?? 0)
      }
      lastBroadcastRef.current = map
      // Anything already in the snapshot's files map has already been
      // uploaded (or originated locally and was persisted). Skip both the
      // upload-side scan and the download-side fetch for these fileIds.
      const files = (json.files ?? {}) as Record<string, BinaryFileData>
      for (const fid of Object.keys(files)) {
        assetSavedRef.current.add(fid)
        fetchedAssetsRef.current.add(fid)
      }
      return {
        elements: json.elements ?? [],
        appState,
        files,
        scrollToContent: true,
      }
    } catch (err) {
      console.warn('whiteboard: failed to parse initialBytes', err)
      return null
    }
  }, [initialBytes])

  useImperativeHandle(
    ref,
    () => ({
      save: async () => {
        const api = apiRef.current
        if (!api) throw new Error('whiteboard editor not ready')
        const elements = api.getSceneElements()
        const appState = api.getAppState()
        const files = api.getFiles()
        const json = serializeAsJSON(elements, appState, files, 'local')
        const bytes = new TextEncoder().encode(json)
        return { bytes }
      },
    }),
    [],
  )

  // ---- Collab ----
  useEffect(() => {
    if (!accessToken) return
    let alive = true

    ;(async () => {
      let kp = loadKeypair()
      if (!kp) { kp = await generateDeviceKeypair(); saveKeypair(kp) }
      keypairRef.current = kp

      let did = storedDeviceId
      if (!did) {
        const pubB64 = encodePubKeyB64(kp.publicKey)
        did = await ensureRegistered(pubB64, 'kutup-whiteboard:' + navigator.userAgent.slice(0, 60))
        if (!alive) return
        dispatch(setDeviceId(did))
      }
      deviceIdRef.current = did

      const wsUrl = `${location.origin.replace(/^http/, 'ws')}/api/files/${fileId}/collab/ws?token=${encodeURIComponent(accessToken)}&deviceId=${did}`

      const transport = new CollabTransport({
        url: wsUrl,
        lastSeenSeq: () => lastSeenSeqRef.current,
        onHello: (h: HelloMsg) => {
          docKeyIdRef.current = h.currentDocKeyId
          lastSeenSeqRef.current = h.headSeq
          if (typeof h.mySenderSeqHigh === 'number' && h.mySenderSeqHigh > 0) {
            const high = BigInt(h.mySenderSeqHigh)
            if (outboundSeqRef.current <= high) {
              outboundSeqRef.current = randomSenderSeqPrefix(high)
            }
          }
        },
        onFrame: async (bs: Uint8Array) => {
          try {
            const f: Frame = unpack(bs)
            const api = apiRef.current
            if (!api) return
            if (f.kind === KIND.EXCALIDRAW_OP) {
              const payload = await decryptExcalidrawOp(f, fileId, collectionMaster)
              const remote = JSON.parse(new TextDecoder().decode(payload)) as OrderedExcalidrawElement[]
              // reconcileElements expects (localElements, remoteElements,
              // localAppState). It returns merged element array honouring
              // versionNonce — last-write-wins per element.
              const local = api.getSceneElementsIncludingDeleted() as OrderedExcalidrawElement[]
              const merged = reconcileElements(local, remote as never, api.getAppState())
              applyingRemoteRef.current = true
              try {
                api.updateScene({
                  elements: merged,
                  captureUpdate: CaptureUpdateAction.NEVER,
                })
              } finally {
                applyingRemoteRef.current = false
              }
              // Update our broadcast snapshot so we don't re-broadcast
              // these elements as our own changes.
              for (const el of merged) {
                lastBroadcastRef.current.set(el.id, (el as OrderedExcalidrawElement).version ?? 0)
              }
              // If the merge pulled in image elements with status="saved"
              // whose binaries we don't have locally, fetch them from the
              // asset blob endpoint. Async — element renders as broken
              // until the file lands.
              maybeFetchMissingAssets(merged as OrderedExcalidrawElement[])
            } else if (f.kind === KIND.EXCALIDRAW_CURSOR) {
              const payload = await decryptExcalidrawCursor(f, fileId, collectionMaster)
              const data = JSON.parse(new TextDecoder().decode(payload)) as CursorPayload
              const senderId = String(f.senderDeviceId)
              const myDid = deviceIdRef.current
              if (myDid !== null && f.senderDeviceId === BigInt(myDid)) return
              const stroke = data.color ?? '#94a3b8'
              const collaborator: Record<string, unknown> = {
                id: data.userId ?? senderId,
                socketId: senderId,
                username: data.username ?? null,
                color: { background: stroke, stroke },
              }
              if (data.pointer) collaborator.pointer = data.pointer
              if (data.button) collaborator.button = data.button
              if (data.selectedElementIds) collaborator.selectedElementIds = data.selectedElementIds
              collaboratorsRef.current.set(senderId, collaborator)
              applyingRemoteRef.current = true
              try {
                api.updateScene({
                  collaborators: new Map(collaboratorsRef.current) as never,
                  captureUpdate: CaptureUpdateAction.NEVER,
                })
              } finally {
                applyingRemoteRef.current = false
              }
            }
          } catch (e) {
            console.warn('whiteboard: dropped frame', e)
          }
        },
        onPeers: (p) => {
          // Prune cursors of devices that have left the room. Otherwise a
          // peer who closes their tab leaves a frozen cursor on screen.
          const live = new Set<string>(p.list.map((x: PeerInfo) => String(x.deviceId)))
          let pruned = false
          for (const k of Array.from(collaboratorsRef.current.keys())) {
            if (!live.has(k)) {
              collaboratorsRef.current.delete(k)
              pruned = true
            }
          }
          if (pruned) {
            const api = apiRef.current
            if (api) {
              applyingRemoteRef.current = true
              try {
                api.updateScene({
                  collaborators: new Map(collaboratorsRef.current) as never,
                  captureUpdate: CaptureUpdateAction.NEVER,
                })
              } finally {
                applyingRemoteRef.current = false
              }
            }
          }
        },
        onError: (e: unknown) => console.warn('whiteboard: ws error', e),
      })
      if (!alive) { transport.close(); return }
      transportRef.current = transport
    })()

    return () => {
      alive = false
      transportRef.current?.close()
      transportRef.current = null
      if (broadcastTimerRef.current) clearTimeout(broadcastTimerRef.current)
      if (presenceTimerRef.current) clearTimeout(presenceTimerRef.current)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps -- accessToken
    // captured in URL on first connect; refresh handled by transport
    // reconnect, NOT by re-mounting the WS (would lose in-flight broadcasts).
  }, [fileId, collectionMaster, dispatch])

  // Trailing-edge throttle for cursor + selection presence.
  function schedulePresence() {
    if (presenceTimerRef.current) return
    presenceTimerRef.current = setTimeout(async () => {
      presenceTimerRef.current = null
      const transport = transportRef.current
      const did = deviceIdRef.current
      const kp = keypairRef.current
      if (!transport || !did || !kp) return
      const payload: CursorPayload = {
        color: userColorRef.current,
        // Same "<user> #<tabId>" shape that notes / office use, so two
        // tabs of the same account are distinguishable in the cursor
        // label instead of both reading just "admin".
        username: buildAwarenessName(usernameRef.current),
        userId: userIdRef.current,
        button: localButtonRef.current,
        selectedElementIds: localSelectionRef.current,
      }
      if (localPointerRef.current) payload.pointer = localPointerRef.current
      try {
        outboundSeqRef.current = outboundSeqRef.current + 1n
        const bytes = new TextEncoder().encode(JSON.stringify(payload))
        const f = await encryptExcalidrawCursor(
          bytes, fileId, docKeyIdRef.current, BigInt(did), outboundSeqRef.current, collectionMaster,
        )
        const packed = pack(f)
        const body = packed.subarray(0, packed.length - 64)
        const sig = await ed25519Sign(body, kp.privateKey)
        packed.set(sig, packed.length - 64)
        transport.send(packed)
      } catch (e) {
        console.warn('whiteboard: cursor send failed', e)
      }
    }, 50)
  }

  // Mutate a single image element's status field (saved | error). Bumps
  // version + versionNonce so the existing scheduleBroadcast diff picks
  // it up as a local change and propagates it to peers. Used by both the
  // happy path (status → "saved") and the quota-exceeded path
  // (status → "error" so the user sees a broken-image marker instead of
  // an indefinitely-pending placeholder).
  function flipImageStatus(elemId: string, next: 'saved' | 'error') {
    const api = apiRef.current
    if (!api) return
    const current = api.getSceneElementsIncludingDeleted() as OrderedExcalidrawElement[]
    const updated = current.map((e) => {
      if (e.id !== elemId) return e
      const ie = e as ExcalidrawImageElement
      return {
        ...ie,
        status: next,
        version: (ie.version ?? 0) + 1,
        versionNonce: Math.floor(Math.random() * 0x7fffffff),
        updated: Date.now(),
      }
    })
    api.updateScene({ elements: updated })
  }

  // ---- Asset upload helpers ------------------------------------------
  // Walk the scene for image elements that haven't been "saved" yet, then
  // for each one whose binary is in api.getFiles(), encrypt+upload and
  // flip the element's status to "saved" via updateScene. The flip is a
  // normal local mutation: scheduleBroadcast picks it up and propagates.
  //
  // Idempotent — guarded by assetSavedRef + pendingUploadsRef so rapid
  // onChange ticks don't fire duplicate uploads.
  async function maybeUploadDirtyAssets() {
    const api = apiRef.current
    if (!api) return
    const els = api.getSceneElementsIncludingDeleted() as OrderedExcalidrawElement[]
    const files = api.getFiles()
    for (const el of els) {
      if (el.type !== 'image') continue
      const img = el as ExcalidrawImageElement
      if (img.isDeleted) continue
      if (!img.fileId) continue
      if (img.status === 'saved') continue
      const fid = img.fileId as string
      if (assetSavedRef.current.has(fid)) continue
      if (pendingUploadsRef.current.has(fid)) continue
      const data = files[fid]
      if (!data || !data.dataURL) continue

      pendingUploadsRef.current.add(fid)
      const elemId = img.id
      ;(async () => {
        try {
          const plain = new TextEncoder().encode(data.dataURL)
          await uploadAsset(fileId, fid, plain, collectionMaster)
          assetSavedRef.current.add(fid)
          flipImageStatus(elemId, 'saved')
        } catch (e) {
          if (e instanceof QuotaExceededError) {
            // 413: don't retry. Surface to the user and flip the element to
            // "error" so the upload-side scan ignores it on next onChange.
            toast.error(t('whiteboard.image.quotaExceeded'))
            assetSavedRef.current.add(fid) // suppress further attempts
            flipImageStatus(elemId, 'error')
          } else {
            console.warn('whiteboard: asset upload failed', e)
          }
        } finally {
          pendingUploadsRef.current.delete(fid)
        }
      })()
    }
  }

  // After applying a remote element merge, walk the merged elements for
  // image elements with status "saved" whose binary is missing locally,
  // and fetch each from the asset blob endpoint.
  function maybeFetchMissingAssets(merged: OrderedExcalidrawElement[]) {
    const api = apiRef.current
    if (!api) return
    const have = api.getFiles()
    for (const el of merged) {
      if (el.type !== 'image') continue
      const img = el as ExcalidrawImageElement
      if (img.isDeleted) continue
      if (img.status !== 'saved') continue
      if (!img.fileId) continue
      const fid = img.fileId as string
      if (have[fid]) continue
      if (fetchedAssetsRef.current.has(fid)) continue
      fetchedAssetsRef.current.add(fid)
      ;(async () => {
        try {
          const plain = await fetchAsset(fileId, fid, collectionMaster)
          const dataURL = new TextDecoder().decode(plain)
          // Recover mimeType from the dataURL prefix; default to png.
          const match = dataURL.match(/^data:([^;]+);/i)
          const mimeType = (match?.[1] ?? 'image/png') as BinaryFileData['mimeType']
          const data: BinaryFileData = {
            id: fid as FileId,
            mimeType,
            dataURL: dataURL as DataURL,
            created: Date.now(),
          }
          const api2 = apiRef.current
          if (!api2) return
          api2.addFiles([data])
          assetSavedRef.current.add(fid)
        } catch (e) {
          console.warn('whiteboard: asset fetch failed', fid, e)
          // Allow a future reconcile to retry — the peer might be in the
          // middle of uploading.
          fetchedAssetsRef.current.delete(fid)
        }
      })()
    }
  }

  // Debounced broadcaster: diff current scene against lastBroadcast
  // and send only the changed elements.
  function scheduleBroadcast() {
    if (broadcastTimerRef.current) return
    broadcastTimerRef.current = setTimeout(async () => {
      broadcastTimerRef.current = null
      const api = apiRef.current
      const transport = transportRef.current
      const did = deviceIdRef.current
      const kp = keypairRef.current
      if (!api || !transport || !did || !kp) return
      // Use IncludingDeleted so deletes are propagated (Excalidraw marks
      // deletions with isDeleted: true rather than removing entries).
      const all = api.getSceneElementsIncludingDeleted() as OrderedExcalidrawElement[]
      const last = lastBroadcastRef.current
      const changed: OrderedExcalidrawElement[] = []
      for (const el of all) {
        const prev = last.get(el.id)
        if (prev === undefined || (el.version ?? 0) > prev) {
          changed.push(el)
        }
      }
      if (changed.length === 0) return
      try {
        outboundSeqRef.current = outboundSeqRef.current + 1n
        const payload = new TextEncoder().encode(JSON.stringify(changed))
        const f = await encryptExcalidrawOp(
          payload, fileId, docKeyIdRef.current, BigInt(did), outboundSeqRef.current, collectionMaster,
        )
        const packed = pack(f)
        const body = packed.subarray(0, packed.length - 64)
        const sig = await ed25519Sign(body, kp.privateKey)
        packed.set(sig, packed.length - 64)
        transport.send(packed)
        for (const el of changed) {
          last.set(el.id, el.version ?? 0)
        }
      } catch (e) {
        console.warn('whiteboard: send failed', e)
      }
    }, 200)
  }

  return (
    <div className="h-full w-full">
      <Suspense
        fallback={<div className="p-4 text-sm text-muted-foreground">Loading whiteboard…</div>}
      >
        <Excalidraw
          theme={theme}
          initialData={initialData ?? undefined}
          excalidrawAPI={(api) => {
            apiRef.current = api
            // Expose for e2e probing (spec 21). Cheap; no security
            // implication — the API surface only mutates the local scene
            // and the user already controls the page.
            ;(window as unknown as { __EXCALIDRAW_API__?: ExcalidrawImperativeAPI }).__EXCALIDRAW_API__ = api
          }}
          onChange={(_elements, appState) => {
            if (applyingRemoteRef.current) return
            scheduleBroadcast()
            // Image binaries: scan for newly-pasted images whose status
            // is still "pending" and upload them. The status flip after
            // upload re-enters this onChange — assetSavedRef short-
            // circuits the second pass.
            maybeUploadDirtyAssets()
            // Selection changes also drive presence so peers see the
            // translucent rectangle around the elements you've selected.
            // selectedElementIds is a small object — JSON.stringify is fine.
            const sel = (appState as { selectedElementIds?: Record<string, true> }).selectedElementIds ?? {}
            const key = JSON.stringify(sel)
            if (key !== lastSelectionKeyRef.current) {
              lastSelectionKeyRef.current = key
              localSelectionRef.current = sel
              schedulePresence()
            }
          }}
          onPointerUpdate={(payload) => {
            const p = payload as {
              pointer: { x: number; y: number; tool: 'pointer' | 'laser' }
              button: 'up' | 'down'
            }
            localPointerRef.current = p.pointer
            localButtonRef.current = p.button
            schedulePresence()
          }}
        />
      </Suspense>
    </div>
  )
}

const WhiteboardEditor = forwardRef<WhiteboardEditorHandle, Props>(WhiteboardEditorBase)
export default WhiteboardEditor
