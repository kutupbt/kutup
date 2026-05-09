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
} from '@excalidraw/excalidraw/types'
import type { OrderedExcalidrawElement } from '@excalidraw/excalidraw/element/types'
import { useAppDispatch, useAppSelector } from '@/store'
import { setDeviceId } from '@/store/authSlice'
import { CollabTransport, type HelloMsg } from '@/collab/transport'
import { pack, unpack, KIND, type Frame } from '@/collab/envelope'
import { encryptExcalidrawOp, decryptExcalidrawOp } from '@/collab/cryptoFrame'
import { ed25519Sign } from '@/collab/sign'
import {
  generateDeviceKeypair, loadKeypair, saveKeypair, encodePubKeyB64,
} from '@/collab/devices'
import { randomSenderSeqPrefix } from '@/collab/identity'
import { registerDevice } from '@/api/collab'

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

function WhiteboardEditorBase(
  { fileId, initialBytes, collectionMaster }: Props,
  ref: Ref<WhiteboardEditorHandle>,
) {
  const apiRef = useRef<ExcalidrawImperativeAPI | null>(null)
  const dispatch = useAppDispatch()
  const accessToken = useAppSelector(s => s.auth.accessToken)
  const storedDeviceId = useAppSelector(s => s.auth.currentDeviceId)

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
      return {
        elements: json.elements ?? [],
        appState,
        files: json.files ?? {},
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
            if (f.kind !== KIND.EXCALIDRAW_OP) return
            const payload = await decryptExcalidrawOp(f, fileId, collectionMaster)
            const remote = JSON.parse(new TextDecoder().decode(payload)) as OrderedExcalidrawElement[]
            const api = apiRef.current
            if (!api) return
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
          } catch (e) {
            console.warn('whiteboard: dropped frame', e)
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
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps -- accessToken
    // captured in URL on first connect; refresh handled by transport
    // reconnect, NOT by re-mounting the WS (would lose in-flight broadcasts).
  }, [fileId, collectionMaster, dispatch])

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
          initialData={initialData ?? undefined}
          excalidrawAPI={(api) => {
            apiRef.current = api
            // Expose for e2e probing (spec 21). Cheap; no security
            // implication — the API surface only mutates the local scene
            // and the user already controls the page.
            ;(window as unknown as { __EXCALIDRAW_API__?: ExcalidrawImperativeAPI }).__EXCALIDRAW_API__ = api
          }}
          onChange={() => {
            if (applyingRemoteRef.current) return
            scheduleBroadcast()
          }}
        />
      </Suspense>
    </div>
  )
}

const WhiteboardEditor = forwardRef<WhiteboardEditorHandle, Props>(WhiteboardEditorBase)
export default WhiteboardEditor
