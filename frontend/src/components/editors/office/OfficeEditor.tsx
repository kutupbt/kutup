// SPDX-FileCopyrightText: 2026 kutup contributors
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Part of kutup's optional OnlyOffice integration. This file is licensed
// AGPL-3.0-or-later because it drives the AGPL OnlyOffice bridge. Kutup
// itself is AGPL-3.0-only; this subtree carries the upstream "or-later"
// suffix to stay compatible with the OnlyOffice client's license terms.
// See ./LICENSE.md.
//
// OfficeEditor — React wrapper around the OnlyOffice bridge iframe.
//
// Phase 5: real-time collab. The bridge captures OnlyOffice's saveChanges
// postMessages and forwards them to us; we wrap each in a libsodium AEAD
// envelope (KIND.OO_OP), sign with our device's Ed25519 key, and ship
// through the existing Go WebSocket relay. Incoming frames go the other
// way: decrypt → bridge → ooChannel.send → OnlyOffice applies remotely.

import {
  useEffect, useImperativeHandle, useRef, useState, forwardRef,
  type Ref,
} from 'react'
import { useAppDispatch, useAppSelector } from '@/store'
import { setDeviceId } from '@/store/authSlice'
import { CollabTransport, type HelloMsg } from '@/collab/transport'
import { pack, unpack, KIND, type Frame } from '@/collab/envelope'
import { encryptOOOp, decryptOOOp, encryptOOCursor, decryptOOCursor } from '@/collab/cryptoFrame'
import { ed25519Sign } from '@/collab/sign'
import {
  generateDeviceKeypair, loadKeypair, saveKeypair, encodePubKeyB64,
} from '@/collab/devices'
import { randomSenderSeqPrefix } from '@/collab/identity'
import { registerDevice } from '@/api/collab'

export interface OfficeEditorHandle {
  /** Asks inner.html to extract the doc binary, run x2t to OOXML, and
   *  return the bytes. Resolves with the converted bytes + format
   *  ('docx'|'xlsx'|'pptx') so callers know what extension to encode. */
  save: () => Promise<{ bytes: Uint8Array; format: 'docx' | 'xlsx' | 'pptx' }>
}

interface Props {
  fileId: string
  filename: string
  collectionMaster: Uint8Array
  initialBytes?: Uint8Array
}

type DocType = 'docx' | 'xlsx' | 'pptx'

function detectType(filename: string): DocType | null {
  const ext = filename.split('.').pop()?.toLowerCase() ?? ''
  if (ext === 'docx') return 'docx'
  if (ext === 'xlsx') return 'xlsx'
  if (ext === 'pptx') return 'pptx'
  return null
}

// All postMessage envelopes we exchange with inner.html.
type FromBridge =
  | { type: 'ready'; docType: string | null }
  | { type: 'pong' }
  | { type: 'init-ack' }
  | { type: 'save-result'; requestId: number; bytes?: Uint8Array; format?: DocType; error?: string }
  | { type: 'oo-local-op'; payload: string }
  | { type: 'oo-local-cursor'; payload: string }
type ToBridge =
  | { type: 'ping' }
  | { type: 'init'; payload: InitPayload }
  | { type: 'save-request'; requestId: number }
  | { type: 'oo-remote-op'; payload: string }
  | { type: 'oo-remote-cursor'; senderDeviceId: number; payload: string }
  | { type: 'oo-peers'; list: { deviceId: number; userId: string; username?: string; color?: string }[]; ts: number }
  | { type: 'oo-self'; deviceId: number; userId: string }
  | { type: 'oo-color-update'; userId: string; color: string | null }

interface InitPayload {
  type: DocType
  filename: string
  fileId: string
  initialBytes?: Uint8Array
  /** Display name for the local user — surfaced as `editorConfig.user.name`
   *  inside OnlyOffice and as the self entry's username in connectState
   *  (so peers see a real handle instead of the previous 'You' placeholder). */
  username?: string
  /** Per-user presence color — populated into userColors[selfUserId] in
   *  the bridge so window.APP.getUserColor returns it for self's foreign-
   *  selection rectangle. Null falls back to OO's deterministic palette. */
  color?: string | null
}

// Module-level cache: dedupes concurrent registerDevice() calls within the
// same browser session — same pattern as TextCollabEditor.
const _devicePromiseCache = new Map<string, Promise<number>>()
function ensureRegistered(pubKeyB64: string, label: string): Promise<number> {
  let p = _devicePromiseCache.get(pubKeyB64)
  if (!p) {
    p = registerDevice(pubKeyB64, label).then(r => r.deviceId)
    _devicePromiseCache.set(pubKeyB64, p)
  }
  return p
}

function OfficeEditorBase(
  { fileId, filename, initialBytes, collectionMaster }: Props,
  ref: Ref<OfficeEditorHandle>,
) {
  const iframeRef = useRef<HTMLIFrameElement>(null)
  const [bridgeReady, setBridgeReady] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const docType = detectType(filename)

  // Save() imperative handle plumbing.
  const pendingSavesRef = useRef<Map<number, {
    resolve: (v: { bytes: Uint8Array; format: DocType }) => void
    reject: (e: Error) => void
  }>>(new Map())
  const nextSaveIdRef = useRef(1)

  // Collab WS state — held in refs so message handlers (which are stable)
  // see the latest values without re-binding.
  const transportRef = useRef<CollabTransport | null>(null)
  const deviceIdRef = useRef<number | null>(null)
  const keypairRef = useRef<{ publicKey: Uint8Array; privateKey: Uint8Array } | null>(null)
  const docKeyIdRef = useRef<number>(1)
  const lastSeenSeqRef = useRef<number>(0)
  // Per-tab sender_seq partition — see randomSenderSeqPrefix doc in
  // @/collab/identity. Two tabs of the same user share a sender_device
  // row; without a high random tabPrefix in the upper 32 bits, both
  // tabs would collide on (file_id, sender_device, sender_seq) UNIQUE
  // and one frame would silently drop, producing one-way sync.
  const outboundSeqRef = useRef<bigint>(randomSenderSeqPrefix())

  const accessToken = useAppSelector(s => s.auth.accessToken)
  const storedDeviceId = useAppSelector(s => s.auth.currentDeviceId)
  const username = useAppSelector(s => s.auth.username)
  const color = useAppSelector(s => s.auth.color)
  const userId = useAppSelector(s => s.auth.userId)
  const dispatch = useAppDispatch()

  useImperativeHandle(ref, () => ({
    save: () =>
      new Promise((resolve, reject) => {
        const iframe = iframeRef.current
        if (!iframe || !iframe.contentWindow) {
          reject(new Error('editor iframe not mounted'))
          return
        }
        if (!docType) {
          reject(new Error('unsupported file extension'))
          return
        }
        const requestId = nextSaveIdRef.current++
        pendingSavesRef.current.set(requestId, { resolve, reject })
        iframe.contentWindow.postMessage(
          { type: 'save-request', requestId } satisfies ToBridge,
          window.location.origin,
        )
      }),
  }), [docType])

  // ---- bridge handshake (init / init-ack / save-result / oo-local-op) ----
  useEffect(() => {
    if (!docType) {
      setError(`Unsupported office extension for ${filename}`)
      return
    }

    function send(msg: ToBridge) {
      const iframe = iframeRef.current
      if (!iframe || !iframe.contentWindow) return
      iframe.contentWindow.postMessage(msg, window.location.origin)
    }

    async function sendLocalOp(payload: string) {
      const transport = transportRef.current
      const did = deviceIdRef.current
      const kp = keypairRef.current
      if (!transport || !did || !kp) {
        // eslint-disable-next-line no-console
        console.warn('[office] sendLocalOp dropped — transport/did/kp not ready', { hasTransport: !!transport, hasDid: !!did, hasKp: !!kp, payloadLen: payload.length })
        return
      }
      try {
        outboundSeqRef.current = outboundSeqRef.current + 1n
        const f = await encryptOOOp(
          new TextEncoder().encode(payload),
          fileId, docKeyIdRef.current, BigInt(did), outboundSeqRef.current,
          collectionMaster,
        )
        const packed = pack(f)
        const body = packed.subarray(0, packed.length - 64)
        const sig = await ed25519Sign(body, kp.privateKey)
        packed.set(sig, packed.length - 64)
        transport.send(packed)
      } catch (e) {
        console.warn('office: send op failed', e)
      }
    }

    async function sendLocalCursor(payload: string) {
      const transport = transportRef.current
      const did = deviceIdRef.current
      const kp = keypairRef.current
      if (!transport || !did || !kp) return
      try {
        outboundSeqRef.current = outboundSeqRef.current + 1n
        const f = await encryptOOCursor(
          new TextEncoder().encode(payload),
          fileId, docKeyIdRef.current, BigInt(did), outboundSeqRef.current,
          collectionMaster,
        )
        const packed = pack(f)
        const body = packed.subarray(0, packed.length - 64)
        const sig = await ed25519Sign(body, kp.privateKey)
        packed.set(sig, packed.length - 64)
        transport.send(packed)
      } catch (e) {
        console.warn('office: send cursor failed', e)
      }
    }

    function onMessage(e: MessageEvent<FromBridge>) {
      if (e.origin !== window.location.origin) return
      const iframe = iframeRef.current
      if (!iframe || e.source !== iframe.contentWindow) return
      const msg = e.data
      if (!msg || typeof msg !== 'object') return

      switch (msg.type) {
        case 'ready':
          setBridgeReady(true)
          send({
            type: 'init',
            payload: {
              type: docType!,
              filename,
              fileId,
              initialBytes,
              username: username ?? undefined,
              color: color ?? null,
            },
          })
          return
        case 'init-ack':
          return
        case 'save-result': {
          const pending = pendingSavesRef.current.get(msg.requestId)
          if (!pending) return
          pendingSavesRef.current.delete(msg.requestId)
          if (msg.error) {
            pending.reject(new Error(msg.error))
          } else if (msg.bytes && msg.format) {
            const u8 = msg.bytes instanceof Uint8Array ? msg.bytes : new Uint8Array(msg.bytes)
            pending.resolve({ bytes: u8, format: msg.format })
          } else {
            pending.reject(new Error('save returned no bytes'))
          }
          return
        }
        case 'oo-local-op':
          // OnlyOffice fired saveChanges → relay through WS.
          sendLocalOp(msg.payload)
          return
        case 'oo-local-cursor':
          // OnlyOffice fired a cursor/selection event → broadcast as ephemeral.
          sendLocalCursor(msg.payload)
          return
      }
    }

    window.addEventListener('message', onMessage)
    return () => window.removeEventListener('message', onMessage)
    // eslint-disable-next-line react-hooks/exhaustive-deps -- color/username
    // changes don't need a full effect re-run (init send is gated by 'ready'
    // which fires once); a separate effect below pushes them live.
  }, [docType, filename, fileId, initialBytes, collectionMaster])

  // Push live color updates to the iframe so the picker's effect is
  // visible without a reload. The bridge updates userColors[selfUserId]
  // and OO's next foreign-cursor render uses the new value via
  // window.APP.getUserColor.
  useEffect(() => {
    const iframe = iframeRef.current
    if (!iframe || !iframe.contentWindow) return
    if (!userId) return
    iframe.contentWindow.postMessage(
      { type: 'oo-color-update', userId, color: color ?? null } satisfies ToBridge,
      window.location.origin,
    )
  }, [userId, color])

  // ---- WebSocket transport ----
  useEffect(() => {
    if (!docType || !accessToken) return
    let alive = true

    ;(async () => {
      // 1. Device keypair + registered deviceId.
      let kp = loadKeypair()
      if (!kp) {
        kp = await generateDeviceKeypair()
        saveKeypair(kp)
      }
      keypairRef.current = kp

      let did = storedDeviceId
      if (!did) {
        const pubB64 = encodePubKeyB64(kp.publicKey)
        did = await ensureRegistered(pubB64, 'kutup-office:' + navigator.userAgent.slice(0, 60))
        if (!alive) return
        dispatch(setDeviceId(did))
      }
      deviceIdRef.current = did

      // 2. Open the relay WebSocket.
      const wsUrl = `${location.origin.replace(/^http/, 'ws')}/api/files/${fileId}/collab/ws?token=${encodeURIComponent(accessToken)}&deviceId=${did}`
      // Forward initial peer-list (from hello) + later updates (from
      // server-pushed `peers` messages) to the bridge so it can rebuild
      // OnlyOffice's connectState. Without this OO rejects remote
      // saveChanges from peers it never learned about, producing the
      // "second-direction sync stalls" bug user-reported on 2026-05-07.
      function forwardPeers(list: { deviceId: number; userId: string; username?: string; color?: string }[], ts: number) {
        const iframe = iframeRef.current
        if (!iframe || !iframe.contentWindow) return
        iframe.contentWindow.postMessage(
          { type: 'oo-peers', list, ts } satisfies ToBridge,
          window.location.origin,
        )
      }

      // Tell the bridge which deviceId is "self" so it can filter that
      // entry out of the peer list (self stays at SELF_INDEX_USER and
      // doesn't need a separate participant entry).
      const iframeForSelf = iframeRef.current
      if (iframeForSelf && iframeForSelf.contentWindow && did && userId) {
        iframeForSelf.contentWindow.postMessage(
          { type: 'oo-self', deviceId: did, userId } satisfies ToBridge,
          window.location.origin,
        )
      }

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
          // Hello carries the initial peer snapshot. Forward immediately so
          // a tab opened into an existing room can connectState before the
          // first remote frame arrives.
          if (Array.isArray(h.peers)) forwardPeers(h.peers, Date.now())
        },
        onPeers: (p) => {
          forwardPeers(p.list, p.ts)
        },
        onFrame: async (bs: Uint8Array) => {
          try {
            const f: Frame = unpack(bs)
            if (f.kind === KIND.OO_OP) {
              const payload = await decryptOOOp(f, fileId, collectionMaster)
              const iframe = iframeRef.current
              if (iframe && iframe.contentWindow) {
                iframe.contentWindow.postMessage(
                  {
                    type: 'oo-remote-op',
                    payload: new TextDecoder().decode(payload),
                  } satisfies ToBridge,
                  window.location.origin,
                )
              }
            } else if (f.kind === KIND.OO_CURSOR) {
              const payload = await decryptOOCursor(f, fileId, collectionMaster)
              const iframe = iframeRef.current
              if (iframe && iframe.contentWindow) {
                iframe.contentWindow.postMessage(
                  {
                    type: 'oo-remote-cursor',
                    senderDeviceId: Number(f.senderDeviceId),
                    payload: new TextDecoder().decode(payload),
                  } satisfies ToBridge,
                  window.location.origin,
                )
              }
            }
          } catch (e) {
            console.warn('office: dropped frame', e)
          }
        },
        onError: (e: unknown) => console.warn('office: ws error', e),
      })
      if (!alive) {
        transport.close()
        return
      }
      transportRef.current = transport
    })()

    return () => {
      alive = false
      transportRef.current?.close()
      transportRef.current = null
    }
    // storedDeviceId is intentionally NOT a dep: the first render reads it
    // (often null), the registration flow sets it via dispatch, and React's
    // re-render would otherwise tear down + recreate the WS for no reason.
    // We hold the registered id in deviceIdRef and don't need it in deps.
    // eslint-disable-next-line react-hooks/exhaustive-deps
    // eslint-disable-next-line react-hooks/exhaustive-deps -- accessToken is
    // captured in the WS URL on first connect; refreshing the token mid-session
    // (App.tsx handles 401 → /auth/refresh) MUST NOT tear down the WS — that
    // would drop the peer roster and silently break sync. The WS itself stays
    // authenticated for its lifetime; if the relay needs to re-auth, it'll
    // close the connection and the existing reconnect-with-backoff handles it.
  }, [docType, fileId, collectionMaster, dispatch])

  if (error) {
    return (
      <div className="flex h-full w-full items-center justify-center p-6 text-sm text-destructive">
        {error}
      </div>
    )
  }

  void bridgeReady

  return (
    <iframe
      ref={iframeRef}
      title={filename}
      src={`/onlyoffice/inner.html?type=${docType}&fileId=${encodeURIComponent(fileId)}`}
      className="block h-full w-full border-0"
    />
  )
}

const OfficeEditor = forwardRef<OfficeEditorHandle, Props>(OfficeEditorBase)
export default OfficeEditor
