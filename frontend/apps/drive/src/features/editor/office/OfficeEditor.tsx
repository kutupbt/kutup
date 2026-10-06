// SPDX-FileCopyrightText: 2026 kutup contributors
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Part of kutup's client-side OnlyOffice integration. This file is licensed
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
import { useTranslation } from 'react-i18next'
import { collabSocketUrl } from '@kutup/collab/socketUrl'
import { appUrl, getAppDirectory } from '@kutup/session/apps'
import { LoadingPanel } from '@kutup/ui/components/states'
import { updateSession, useRequiredSession } from '@kutup/session/store'
import { CollabTransport, type BaseMsg, type HelloMsg, type PositionMsg } from '@kutup/collab/transport'
import type { LogPosition } from '../snapshots'
import { KIND } from '@kutup/collab/envelope'
import { encryptCollabFrameV1, openCollabFrameV1 } from '@kutup/collab/cryptoFrame'
import {
  generateDeviceKeypair, loadKeypair, saveKeypair, encodePubKeyB64,
} from '@kutup/collab/devices'
import { randomSenderSeqPrefix } from '@kutup/collab/identity'
import { registerDevice } from '@kutup/collab/api'
import { useResolvedTheme } from '../useResolvedTheme'

export interface OfficeEditorHandle {
  /** Asks inner.html for the document as a file: OOXML through x2t, or
   *  for a PDF its edits applied to it by x2t. Resolves with the bytes and
   *  their format so callers know what extension to encode. */
  save: () => Promise<{ bytes: Uint8Array; format: DocType }>
  /** The document as OnlyOffice lays it out, as a PDF (for its thumbnail). */
  thumbnailPdf: () => Promise<Uint8Array>
  /** Where this editor is in the collaboration log (read before `save`). */
  logPosition: () => LogPosition
}

interface Props {
  fileId: string
  filename: string
  /** The file key collaboration frames are sealed under, and its generation. */
  fileKey: Uint8Array
  keyGeneration: number
  initialBytes?: Uint8Array
  /** Fires when inner.html intercepts Cmd/Ctrl+S inside the OO iframe.
   *  Parent should call its save handler. */
  onSaveShortcut?: () => void
  /** View-only access: OnlyOffice opens in its viewer; nothing is sent. */
  readOnly?: boolean
  /** The version `initialBytes` came from (null: the original upload) and
   *  its log position: claimed as the session's base, replayed after. */
  base?: SessionBase
  /** Claim `base` as the room's new base once (after a restore). */
  resetBase?: boolean
  /** The room's session base is another version (or a restore replaced it):
   *  the document must reopen from `base` (latest when omitted). */
  onOutdated?: (base?: SessionBase) => void
}

/** Where an office editing session started (docs/onlyoffice.md). */
export interface SessionBase {
  versionId: string | null
  seq: number
}

export type DocType = 'docx' | 'xlsx' | 'pptx' | 'pdf'

/**
 * OnlyOffice runs on its own origin (editor.<domain>), which holds no
 * session, keys or API: the bridge there sees only the document this page
 * hands it. Every message to it names that origin, and only messages from
 * it (and from this iframe) are read.
 */
function officeOrigin(): string {
  return getAppDirectory().editor
}

/** How long the bridge may take to say it is ready before we give up. */
const BRIDGE_TIMEOUT_MS = 30_000

function detectType(filename: string): DocType | null {
  const ext = filename.split('.').pop()?.toLowerCase() ?? ''
  if (ext === 'docx') return 'docx'
  if (ext === 'xlsx') return 'xlsx'
  if (ext === 'pptx') return 'pptx'
  if (ext === 'pdf') return 'pdf'
  return null
}

// All postMessage envelopes we exchange with inner.html.
type FromBridge =
  | { type: 'ready'; docType: string | null }
  | { type: 'pong' }
  | { type: 'init-ack' }
  | { type: 'save-result'; requestId: number; bytes?: Uint8Array; format?: DocType; error?: string }
  | { type: 'thumbnail-result'; requestId: number; bytes?: Uint8Array; error?: string }
  | { type: 'oo-local-op'; payload: string }
  | { type: 'oo-local-cursor'; payload: string }
  | { type: 'oo-save-shortcut' }
  /** The document cannot open (`notPdf`: no PDF header in the file). */
  | { type: 'failed'; reason: string; detail: string | null }
type ToBridge =
  | { type: 'ping' }
  | { type: 'init'; payload: InitPayload }
  | { type: 'save-request'; requestId: number }
  | { type: 'thumbnail-request'; requestId: number }
  | { type: 'oo-remote-op'; payload: string }
  | { type: 'oo-remote-cursor'; senderDeviceId: number; payload: string }
  | { type: 'oo-peers'; list: { deviceId: number; userId: string; username?: string; color?: string }[]; ts: number }
  | { type: 'oo-self'; deviceId: number; userId: string }
  | { type: 'oo-color-update'; userId: string; color: string | null }
  | { type: 'oo-theme'; theme: 'dark' | 'light' }

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
  /** Open in OnlyOffice's viewer. */
  readOnly?: boolean
  /** Drive's theme as shown: OnlyOffice opens in its light or dark theme. */
  theme: 'dark' | 'light'
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
  {
    fileId,
    filename,
    initialBytes,
    fileKey,
    keyGeneration,
    onSaveShortcut,
    readOnly = false,
    base,
    resetBase = false,
    onOutdated,
  }: Props,
  ref: Ref<OfficeEditorHandle>,
) {
  // Stable ref so the postMessage handler doesn't need to re-bind when
  // the parent's callback identity churns.
  const onSaveShortcutRef = useRef(onSaveShortcut)
  onSaveShortcutRef.current = onSaveShortcut
  const onOutdatedRef = useRef(onOutdated)
  onOutdatedRef.current = onOutdated
  const iframeRef = useRef<HTMLIFrameElement>(null)
  const [bridgeReady, setBridgeReady] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const { t } = useTranslation()
  const docType = detectType(filename)
  // Read when the editor starts; later changes go over as 'oo-theme'.
  const theme = useResolvedTheme()
  const themeRef = useRef(theme)
  themeRef.current = theme

  // Save() imperative handle plumbing.
  const pendingSavesRef = useRef<Map<number, {
    resolve: (v: { bytes: Uint8Array; format: DocType }) => void
    reject: (e: Error) => void
  }>>(new Map())
  const nextSaveIdRef = useRef(1)
  const pendingThumbnailsRef = useRef<Map<number, { resolve: (pdf: Uint8Array) => void; reject: (e: Error) => void }>>(new Map())

  // Collab WS state — held in refs so message handlers (which are stable)
  // see the latest values without re-binding.
  const transportRef = useRef<CollabTransport | null>(null)
  const deviceIdRef = useRef<number | null>(null)
  const keypairRef = useRef<{ publicKey: Uint8Array; privateKey: Uint8Array } | null>(null)
  const docKeyIdRef = useRef<number>(1)
  // The collaboration log up to here is in the document (the version it
  // opened from, then every frame applied since, the editor's own included).
  const lastSeenSeqRef = useRef<number>(base?.seq ?? 0)
  const baseRef = useRef<SessionBase>(base ?? { versionId: null, seq: 0 })
  const resetBaseRef = useRef(resetBase)
  // Per-tab sender_seq partition — see randomSenderSeqPrefix doc in
  // @/collab/identity. Two tabs of the same user share a sender_device
  // row; without a high random tabPrefix in the upper 32 bits, both
  // tabs would collide on (file_id, sender_device, sender_seq) UNIQUE
  // and one frame would silently drop, producing one-way sync.
  const outboundSeqRef = useRef<bigint>(randomSenderSeqPrefix())

  const session = useRequiredSession()
  const storedDeviceId = session.currentDeviceId
  const username = session.username
  const color = session.color
  const userId = session.userId

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
          officeOrigin(),
        )
      }),
    thumbnailPdf: () =>
      new Promise((resolve, reject) => {
        const target = iframeRef.current?.contentWindow
        if (!target) {
          reject(new Error('editor iframe not mounted'))
          return
        }
        const requestId = nextSaveIdRef.current++
        pendingThumbnailsRef.current.set(requestId, { resolve, reject })
        target.postMessage({ type: 'thumbnail-request', requestId } satisfies ToBridge, officeOrigin())
      }),
    logPosition: () => ({ seq: lastSeenSeqRef.current, docKeyId: docKeyIdRef.current }),
  }), [docType])

  // ---- bridge handshake (init / init-ack / save-result / oo-local-op) ----
  useEffect(() => {
    if (!docType) {
      setError(t('editor.office.unsupported'))
      return
    }

    function send(msg: ToBridge) {
      const iframe = iframeRef.current
      if (!iframe || !iframe.contentWindow) return
      iframe.contentWindow.postMessage(msg, officeOrigin())
    }

    async function sendLocalOp(payload: string) {
      const transport = transportRef.current
      const did = deviceIdRef.current
      const kp = keypairRef.current
      if (!transport || !did || !kp) {
        console.warn('[office] sendLocalOp dropped — transport/did/kp not ready', { hasTransport: !!transport, hasDid: !!did, hasKp: !!kp, payloadLen: payload.length })
        return
      }
      try {
        outboundSeqRef.current = outboundSeqRef.current + 1n
        const packed = await encryptCollabFrameV1(
          new TextEncoder().encode(payload),
          KIND.OO_OP,
          {
            fileId,
            keyGeneration,
            docKeyId: docKeyIdRef.current,
            deviceId: BigInt(did),
            sequence: outboundSeqRef.current,
          },
          fileKey,
          kp.privateKey,
        )
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
        const packed = await encryptCollabFrameV1(
          new TextEncoder().encode(payload),
          KIND.OO_CURSOR,
          {
            fileId,
            keyGeneration,
            docKeyId: docKeyIdRef.current,
            deviceId: BigInt(did),
            sequence: outboundSeqRef.current,
          },
          fileKey,
          kp.privateKey,
        )
        transport.send(packed, { edit: false })
      } catch (e) {
        console.warn('office: send cursor failed', e)
      }
    }

    function onMessage(e: MessageEvent<FromBridge>) {
      if (e.origin !== officeOrigin()) return
      const iframe = iframeRef.current
      if (!iframe || e.source !== iframe.contentWindow) return
      const msg = e.data
      if (!msg || typeof msg !== 'object') return

      switch (msg.type) {
        case 'ready':
          setBridgeReady(true)
          // Send 'oo-self' before 'init' so the bridge's maybeStart() —
          // which gates on selfDeviceId/selfUserId — has both sides of the
          // identity ready when 'init' lands. The WS effect also posts
          // 'oo-self', but on refresh storedDeviceId is hydrated from
          // sessionStorage and the WS effect sends it BEFORE inner.html's
          // listener is attached (the await in ensureRegistered that gave
          // it a head start on first login is skipped). Sending here on
          // 'ready' guarantees the iframe is listening.
          {
            const did = deviceIdRef.current ?? storedDeviceId
            if (did != null && userId) {
              send({ type: 'oo-self', deviceId: did, userId })
            }
          }
          send({
            type: 'init',
            payload: {
              type: docType!,
              filename,
              fileId,
              initialBytes,
              username: username ?? undefined,
              color: color ?? null,
              readOnly,
              theme: themeRef.current,
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
        case 'thumbnail-result': {
          const pending = pendingThumbnailsRef.current.get(msg.requestId)
          if (!pending) return
          pendingThumbnailsRef.current.delete(msg.requestId)
          if (msg.bytes) pending.resolve(msg.bytes instanceof Uint8Array ? msg.bytes : new Uint8Array(msg.bytes))
          else pending.reject(new Error(msg.error ?? 'no thumbnail'))
          return
        }
        case 'oo-local-op':
          // OnlyOffice fired saveChanges → relay through WS (never from a
          // viewer, whose edits the server would drop anyway).
          if (!readOnly) void sendLocalOp(msg.payload)
          return
        case 'oo-local-cursor':
          // OnlyOffice fired a cursor/selection event → broadcast as ephemeral.
          void sendLocalCursor(msg.payload)
          return
        case 'oo-save-shortcut':
          // User pressed Cmd/Ctrl+S inside the OO iframe — inner.html
          // intercepted it, suppressed the browser save dialog, and
          // forwarded the intent here. Bubble up to the parent.
          onSaveShortcutRef.current?.()
          return
        case 'failed':
          console.warn('[office] the editor could not open the document', msg.reason, msg.detail)
          setError(msg.reason === 'notPdf' ? t('editor.office.notPdf') : t('editor.office.openFailed'))
          return
      }
    }

    window.addEventListener('message', onMessage)
    return () => window.removeEventListener('message', onMessage)
    // color/username changes don't need a full effect re-run (init send is
    // gated by 'ready', which fires once); a separate effect below pushes
    // them live.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [docType, filename, fileId, initialBytes, fileKey, readOnly])

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
      officeOrigin(),
    )
  }, [userId, color])

  // Drive's theme toggled: OnlyOffice switches with it.
  useEffect(() => {
    iframeRef.current?.contentWindow?.postMessage({ type: 'oo-theme', theme } satisfies ToBridge, officeOrigin())
  }, [theme])

  // ---- WebSocket transport ----
  useEffect(() => {
    if (!docType) return
    let alive = true

    void (async () => {
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
        updateSession({ currentDeviceId: did })
      }
      deviceIdRef.current = did

      // 2. Open the relay WebSocket.
      const wsUrl = () => collabSocketUrl(fileId, did)
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
          officeOrigin(),
        )
      }

      // Tell the bridge which deviceId is "self" so it can filter that
      // entry out of the peer list (self stays at SELF_INDEX_USER and
      // doesn't need a separate participant entry).
      const iframeForSelf = iframeRef.current
      if (iframeForSelf && iframeForSelf.contentWindow && did && userId) {
        iframeForSelf.contentWindow.postMessage(
          { type: 'oo-self', deviceId: did, userId } satisfies ToBridge,
          officeOrigin(),
        )
      }

      const transport = new CollabTransport({
        url: wsUrl,
        lastSeenSeq: () => lastSeenSeqRef.current,
        // Every connect claims the session base this document loaded.
        openMessages: () => {
          const reset = resetBaseRef.current
          resetBaseRef.current = false
          return [{ type: 'base', versionId: baseRef.current.versionId, seq: baseRef.current.seq, reset }]
        },
        onBase: (message: BaseMsg) => {
          // Joined a live session that started elsewhere, or a restore
          // replaced it: reopen from the room's base.
          if (message.reset || !message.yours) {
            onOutdatedRef.current?.(message.reset ? undefined : { versionId: message.versionId, seq: message.seq })
          }
        },
        onPosition: (message: PositionMsg) => {
          if (message.type === 'stored') {
            lastSeenSeqRef.current = Math.max(lastSeenSeqRef.current, message.seq)
          } else {
            // Frames before `floor` were trimmed into a version newer than
            // this document: it lacks them, so it reopens from that version.
            if (message.floor > message.since) onOutdatedRef.current?.()
            lastSeenSeqRef.current = Math.max(lastSeenSeqRef.current, message.throughSeq)
          }
        },
        onHello: (h: HelloMsg) => {
          docKeyIdRef.current = h.currentDocKeyId
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
            const f = await openCollabFrameV1(bs, fileKey, {
              fileId,
              keyGeneration,
            })
            if (f.kind === KIND.OO_OP) {
              const payload = f.plaintext
              const iframe = iframeRef.current
              if (iframe && iframe.contentWindow) {
                iframe.contentWindow.postMessage(
                  {
                    type: 'oo-remote-op',
                    payload: new TextDecoder().decode(payload),
                  } satisfies ToBridge,
                  officeOrigin(),
                )
              }
            } else if (f.kind === KIND.OO_CURSOR) {
              const payload = f.plaintext
              const iframe = iframeRef.current
              if (iframe && iframe.contentWindow) {
                iframe.contentWindow.postMessage(
                  {
                    type: 'oo-remote-cursor',
                    senderDeviceId: Number(f.senderDeviceId),
                    payload: new TextDecoder().decode(payload),
                  } satisfies ToBridge,
                  officeOrigin(),
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
    // The WS URL is built per connect from a fresh token (collabSocketUrl); refreshing the
    // token mid-session MUST NOT tear down the WS — that would drop the peer
    // roster and silently break sync. The WS stays authenticated for its
    // lifetime; if the relay needs to re-auth, it'll
    // close the connection and the existing reconnect-with-backoff handles it.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [docType, fileId, fileKey])

  useEffect(() => {
    if (bridgeReady) return
    const timer = setTimeout(() => setError(t('editor.office.unavailable')), BRIDGE_TIMEOUT_MS)
    return () => clearTimeout(timer)
  }, [bridgeReady, t])

  if (error) {
    return (
      <div className="flex h-full w-full items-center justify-center p-6 text-sm text-destructive">
        {error}
      </div>
    )
  }

  return (
    <div className="relative h-full w-full">
      <iframe
        ref={iframeRef}
        title={filename}
        src={appUrl(
          'editor',
          `/onlyoffice/inner.html?${new URLSearchParams({
            type: docType ?? '',
            fileId,
            // The bridge answers only this origin (see inner.html).
            parent: window.location.origin,
          }).toString()}`,
        )}
        // Its own origin already; the sandbox takes away top navigation.
        sandbox="allow-scripts allow-same-origin allow-forms allow-popups allow-modals allow-downloads"
        allow="clipboard-read; clipboard-write"
        className="block h-full w-full border-0"
      />
      {bridgeReady ? null : (
        <div className="absolute inset-0 flex items-center justify-center bg-background">
          <LoadingPanel label={t('editor.office.loading')} />
        </div>
      )}
    </div>
  )
}

const OfficeEditor = forwardRef<OfficeEditorHandle, Props>(OfficeEditorBase)
export default OfficeEditor
