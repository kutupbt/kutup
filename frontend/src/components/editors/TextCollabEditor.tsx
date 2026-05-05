// TextCollabEditor: CodeMirror 6 + Yjs + AEAD-encrypted relay transport.
// Mounts in place of the existing file preview when the file extension matches a
// CodeMirror language (see ../components/editors/dispatch.tsx, written in G1).
import { useEffect, useRef, useState } from 'react'
import * as Y from 'yjs'
import { yCollab } from 'y-codemirror.next'
import { Awareness, encodeAwarenessUpdate, applyAwarenessUpdate } from 'y-protocols/awareness'
import { EditorState, type Extension } from '@codemirror/state'
import { EditorView, keymap } from '@codemirror/view'
import { defaultKeymap, history, historyKeymap } from '@codemirror/commands'

import { langForExtension } from './lang'
import { CollabTransport, type HelloMsg } from '../../collab/transport'
import { pack, unpack, KIND, type Frame } from '../../collab/envelope'
import { encryptYjsUpdate, decryptYjsUpdate, encryptAwareness, decryptAwareness } from '../../collab/cryptoFrame'
import { ed25519Sign } from '../../collab/sign'
import { generateDeviceKeypair, loadKeypair, saveKeypair, encodePubKeyB64 } from '../../collab/devices'
import { registerDevice } from '../../api/collab'
import { useAppDispatch, useAppSelector } from '../../store'
import { setDeviceId } from '../../store/authSlice'

// Module-level cache: dedupes concurrent registerDevice() calls within the same
// browser session (prevents StrictMode double-mount from creating two rows).
const _devicePromiseCache = new Map<string, Promise<number>>()

function ensureRegistered(pubKeyB64: string, label: string): Promise<number> {
  let p = _devicePromiseCache.get(pubKeyB64)
  if (!p) {
    p = registerDevice(pubKeyB64, label).then(r => r.deviceId)
    _devicePromiseCache.set(pubKeyB64, p)
  }
  return p
}

interface Props {
  fileId: string
  filename: string
  /** Collection master key (32 bytes). MUST be referentially stable across renders —
   *  otherwise the editor tears down and reconnects every parent re-render. The G1
   *  caller is responsible for memoizing or pulling from a stable Redux selector. */
  collectionMaster: Uint8Array
}

export default function TextCollabEditor({ fileId, filename, collectionMaster }: Props) {
  const ref = useRef<HTMLDivElement>(null)
  const [status, setStatus] = useState<'connecting' | 'ready' | 'error'>('connecting')
  const accessToken = useAppSelector(s => s.auth.accessToken)
  const username = useAppSelector(s => s.auth.username)
  const storedDeviceId = useAppSelector(s => s.auth.currentDeviceId)
  const dispatch = useAppDispatch()

  useEffect(() => {
    if (!ref.current || !accessToken) return
    let alive = true
    let view: EditorView | null = null
    let transport: CollabTransport | null = null
    let ydoc: Y.Doc | null = null
    let awareness: Awareness | null = null
    let cleanup: (() => void) | null = null

    ;(async () => {
      // 1. Ensure we have a device keypair + registered deviceId.
      let kp = loadKeypair()
      if (!kp) {
        kp = await generateDeviceKeypair()
        saveKeypair(kp)
      }
      let deviceId = storedDeviceId
      if (!deviceId) {
        const pubB64 = encodePubKeyB64(kp.publicKey)
        deviceId = await ensureRegistered(pubB64, navigator.userAgent.slice(0, 80))
        if (!alive) return
        dispatch(setDeviceId(deviceId))
      }
      if (!alive) return

      // 2. Local Yjs doc + awareness.
      ydoc = new Y.Doc()
      const ytext = ydoc.getText('content')
      awareness = new Awareness(ydoc)
      if (username) {
        awareness.setLocalStateField('user', { name: username, color: pickColor(username) })
      }
      let lastSeenSeq = 0
      let docKeyId = 1
      let outboundSeq = 0n

      // 3. Sign-and-send helper.
      const signAndSend = async (f: Frame) => {
        if (!transport) return
        const packed = pack(f)
        const body = packed.subarray(0, packed.length - 64)
        const sig = await ed25519Sign(body, kp!.privateKey)
        packed.set(sig, packed.length - 64)
        transport.send(packed)
      }

      // 4. Local Yjs update -> encrypt + sign + send.
      const onLocalUpdate = (update: Uint8Array, origin: unknown) => {
        if (origin === 'remote') return
        ;(async () => {
          // Per-device sequence is incremented synchronously to guarantee uniqueness; the
          // encrypt → sign → send chain is async, so wire-arrival order may differ from
          // generation order. The server's UNIQUE (file_id, sender_device, sender_seq)
          // index in migration 013 deduplicates either way; Yjs convergence handles
          // out-of-order application.
          outboundSeq++
          const f = await encryptYjsUpdate(update, fileId, docKeyId, BigInt(deviceId!), outboundSeq, collectionMaster)
          await signAndSend(f)
        })()
      }
      ydoc.on('update', onLocalUpdate)

      // 5. Local awareness change -> encrypt + send (no persistence server-side).
      const onAwarenessChange = (
        { added, updated, removed }: { added: number[]; updated: number[]; removed: number[] },
        origin: unknown,
      ) => {
        if (origin === 'remote') return
        const changed = [...added, ...updated, ...removed]
        if (changed.length === 0) return
        ;(async () => {
          const upd = encodeAwarenessUpdate(awareness!, changed)
          outboundSeq++
          const f = await encryptAwareness(upd, fileId, docKeyId, BigInt(deviceId!), outboundSeq, collectionMaster)
          await signAndSend(f)
        })()
      }
      awareness.on('change', onAwarenessChange)

      // 6. Build transport.
      const wsUrl = `${location.origin.replace(/^http/, 'ws')}/api/files/${fileId}/collab/ws?token=${encodeURIComponent(accessToken)}&deviceId=${deviceId}`
      transport = new CollabTransport({
        url: wsUrl,
        lastSeenSeq: () => lastSeenSeq,
        onHello: (h: HelloMsg) => {
          docKeyId = h.currentDocKeyId
          lastSeenSeq = h.headSeq
          setStatus('ready')
        },
        onFrame: async (bs) => {
          try {
            const f = unpack(bs)
            if (f.kind === KIND.YJS_UPDATE) {
              const upd = await decryptYjsUpdate(f, fileId, collectionMaster)
              Y.applyUpdate(ydoc!, upd, 'remote')
            } else if (f.kind === KIND.YJS_AWARENESS) {
              const upd = await decryptAwareness(f, fileId, collectionMaster)
              applyAwarenessUpdate(awareness!, upd, 'remote')
            }
            // Snapshot/oo_* kinds ignored in v1 text path.
          } catch (e) {
            // Drop invalid/undecryptable frames silently.
            console.warn('collab: dropped frame', e)
          }
        },
        onError: (e) => {
          console.warn('collab transport error', e)
          setStatus('error')
        },
      })

      // 7. Build the CodeMirror editor.
      const ext = filename.split('.').pop()?.toLowerCase() ?? ''
      const langExt = langForExtension(ext)
      const exts: Extension[] = [
        keymap.of([...defaultKeymap, ...historyKeymap]),
        history(),
        ...(langExt ? [langExt] : []),
        yCollab(ytext, awareness),
      ]
      const state = EditorState.create({ extensions: exts })
      view = new EditorView({ state, parent: ref.current! })

      // 8. Cleanup on unmount.
      cleanup = () => {
        ydoc?.off('update', onLocalUpdate)
        awareness?.off('change', onAwarenessChange)
        view?.destroy()
        ydoc?.destroy()
        transport?.close()
      }
    })()

    return () => {
      alive = false
      cleanup?.()
    }
  }, [fileId, filename, accessToken, collectionMaster, storedDeviceId, username, dispatch])

  return (
    <div className="flex h-full w-full flex-col">
      <div className="border-b px-3 py-1 text-xs text-muted-foreground">
        {filename} · {status}
      </div>
      <div ref={ref} className="flex-1 overflow-auto" />
    </div>
  )
}

// Stable color hash for awareness cursors.
function pickColor(s: string): string {
  let h = 0
  for (let i = 0; i < s.length; i++) h = (h * 31 + s.charCodeAt(i)) | 0
  const colors = ['#ef4444', '#f59e0b', '#10b981', '#3b82f6', '#8b5cf6', '#ec4899', '#06b6d4', '#84cc16']
  return colors[Math.abs(h) % colors.length]
}
