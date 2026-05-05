// TextCollabEditor: CodeMirror 6 + Yjs + AEAD-encrypted relay transport.
// Mounts in place of the existing file preview when the file extension matches a
// CodeMirror language (see ../components/editors/dispatch.tsx, written in G1).
import { useEffect, useRef, useState } from 'react'
import _sodium from 'libsodium-wrappers-sumo'
import * as Y from 'yjs'
import { yCollab } from 'y-codemirror.next'
import { Awareness, encodeAwarenessUpdate, applyAwarenessUpdate } from 'y-protocols/awareness'
import { EditorState, type Extension } from '@codemirror/state'
import { EditorView, keymap } from '@codemirror/view'
import { defaultKeymap, history, historyKeymap } from '@codemirror/commands'

import { langForExtension } from './lang'
import { CollabTransport, type HelloMsg } from '../../collab/transport'
import { pack, unpack, KIND, type Frame } from '../../collab/envelope'
import { encryptYjsUpdate, decryptYjsUpdate, encryptAwareness, decryptAwareness, deriveContentKey } from '../../collab/cryptoFrame'
import { SnapshotTrigger } from '../../collab/snapshot'
import { ed25519Sign } from '../../collab/sign'
import { generateDeviceKeypair, loadKeypair, saveKeypair, encodePubKeyB64 } from '../../collab/devices'
import { registerDevice, listVersions } from '../../api/collab'
import api from '../../api/client'
import { useAppDispatch, useAppSelector } from '../../store'
import { setDeviceId } from '../../store/authSlice'
import VersionHistoryPanel from '../VersionHistory/VersionHistoryPanel'

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
  const [trigger, setTrigger] = useState<SnapshotTrigger | null>(null)
  const [savingVersion, setSavingVersion] = useState(false)
  const [historyOpen, setHistoryOpen] = useState(false)
  const [restoreHandler, setRestoreHandler] = useState<((vid: string) => Promise<void>) | null>(null)
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

      // 2.5 Snapshot trigger.
      const trig = new SnapshotTrigger({
        fileId,
        ydoc,
        getSeq: () => Number(outboundSeq),
        encryptSnapshot: async (bytes: Uint8Array) => {
          await _sodium.ready
          const key = await deriveContentKey(collectionMaster, fileId)
          const nonce = _sodium.randombytes_buf(24)
          const ct = _sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(bytes, null, null, nonce, key)
          // Self-contained snapshot: nonce(24) || aead(state).
          // Decrypter must split: nonce = blob[:24], aead_ct = blob[24:].
          const out = new Uint8Array(24 + ct.length)
          out.set(nonce, 0)
          out.set(ct, 24)
          return { ciphertext: out, storageHints: { docKeyId, sizeBytes: out.length } }
        },
      })
      if (alive) setTrigger(trig)

      // Restore handler. Wired into VersionHistoryPanel via onRestore prop.
      const handleRestore = async (versionId: string) => {
        try {
          // axios `api` instance has baseURL='/api'; do NOT include /api/ here.
          const r = await api.get(`/files/${fileId}/versions/${versionId}/download`, {
            responseType: 'arraybuffer',
          })
          const blob = new Uint8Array(r.data as ArrayBuffer)
          if (blob.length < 24 + 17) throw new Error('snapshot blob too short')
          const nonce = blob.subarray(0, 24)
          const ct = blob.subarray(24)
          await _sodium.ready
          const key = await deriveContentKey(collectionMaster, fileId)
          const stateBytes = _sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(null, ct, null, nonce, key)
          // Materialize the old state in a throwaway doc, extract the plaintext.
          const oldDoc = new Y.Doc()
          Y.applyUpdateV2(oldDoc, stateBytes)
          const oldText = oldDoc.getText('content').toString()
          oldDoc.destroy()
          // Pre-save the current state so the restore doesn't clobber unsaved work.
          await trig.forceSave(`Pre-restore @ ${new Date().toLocaleString()}`)
          // Replace live content. CodeMirror sees this as a delete + insert.
          ydoc!.transact(() => {
            ytext.delete(0, ytext.length)
            ytext.insert(0, oldText)
          })
          // Save a named snapshot so the restore is itself a milestone.
          await trig.forceSave(`Restored from ${new Date().toLocaleString()}`, true)
        } catch (e) {
          console.error('restore failed', e)
          alert('Restore failed: ' + (e instanceof Error ? e.message : String(e)))
        }
      }
      if (alive) setRestoreHandler(() => handleRestore)

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

      // 5.5 Load the latest snapshot from S3 (if any) so the editor shows the
      // current state on open. The relay can't help here — when a snapshot was
      // taken the file_update_log was truncated up to seq_at_snapshot, so a
      // resume(0) would replay nothing. We load the snapshot blob, decrypt,
      // applyUpdateV2 to seed the Y.Doc, then set lastSeenSeq so the WS resume
      // only fetches post-snapshot deltas.
      try {
        const versions = await listVersions(fileId)
        if (versions.length > 0) {
          const latest = versions[0] // newest-first ordering
          const r = await api.get(`/files/${fileId}/versions/${latest.id}/download`, {
            responseType: 'arraybuffer',
          })
          const blob = new Uint8Array(r.data as ArrayBuffer)
          if (blob.length >= 24 + 17) {
            const nonce = blob.subarray(0, 24)
            const ct = blob.subarray(24)
            await _sodium.ready
            const key = await deriveContentKey(collectionMaster, fileId)
            const stateBytes = _sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
              null, ct, null, nonce, key,
            )
            // Apply with a synthetic 'remote' origin so onLocalUpdate doesn't
            // re-emit the snapshot bytes back through the relay.
            Y.applyUpdateV2(ydoc, stateBytes, 'remote')
            lastSeenSeq = latest.seqAtSnapshot
          }
        }
      } catch (e) {
        console.warn('collab: failed to load latest snapshot, starting empty', e)
      }
      if (!alive) return

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
        trig.destroy()
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
      <div className="flex items-center justify-between border-b px-3 py-1 text-xs">
        <span className="text-muted-foreground">{filename} · {status}</span>
        <div className="flex items-center gap-2">
          <button
            type="button"
            disabled={!trigger || savingVersion}
            onClick={async () => {
              if (!trigger) return
              const name = window.prompt('Name this version (optional):') ?? undefined
              setSavingVersion(true)
              try {
                await trigger.forceSave(name && name.trim() !== '' ? name.trim() : undefined, !!name)
              } finally {
                setSavingVersion(false)
              }
            }}
            className="rounded border px-2 py-0.5 hover:bg-muted disabled:opacity-50"
          >
            {savingVersion ? 'Saving…' : 'Save version'}
          </button>
          <button
            type="button"
            onClick={() => setHistoryOpen(v => !v)}
            className="rounded border px-2 py-0.5 hover:bg-muted"
          >
            {historyOpen ? 'Hide history' : 'History'}
          </button>
        </div>
      </div>
      <div className="flex flex-1 overflow-hidden">
        <div ref={ref} className="flex-1 overflow-auto" />
        {historyOpen && (
          <aside className="w-80 shrink-0 overflow-y-auto border-l">
            <VersionHistoryPanel
              fileId={fileId}
              onRestore={async (vid) => {
                if (!restoreHandler) return
                if (!window.confirm('Restore this version? Current state will be saved as a new version first.')) return
                await restoreHandler(vid)
              }}
            />
          </aside>
        )}
      </div>
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
