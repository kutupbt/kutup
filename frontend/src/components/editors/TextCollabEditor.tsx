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
import { Button } from '@/components/ui/button'
import { Save, BookmarkPlus, History, X, Check } from 'lucide-react'
import CursorColorPicker from './CursorColorPicker'
import {
  buildAwarenessName,
  getCursorColor,
  setCursorColor as persistCursorColor,
  withAlpha,
} from '../../collab/identity'

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
  /** Plaintext content of the original encrypted file blob (kutup's existing per-file
   *  encryption flow). Used as the initial Y.Text content when no Yjs snapshot exists
   *  yet — i.e. on the very first time a freshly-uploaded file is opened in the editor.
   *  After the first Save Version, snapshots become canonical and this is ignored. */
  initialContent?: string
}

export default function TextCollabEditor({ fileId, filename, collectionMaster, initialContent }: Props) {
  const ref = useRef<HTMLDivElement>(null)
  const [status, setStatus] = useState<'connecting' | 'ready' | 'error'>('connecting')
  const [trigger, setTrigger] = useState<SnapshotTrigger | null>(null)
  const [savingVersion, setSavingVersion] = useState(false)
  const [savingPlain, setSavingPlain] = useState(false)
  const [justSaved, setJustSaved] = useState(false)
  const [historyOpen, setHistoryOpen] = useState(false)
  const [restoreHandler, setRestoreHandler] = useState<((vid: string) => Promise<void>) | null>(null)
  const [cursorColor, setCursorColorState] = useState<string>(getCursorColor)
  const accessToken = useAppSelector(s => s.auth.accessToken)
  const username = useAppSelector(s => s.auth.username)
  const storedDeviceId = useAppSelector(s => s.auth.currentDeviceId)
  const dispatch = useAppDispatch()
  // Stable awareness ref so the color-picker callback can mutate the live
  // awareness state without re-mounting the editor.
  const awarenessRef = useRef<Awareness | null>(null)

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
      awarenessRef.current = awareness
      // Each tab gets its own display name (#<tabId>) and randomized color
      // from a 20-color palette (user-customizable via the toolbar). The
      // colorLight is what y-codemirror.next paints as the selection bg.
      awareness.setLocalStateField('user', {
        name: buildAwarenessName(username),
        color: cursorColor,
        colorLight: withAlpha(cursorColor, 0.3),
      })
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
          const latest = versions[0]
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
            Y.applyUpdateV2(ydoc, stateBytes, 'remote')
            lastSeenSeq = latest.seqAtSnapshot
          }
        } else if (initialContent && initialContent.length > 0) {
          // Cold-start: no snapshot yet, but the file has original plaintext from
          // its upload via kutup's existing per-file-key flow. Seed Y.Text so the
          // editor opens with the actual file content.
          ytext.insert(0, initialContent)
        }
      } catch (e) {
        console.warn('collab: failed to load initial content, starting empty', e)
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
          // Resume per-device outbound counter from the server's record so
          // we don't replay sender_seqs and trip the unique index after a
          // refresh / remount.
          if (typeof h.mySenderSeqHigh === 'number' && h.mySenderSeqHigh > 0) {
            outboundSeq = BigInt(h.mySenderSeqHigh)
          }
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
      // Cmd/Ctrl+S → force-save snapshot. Wires to the same `trig.forceSave()`
      // the Save button calls; `triggerRef.current` lets the closure see the
      // latest trigger instance even though it's captured at editor build time.
      const saveKeymap = keymap.of([{
        key: 'Mod-s',
        preventDefault: true,
        run: () => {
          ;(async () => {
            try {
              await trig.forceSave(undefined, false)
              setJustSaved(true)
              setTimeout(() => setJustSaved(false), 1200)
            } catch (e) { console.warn('save shortcut failed', e) }
          })()
          return true
        },
      }])
      const exts: Extension[] = [
        saveKeymap,
        keymap.of([...defaultKeymap, ...historyKeymap]),
        history(),
        ...(langExt ? [langExt] : []),
        yCollab(ytext, awareness),
      ]
      // Seed CodeMirror's initial doc from ytext so they're in sync at mount.
      // y-codemirror.next assumes parity at mount; if Y.Text was populated by the
      // snapshot-load step above and CM started empty, a later ytext.delete()
      // (e.g. from restore) would reference a CM range that doesn't exist.
      const state = EditorState.create({ doc: ytext.toString(), extensions: exts })
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

  // Push live cursor-color updates to awareness without remounting the editor.
  useEffect(() => {
    const a = awarenessRef.current
    if (!a) return
    const prev = a.getLocalState() as { user?: { name?: string } } | null
    a.setLocalStateField('user', {
      name: prev?.user?.name ?? buildAwarenessName(username),
      color: cursorColor,
      colorLight: withAlpha(cursorColor, 0.3),
    })
  }, [cursorColor, username])

  function handleCursorColorChange(hex: string) {
    setCursorColorState(hex)
    persistCursorColor(hex)
  }

  const statusDot = status === 'ready'
    ? 'bg-emerald-500'
    : status === 'connecting'
      ? 'bg-amber-500 animate-pulse'
      : 'bg-destructive'

  return (
    <div className="flex h-full w-full flex-col">
      <div className="flex h-12 items-center gap-3 border-b border-border bg-background/95 px-4">
        <div className="flex min-w-0 items-center gap-2">
          <span className={`inline-block h-2 w-2 rounded-full ${statusDot}`} aria-hidden />
          <span className="truncate text-sm font-medium">{filename}</span>
          <span className="text-xs text-muted-foreground capitalize">· {status}</span>
        </div>

        <div className="ml-auto flex items-center gap-2">
          <CursorColorPicker color={cursorColor} onChange={handleCursorColorChange} />
          <Button
            type="button"
            size="sm"
            variant="outline"
            disabled={!trigger || savingPlain || savingVersion}
            onClick={async () => {
              if (!trigger) return
              setSavingPlain(true)
              try {
                await trigger.forceSave(undefined, false)
                setJustSaved(true)
                setTimeout(() => setJustSaved(false), 1200)
              } finally {
                setSavingPlain(false)
              }
            }}
            title="Save current state (⌘/Ctrl+S)"
            className="gap-1.5"
          >
            {justSaved ? <Check className="h-4 w-4 text-emerald-500" /> : <Save className="h-4 w-4" />}
            {savingPlain ? 'Saving…' : justSaved ? 'Saved' : 'Save'}
          </Button>
          <Button
            type="button"
            size="sm"
            variant="outline"
            disabled={!trigger || savingVersion || savingPlain}
            onClick={async () => {
              if (!trigger) return
              const name = window.prompt('Name this version:')
              const trimmed = name?.trim() ?? ''
              if (!trimmed) return
              setSavingVersion(true)
              try {
                await trigger.forceSave(trimmed, true)
              } finally {
                setSavingVersion(false)
              }
            }}
            title="Save a named, kept-forever milestone"
            className="gap-1.5"
          >
            <BookmarkPlus className="h-4 w-4" />
            {savingVersion ? 'Saving…' : 'Save version'}
          </Button>
          <Button
            type="button"
            size="sm"
            variant={historyOpen ? 'default' : 'outline'}
            onClick={() => setHistoryOpen((v) => !v)}
            className="gap-1.5"
          >
            <History className="h-4 w-4" />
            History
          </Button>
        </div>
      </div>

      <div className="flex flex-1 min-h-0 overflow-hidden">
        <div ref={ref} className="flex-1 overflow-auto" />

        {historyOpen && (
          <aside className="flex w-[360px] shrink-0 flex-col border-l border-border bg-card">
            <header className="flex h-12 items-center justify-between border-b border-border px-4">
              <h2 className="text-sm font-semibold">Version history</h2>
              <Button
                type="button"
                size="icon"
                variant="ghost"
                onClick={() => setHistoryOpen(false)}
                aria-label="Close history"
                className="h-7 w-7"
              >
                <X className="h-4 w-4" />
              </Button>
            </header>
            <div className="flex-1 min-h-0 overflow-y-auto">
              <VersionHistoryPanel
                fileId={fileId}
                onRestore={async (vid) => {
                  if (!restoreHandler) return
                  if (!window.confirm('Restore this version? Current state will be saved as a new version first.')) return
                  await restoreHandler(vid)
                }}
              />
            </div>
          </aside>
        )}
      </div>
    </div>
  )
}

