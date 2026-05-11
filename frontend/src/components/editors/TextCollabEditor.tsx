// TextCollabEditor: CodeMirror 6 + Yjs + AEAD-encrypted relay transport.
// Mounts in place of the existing file preview when the file extension matches a
// CodeMirror language (see ../components/editors/dispatch.tsx, written in G1).
import { useEffect, useMemo, useRef, useState } from 'react'
import _sodium from 'libsodium-wrappers-sumo'
import * as Y from 'yjs'
import { yCollab } from 'y-codemirror.next'
import { Awareness, encodeAwarenessUpdate, applyAwarenessUpdate } from 'y-protocols/awareness'
import { Compartment, EditorState, type Extension } from '@codemirror/state'
import {
  EditorView, keymap,
  lineNumbers, highlightActiveLine, drawSelection,
  rectangularSelection, crosshairCursor,
} from '@codemirror/view'
import { defaultKeymap, history, historyKeymap } from '@codemirror/commands'
import { bracketMatching } from '@codemirror/language'
import { closeBrackets } from '@codemirror/autocomplete'
import { search, searchKeymap } from '@codemirror/search'
import { oneDark } from '@codemirror/theme-one-dark'
import { useTheme } from '@/hooks/useTheme'

import { langForExtension } from './lang'
import { CollabTransport, type HelloMsg } from '../../collab/transport'
import { pack, unpack, KIND, type Frame } from '../../collab/envelope'
import { encryptYjsUpdate, decryptYjsUpdate, encryptAwareness, decryptAwareness, deriveContentKey } from '../../collab/cryptoFrame'
import { SnapshotTrigger } from '../../collab/snapshot'
import { ed25519Sign } from '../../collab/sign'
import { generateDeviceKeypair, loadKeypair, saveKeypair, encodePubKeyB64 } from '../../collab/devices'
import { registerDevice, listVersions, claimSeed } from '../../api/collab'
import { QuotaExceededError } from '../../api/errors'
import api from '../../api/client'
import { toast } from 'sonner'
import { useTranslation } from 'react-i18next'
import { useAppDispatch, useAppSelector } from '../../store'
import { setDeviceId, setColor } from '../../store/authSlice'
import { broadcastColor } from '../../lib/sessionSync'
import VersionHistoryPanel from '../VersionHistory/VersionHistoryPanel'
import RestoreConfirmDialog from '@/components/RestoreConfirmDialog'
import { Button } from '@/components/ui/button'
import { Save, BookmarkPlus, History, X, Check } from 'lucide-react'
import CursorColorPicker from './CursorColorPicker'
import MarkdownPreview from './markdown/MarkdownPreview'
import ModeToggle from './markdown/ModeToggle'
import StatusBar, { countWords } from './markdown/StatusBar'
import { useMarkdownMode, nextMode, prevMode } from './markdown/useMarkdownMode'
import {
  buildAwarenessName,
  getCursorColor,
  setCursorColor as persistCursorColor,
  withAlpha,
  randomSenderSeqPrefix,
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
  const { t } = useTranslation()
  const ref = useRef<HTMLDivElement>(null)
  const [status, setStatus] = useState<'connecting' | 'ready' | 'error'>('connecting')
  const [trigger, setTrigger] = useState<SnapshotTrigger | null>(null)
  const triggerRef = useRef<SnapshotTrigger | null>(null)
  const [savingVersion, setSavingVersion] = useState(false)
  const [savingPlain, setSavingPlain] = useState(false)
  const [justSaved, setJustSaved] = useState(false)
  const [historyOpen, setHistoryOpen] = useState(false)
  const [restoreHandler, setRestoreHandler] = useState<((vid: string, choice: 'save-and-restore' | 'restore-only') => Promise<void>) | null>(null)
  const [pendingRestoreVersionId, setPendingRestoreVersionId] = useState<string | null>(null)
  // Cursor color: per-user via authSlice (persisted in DB via /user/me +
  // synced cross-tab via BroadcastChannel). Falls back to localStorage on
  // first load before authSlice has hydrated, or for users who haven't
  // picked a color yet — getCursorColor populates a random palette pick
  // and stashes it locally so the cursor is never invisible.
  const accessToken = useAppSelector(s => s.auth.accessToken)
  const username = useAppSelector(s => s.auth.username)
  const storedDeviceId = useAppSelector(s => s.auth.currentDeviceId)
  const userColor = useAppSelector(s => s.auth.color)
  const dispatch = useAppDispatch()
  const cursorColor = userColor ?? getCursorColor()
  // Stable awareness ref so the color-picker callback can mutate the live
  // awareness state without re-mounting the editor.
  const awarenessRef = useRef<Awareness | null>(null)
  // Stable ytext ref so the markdown preview's checkbox-toggle handler
  // can mutate the document without re-mounting the editor. y-codemirror
  // .next picks the change up and dispatches a CM update — preview re-
  // renders with the new state.
  const ytextRef = useRef<Y.Text | null>(null)
  // EditorView ref so React effects can drive scroll back into the
  // editor (preview-side scroll sync uses this).
  const viewRef = useRef<EditorView | null>(null)
  // Compartment wrapping the CodeMirror theme extension so we can swap
  // light/dark without rebuilding the EditorView (which would tear down
  // cursor + selection state). One Compartment per mount.
  const themeCompartment = useMemo(() => new Compartment(), [])
  const [theme] = useTheme()
  // Ignore the next 'scroll' event after we apply a controlled scroll —
  // otherwise the editor's own onScroll re-emits scrollPercent and we
  // get a feedback loop with the preview.
  const ignoreEditorScrollRef = useRef(false)

  // Markdown view-mode state. The mode toggle (Edit/Split/Read) only
  // appears for .md/.markdown files; code files keep the plain editor.
  const isMarkdown = (() => {
    const dot = filename.lastIndexOf('.')
    if (dot < 0) return false
    const ext = filename.slice(dot + 1).toLowerCase()
    return ext === 'md' || ext === 'markdown'
  })()
  const [mdMode, setMdMode] = useMarkdownMode(fileId)
  // Live document content for the preview pane + word/char count. Updated
  // from the CodeMirror updateListener below — we read ytext.toString()
  // each tick so it picks up remote changes too.
  const [docText, setDocText] = useState<string>(initialContent ?? '')
  const [cursorPos, setCursorPos] = useState<{ line: number; col: number }>({ line: 1, col: 1 })
  // Scroll-percent state shared between editor pane and preview pane in
  // Split mode. The pane that scrolled most-recently is the source of
  // truth; the other mirrors via this state.
  const [scrollPercent, setScrollPercent] = useState<number>(0)
  // Number of remote collaborators currently online (excludes self).
  // Updated from awareness 'change' events.
  const [collaboratorCount, setCollaboratorCount] = useState<number>(0)

  // Toggle the Nth GFM task-list checkbox in the source. Pattern is
  // line-anchored to match only legal task-list syntax (CommonMark +
  // GFM). Mutating ytext via .delete + .insert propagates through
  // y-codemirror.next to the editor (and to remote peers via the
  // existing collab transport).
  function handleToggleTaskList(idx: number, checked: boolean) {
    const ytext = ytextRef.current
    if (!ytext) return
    const taskRE = /^([ \t]*[-*+] +)\[([ xX])\]/gm
    const src = ytext.toString()
    let i = 0
    for (const m of src.matchAll(taskRE)) {
      if (i === idx) {
        const pos = (m.index ?? 0) + m[1].length + 1
        const newChar = checked ? 'x' : ' '
        if (src[pos] === newChar) return
        ytext.delete(pos, 1)
        ytext.insert(pos, newChar)
        return
      }
      i++
    }
  }

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
      ytextRef.current = ytext
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
      // Per-tab sender_seq partition: see randomSenderSeqPrefix in
      // ../../collab/identity. Two tabs of the same user share a
      // sender_device row, so without a high random tabPrefix in the upper
      // 32 bits both tabs would collide on (file_id, sender_device,
      // sender_seq) UNIQUE — the relay would silently drop one frame.
      let outboundSeq = randomSenderSeqPrefix()

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
        // Surface 413 quota errors as a localized toast. Other errors are
        // logged to console only — the autosave path can't surface every
        // transient failure or it'd spam users on flaky networks. Trigger
        // disarms itself after a 413, so this fires at most once per
        // session-after-reload.
        onError: (err) => {
          if (err instanceof QuotaExceededError) {
            toast.error(t('errors.quotaExceededSave'))
          } else {
            console.warn('snapshot save failed', err)
          }
        },
      })
      if (alive) { triggerRef.current = trig; setTrigger(trig) }

      // Restore handler. Wired into VersionHistoryPanel + RestoreConfirmDialog
      // via the staged-versionId pattern in render. The `choice` arg comes
      // from the dialog: 'save-and-restore' pre-snapshots first;
      // 'restore-only' skips the backup snapshot.
      const handleRestore = async (versionId: string, choice: 'save-and-restore' | 'restore-only') => {
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
          if (choice === 'save-and-restore') {
            await trig.forceSave(`Pre-restore @ ${new Date().toLocaleString()}`)
          }
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

      // Track remote-collaborator count for the status bar. Awareness
      // states map clientID → state; we count entries other than our own
      // local clientID. Yjs's awareness 'update' fires on every state
      // change including additions / removals.
      const updateCollabCount = () => {
        const states = awareness!.getStates()
        let n = 0
        const myID = ydoc!.clientID
        states.forEach((_v, id) => { if (id !== myID) n++ })
        setCollaboratorCount(n)
      }
      awareness.on('update', updateCollabCount)
      updateCollabCount()

      // 5.5 Load the latest snapshot from S3 (if any) so the editor shows the
      // current state on open. The relay can't help here — when a snapshot was
      // taken the file_update_log was truncated up to seq_at_snapshot, so a
      // resume(0) would replay nothing. We load the snapshot blob, decrypt,
      // applyUpdateV2 to seed the Y.Doc, then set lastSeenSeq so the WS resume
      // only fetches post-snapshot deltas.
      //
      // For a freshly-created note (no snapshot, no log entries yet), we want
      // to seed Y.Text from `initialContent` exactly once globally. The
      // earlier "headSeq === 0 in onHello" gate looked atomic but wasn't —
      // two tabs whose hellos are computed concurrently both observe
      // headSeq=0 and both seed, and Yjs CRDT-merges the duplicates. The
      // server-arbitrated `claim-seed` endpoint runs an atomic UPDATE
      // false→true so exactly one tab ever wins.
      let mayInitialSeed = false
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
          // Race-safe seed claim. The losing tab simply skips the insert
          // and waits for WS replay to populate Y.Text from the winner's
          // frame. Failures fall through to "don't seed" — the editor
          // opens empty, which is recoverable and strictly better than
          // a duplicated heading.
          try {
            const r = await claimSeed(fileId)
            mayInitialSeed = r.committed
          } catch (e) {
            console.warn('collab: claimSeed failed, opening without seed', e)
          }
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
          // Re-roll the tab prefix if the random pick happened to land at
          // or below the historic high — keeps the (file_id,
          // sender_device, sender_seq) uniqueness guarantee. Vanishingly
          // rare (~2^-32 per fresh tab).
          if (typeof h.mySenderSeqHigh === 'number' && h.mySenderSeqHigh > 0) {
            const high = BigInt(h.mySenderSeqHigh)
            if (outboundSeq <= high) {
              outboundSeq = randomSenderSeqPrefix(high)
            }
          }
          // We won the seed claim earlier — insert the cold-start content
          // now that the WS is up. The local 'update' listener will encrypt
          // and send this as a regular frame; the relay broadcasts it to
          // peers, which replay it onto their (empty) Y.Text via onFrame.
          //
          // Losing tabs (mayInitialSeed=false) fall through and rely on the
          // WS replay alone — server's atomic claim guarantees exactly one
          // local insert per file.
          if (mayInitialSeed && ytext.length === 0 && initialContent) {
            ytext.insert(0, initialContent)
            mayInitialSeed = false  // single-shot
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
        // Note: saveKeymap and the user keymap come BEFORE search keymap
        // so Cmd+S still saves (search wires Cmd+F + a few others).
        saveKeymap,
        keymap.of([...defaultKeymap, ...historyKeymap, ...searchKeymap]),
        history(),
        ...(langExt ? [langExt] : []),
        yCollab(ytext, awareness),
        // ---- Tier 1 baseline polish ----
        lineNumbers(),
        highlightActiveLine(),
        drawSelection(),
        bracketMatching(),
        closeBrackets(),
        search({ top: true }),
        rectangularSelection(),
        crosshairCursor(),
        EditorState.allowMultipleSelections.of(true),
        // Theme: dark mode picks oneDark; light mode uses CM6 defaults.
        // Wrapped in a Compartment so the useEffect below can reconfigure
        // on theme change without rebuilding the EditorView.
        themeCompartment.of(theme === 'dark' ? oneDark : []),
        // Click-anywhere fallback. CodeMirror's own posAtCoords handles
        // clicks within .cm-content correctly (snapping past line-end to
        // the line's end). For clicks BELOW the last line the wrapper
        // CSS makes .cm-content fill the height — but as a belt+braces
        // measure, if a click reports no position we move the caret to
        // end-of-document (matches Obsidian/VSCode behavior).
        EditorView.domEventHandlers({
          mousedown(event, v) {
            const pos = v.posAtCoords({ x: event.clientX, y: event.clientY })
            if (pos == null) {
              v.dispatch({ selection: { anchor: v.state.doc.length } })
              v.focus()
            }
          },
          scroll(_event, v) {
            // Mirror editor scroll into the React state so the preview
            // pane (in Split mode) follows along. The scrollDOM is the
            // CodeMirror outer scroller. Suppress when the document
            // hasn't grown beyond the viewport (no scroll possible),
            // and when the scroll was caused by a controlled-write from
            // the preview (would feedback-loop otherwise).
            if (ignoreEditorScrollRef.current) {
              ignoreEditorScrollRef.current = false
              return
            }
            const el = v.scrollDOM
            const max = el.scrollHeight - el.clientHeight
            if (max <= 0) return
            setScrollPercent(el.scrollTop / max)
          },
        }),
        // Track document content + cursor position for the status bar
        // and the markdown preview pane. Using updateListener over a
        // ViewPlugin keeps it ergonomic; the cost is one closure call
        // per dispatch, which is negligible at the dispatch rates Yjs
        // produces (typing is debounced upstream).
        EditorView.updateListener.of((u) => {
          if (u.docChanged) {
            setDocText(u.state.doc.toString())
          }
          if (u.selectionSet || u.docChanged) {
            const head = u.state.selection.main.head
            const line = u.state.doc.lineAt(head)
            setCursorPos({ line: line.number, col: head - line.from + 1 })
          }
        }),
      ]
      // Seed CodeMirror's initial doc from ytext so they're in sync at mount.
      // y-codemirror.next assumes parity at mount; if Y.Text was populated by the
      // snapshot-load step above and CM started empty, a later ytext.delete()
      // (e.g. from restore) would reference a CM range that doesn't exist.
      const state = EditorState.create({ doc: ytext.toString(), extensions: exts })
      view = new EditorView({ state, parent: ref.current! })
      viewRef.current = view
      // Seed the React state mirror to the editor's initial doc. Without
      // this, docText holds the stale `initialContent` (cold-start seed)
      // until the user's first keypress fires updateListener — meaning
      // the markdown preview rendered only the seed (often just the
      // "# Untitled" heading) until typing.
      setDocText(state.doc.toString())
      // Auto-focus on mount so the user can start typing immediately
      // without an extra click. Mirrors the way most editors behave on
      // open. Safe because the view is the primary interaction surface;
      // header buttons and dialogs still receive their own focus.
      view.focus()

      // 8. Cleanup on unmount.
      cleanup = () => {
        trig.destroy()
        ydoc?.off('update', onLocalUpdate)
        awareness?.off('change', onAwarenessChange)
        awareness?.off('update', updateCollabCount)
        view?.destroy()
        ydoc?.destroy()
        transport?.close()
      }
    })()

    return () => {
      alive = false
      cleanup?.()
    }
    // storedDeviceId is intentionally NOT a dep: the first render reads it
    // (often null), the registration flow sets it via dispatch, and React's
    // re-render would otherwise tear down + recreate the WS for no reason —
    // and on second mount the claimSeed call would lose, leaving the seed
    // un-inserted. Same pattern as OfficeEditor.tsx.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [fileId, filename, accessToken, collectionMaster, username, dispatch])

  // Page-level Cmd/Ctrl+S — catches the case when CodeMirror doesn't
  // have focus (filename input, color picker, history sidebar, etc.).
  // CM's own keymap (line ~360) still wins when CM is focused, which is
  // faster + cancels its default key bindings.
  // Also Cmd/Ctrl+E cycles markdown view modes (Edit → Split → Read),
  // matching Obsidian's binding. Only fires for .md/.markdown files.
  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if ((e.metaKey || e.ctrlKey) && !e.shiftKey && !e.altKey && (e.key === 's' || e.key === 'S')) {
        const t = triggerRef.current
        if (!t) return
        e.preventDefault()
        t.forceSave(undefined, false)
          .then(() => { setJustSaved(true); setTimeout(() => setJustSaved(false), 1200) })
          .catch((err) => console.warn('save shortcut failed', err))
        return
      }
      if (isMarkdown && (e.metaKey || e.ctrlKey) && (e.key === 'e' || e.key === 'E')) {
        e.preventDefault()
        setMdMode(e.shiftKey ? prevMode(mdMode) : nextMode(mdMode))
        return
      }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [isMarkdown, mdMode, setMdMode])

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

  // Drive the editor's scroll position from the shared scrollPercent
  // state — this is the preview-pane → editor leg of the bidirectional
  // sync (the editor → preview leg is handled by the scroll handler in
  // the extension list). Only active in Split mode; in Edit / Read the
  // panes don't share a viewport.
  useEffect(() => {
    if (!isMarkdown || mdMode !== 'split') return
    const v = viewRef.current
    if (!v) return
    const el = v.scrollDOM
    const max = el.scrollHeight - el.clientHeight
    if (max <= 0) return
    const target = Math.round(max * scrollPercent)
    if (Math.abs(el.scrollTop - target) < 2) return
    ignoreEditorScrollRef.current = true
    el.scrollTop = target
  }, [scrollPercent, mdMode, isMarkdown])

  // Reactive theme: when kutup's theme toggles, reconfigure the
  // Compartment instead of rebuilding the view.
  useEffect(() => {
    viewRef.current?.dispatch({
      effects: themeCompartment.reconfigure(theme === 'dark' ? oneDark : []),
    })
  }, [theme, themeCompartment])

  async function handleCursorColorChange(hex: string) {
    const previous = userColor
    dispatch(setColor(hex))
    broadcastColor(hex)
    persistCursorColor(hex)  // localStorage fallback for the next reload
    try {
      await api.patch('/user/me', { color: hex })
    } catch (err: any) {
      dispatch(setColor(previous))
      broadcastColor(previous)
      // localStorage stays — small UX cost; better than re-flashing.
    }
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
          {isMarkdown && <ModeToggle mode={mdMode} onChange={setMdMode} />}
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
        {/* The CSS class trio is what fixes the "can't click anywhere"
            bug: by default CM6 sizes .cm-editor to its content, so the
            scroll area below the last line was dead. h-full on the
            CodeMirror root + min-h-full on .cm-content makes the
            content area fill the wrapper, so clicks below the text
            land inside .cm-content and CM positions the caret at the
            nearest line. The mousedown handler in the extension list
            above is the belt-and-suspenders fallback for the rare
            null-pos case. */}
        <div
          ref={ref}
          className={
            'overflow-auto [&>.cm-editor]:h-full [&_.cm-content]:min-h-full ' +
            (isMarkdown && mdMode === 'read'
              ? 'hidden'
              : isMarkdown && mdMode === 'split'
                ? 'flex-1 min-w-0 border-r border-border'
                : 'flex-1')
          }
        />

        {/* Markdown preview pane. Visible in Split (50/50) and Read
            (full) modes; hidden in Edit. Source pulls from the live
            ytext via docText state, updated by the editor's
            updateListener — that means remote edits via Yjs propagate
            to the preview within the same React tick. */}
        {isMarkdown && (mdMode === 'split' || mdMode === 'read') && (
          <MarkdownPreview
            source={docText}
            scrollPercent={mdMode === 'split' ? scrollPercent : undefined}
            onScrollPercent={mdMode === 'split' ? setScrollPercent : undefined}
            onToggleTaskList={handleToggleTaskList}
            className={mdMode === 'split' ? 'flex-1 min-w-0' : 'flex-1'}
          />
        )}

        {historyOpen && (
          <aside className="flex h-full w-[360px] min-h-0 shrink-0 flex-col overflow-hidden border-l border-border bg-card">
            <header className="flex h-12 shrink-0 items-center justify-between border-b border-border px-4">
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
            <div className="flex-1 min-h-0 overflow-y-auto overscroll-contain">
              <VersionHistoryPanel
                fileId={fileId}
                onRestore={(vid) => setPendingRestoreVersionId(vid)}
              />
            </div>
          </aside>
        )}
      </div>

      {/* Status bar — shown in Edit + Split (where the editor is visible
          and cursor position is meaningful). Hidden in Read mode where
          the editor isn't visible. Shown for both markdown and code
          files since line:col + word/char count is useful in code too.
       */}
      {mdMode !== 'read' && (
        <StatusBar
          cursorLine={cursorPos.line}
          cursorCol={cursorPos.col}
          words={countWords(docText)}
          chars={docText.length}
          collaborators={collaboratorCount}
        />
      )}

      <RestoreConfirmDialog
        open={pendingRestoreVersionId !== null}
        onCancel={() => setPendingRestoreVersionId(null)}
        onChoose={(choice) => {
          const vid = pendingRestoreVersionId
          setPendingRestoreVersionId(null)
          if (vid && restoreHandler) restoreHandler(vid, choice).catch(() => {})
        }}
      />

    </div>
  )
}

