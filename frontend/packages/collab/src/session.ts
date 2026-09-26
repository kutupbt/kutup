// A live, end-to-end encrypted editing session for one Drive file: the
// shared Yjs document, cursors (awareness), the encrypted relay, the latest
// saved state, saving versions and restoring one. Editors (notes, map lists)
// build their own view on top of `doc` and `awareness`.
//
// Extracted from the notes editor (docs/plans/maps.md, slice 4a); the steps
// and their order are unchanged:
//   1. a device keypair and registered device id,
//   2. the local Y.Doc and awareness,
//   3. the snapshot trigger (editors only) and the restore handler,
//   4. local updates and awareness changes sealed and sent,
//   5. the latest saved state loaded (or the first-content seed claimed),
//   6. the relay transport, which replays everything after that state.
import * as Y from 'yjs'
import { Awareness, applyAwarenessUpdate, encodeAwarenessUpdate } from 'y-protocols/awareness'
import { decryptFileBlobV1, encryptFileBlobV1 } from '@kutup/crypto/fileBlob'
import api from '@kutup/session/client'
import { updateSession } from '@kutup/session/store'
import { claimSeed, listVersions, registerDevice } from './api'
import { encryptCollabFrameV1, openCollabFrameAtGenerationV1 } from './cryptoFrame'
import { encodePubKeyB64, generateDeviceKeypair, loadKeypair, saveKeypair } from './devices'
import { KIND } from './envelope'
import { buildAwarenessName, randomSenderSeqPrefix, withAlpha } from './identity'
import { SnapshotTrigger } from './snapshot'
import { collabSocketUrl } from './socketUrl'
import { CollabTransport, type HelloMsg, type PositionMsg } from './transport'

// Dedupes concurrent registerDevice() calls within one browser session
// (a StrictMode double mount must not create two device rows).
const devicePromises = new Map<string, Promise<number>>()

function ensureRegistered(pubKeyB64: string, label: string): Promise<number> {
  let pending = devicePromises.get(pubKeyB64)
  if (!pending) {
    pending = registerDevice(pubKeyB64, label).then((r) => r.deviceId)
    devicePromises.set(pubKeyB64, pending)
  }
  return pending
}

/**
 * The first content of a file no one has edited yet, as one Yjs update by a
 * client id derived from the file: every tab builds the same bytes, so an
 * editor's seed and a viewer's local copy are the same item and merge
 * instead of doubling. `fill` writes the content into the fresh document.
 */
export function deterministicSeed(fileId: string, fill: (doc: Y.Doc) => void): Uint8Array {
  const doc = new Y.Doc()
  // FNV-1a over the id: a stable uint32, as Yjs client ids are.
  let id = 0x811c9dc5
  for (let i = 0; i < fileId.length; i++) id = Math.imul(id ^ fileId.charCodeAt(i), 0x01000193) >>> 0
  doc.clientID = id
  fill(doc)
  const update = Y.encodeStateAsUpdate(doc)
  doc.destroy()
  return update
}

export type RestoreChoice = 'save-and-restore' | 'restore-only'

export interface CollabSessionOptions {
  fileId: string
  /** The file's current key and its generation: frames and saved states are sealed under it. */
  fileKey: Uint8Array
  keyGeneration: number
  /** Older generations' keys, for what was stored before a re-key. */
  fileKeyAt?: (generation: number) => Promise<Uint8Array>
  /** Follow edits live, change nothing (no saving, no restoring). */
  readOnly: boolean
  /** The signed-in user, for the cursor label. */
  username: string | null
  /** This browser's collaboration device id, if already registered. */
  storedDeviceId: number | null
  cursorColor: string
  /**
   * The first content, for a file that has never been saved: the seed
   * update (see `deterministicSeed`) and whether the document is still
   * empty (so a late seed never lands on top of edits).
   */
  seed?: { update: () => Uint8Array; isEmpty: (doc: Y.Doc) => boolean }
  /** Replace the live document's content with an old state's (restore). */
  replaceContent: (live: Y.Doc, old: Y.Doc) => void
  /** Labels for the versions a restore saves. */
  labels: { preRestore: () => string; restored: () => string }
  /** Called after each saved version (e.g. to redraw a thumbnail). */
  onSnapshot?: (versionId: string, explicit: boolean) => void
  onSaveError?: (error: unknown) => void
  onStatus: (status: 'connecting' | 'ready' | 'error') => void
  /** Other people (tabs) in the document now. */
  onCollaborators?: (count: number) => void
  /** Stop: resolves to null if aborted before the session was up. */
  signal: AbortSignal
}

export interface CollabSession {
  doc: Y.Doc
  awareness: Awareness
  /** Absent for viewers. */
  trigger: SnapshotTrigger | null
  restore: ((versionId: string, choice: RestoreChoice) => Promise<void>) | null
  close: () => void
}

/**
 * Open the session. Resolves once the saved state is loaded and the relay is
 * connecting; `onStatus('ready')` follows when the relay has replayed.
 */
export async function openCollabSession(options: CollabSessionOptions): Promise<CollabSession | null> {
  const { fileId, fileKey, keyGeneration, fileKeyAt, readOnly, signal } = options

  // 1. A device keypair and registered device id.
  let keypair = loadKeypair()
  if (!keypair) {
    keypair = await generateDeviceKeypair()
    saveKeypair(keypair)
  }
  let deviceId = options.storedDeviceId
  if (!deviceId) {
    deviceId = await ensureRegistered(encodePubKeyB64(keypair.publicKey), navigator.userAgent.slice(0, 80))
    if (signal.aborted) return null
    updateSession({ currentDeviceId: deviceId })
  }
  if (signal.aborted) return null
  const kp = keypair
  const device = deviceId

  // 2. The document and awareness. Each tab has its own name and colour.
  const doc = new Y.Doc()
  const awareness = new Awareness(doc)
  awareness.setLocalStateField('user', {
    name: buildAwarenessName(options.username),
    color: options.cursorColor,
    colorLight: withAlpha(options.cursorColor, 0.3),
  })
  // How far into the relay's log this document is known to be complete:
  // every kept frame up to `applied` is in it. Saved versions record it (so
  // trimming the log never removes an edit they lack) and reconnects resume
  // from it. Positions announced beyond it wait until the gap closes.
  let applied = 0
  const announced = new Set<number>()
  const advance = () => {
    while (announced.has(applied + 1)) {
      announced.delete(applied + 1)
      applied += 1
    }
    for (const seq of announced) if (seq <= applied) announced.delete(seq)
  }
  let docKeyId = 1
  const keyOf = async (generation: number): Promise<Uint8Array> => {
    if (generation === keyGeneration) return fileKey
    if (!fileKeyAt) throw new Error('no key for an older generation')
    return fileKeyAt(generation)
  }
  // Per-tab sender_seq partition: two tabs of one user share a device row,
  // so a random prefix keeps (file_id, sender_device, sender_seq) unique.
  let outboundSeq = randomSenderSeqPrefix()
  let transport: CollabTransport | null = null

  // 3. Saving versions (editors only) and restoring one.
  const trigger = readOnly
    ? null
    : new SnapshotTrigger({
        onSnapshot: (versionId, explicit) => options.onSnapshot?.(versionId, explicit),
        fileId,
        ydoc: doc,
        getSeq: () => applied,
        encryptSnapshot: async (bytes: Uint8Array) => {
          const out = await encryptFileBlobV1(bytes, fileKey, { fileId, generation: keyGeneration })
          return { ciphertext: out, storageHints: { docKeyId, sizeBytes: out.length } }
        },
        onError: (error) => options.onSaveError?.(error),
      })

  const restore =
    trigger &&
    (async (versionId: string, choice: RestoreChoice) => {
      const r = await api.get(`/files/${fileId}/versions/${versionId}/download`, { responseType: 'arraybuffer' })
      const blob = new Uint8Array(r.data as ArrayBuffer)
      const generation = (await listVersions(fileId)).find((v) => v.id === versionId)?.keyGeneration ?? keyGeneration
      const state = await decryptFileBlobV1(blob, await keyOf(generation), { fileId, generation })
      const old = new Y.Doc()
      Y.applyUpdateV2(old, state)
      if (choice === 'save-and-restore') await trigger.forceSave(options.labels.preRestore())
      options.replaceContent(doc, old)
      old.destroy()
      // The restore is itself a milestone.
      await trigger.forceSave(options.labels.restored(), true)
    })

  // 4. Local updates and awareness changes, sealed and sent.
  const onLocalUpdate = (update: Uint8Array, origin: unknown) => {
    if (origin === 'remote') return
    void (async () => {
      outboundSeq++
      const frame = await encryptCollabFrameV1(
        update,
        KIND.YJS_UPDATE,
        { fileId, keyGeneration, docKeyId, deviceId: BigInt(device), sequence: outboundSeq },
        fileKey,
        kp.privateKey,
      )
      transport?.send(frame)
    })()
  }
  doc.on('update', onLocalUpdate)

  const onAwarenessChange = (
    { added, updated, removed }: { added: number[]; updated: number[]; removed: number[] },
    origin: unknown,
  ) => {
    if (origin === 'remote') return
    const changed = [...added, ...updated, ...removed]
    if (changed.length === 0) return
    void (async () => {
      const update = encodeAwarenessUpdate(awareness, changed)
      outboundSeq++
      const frame = await encryptCollabFrameV1(
        update,
        KIND.YJS_AWARENESS,
        { fileId, keyGeneration, docKeyId, deviceId: BigInt(device), sequence: outboundSeq },
        fileKey,
        kp.privateKey,
      )
      transport?.send(frame)
    })()
  }
  awareness.on('change', onAwarenessChange)

  const countCollaborators = () => {
    let n = 0
    awareness.getStates().forEach((_state, id) => {
      if (id !== doc.clientID) n++
    })
    options.onCollaborators?.(n)
  }
  awareness.on('update', countCollaborators)
  countCollaborators()

  // 5. The latest saved state, or (never saved) the right to seed the first
  // content: the server's claim lets exactly one tab insert it.
  let maySeed = false
  let neverSaved = false
  try {
    const versions = await listVersions(fileId)
    neverSaved = versions.length === 0
    if (versions.length > 0) {
      const latest = versions[0]
      const r = await api.get(`/files/${fileId}/versions/${latest.id}/download`, { responseType: 'arraybuffer' })
      const blob = new Uint8Array(r.data as ArrayBuffer)
      if (blob.length > 0) {
        const state = await decryptFileBlobV1(blob, await keyOf(latest.keyGeneration), {
          fileId,
          generation: latest.keyGeneration,
        })
        Y.applyUpdateV2(doc, state, 'remote')
        applied = latest.seqAtSnapshot
      }
    } else if (options.seed && !readOnly) {
      try {
        maySeed = (await claimSeed(fileId)).committed
      } catch (error) {
        console.warn('collab: claimSeed failed, opening without seed', error)
      }
    }
  } catch (error) {
    console.warn('collab: failed to load initial content, starting empty', error)
  }

  const close = () => {
    trigger?.destroy()
    doc.off('update', onLocalUpdate)
    awareness.off('change', onAwarenessChange)
    awareness.off('update', countCollaborators)
    doc.destroy()
    transport?.close()
  }
  if (signal.aborted) {
    close()
    return null
  }

  // A saved version trimmed the log past where this document was: merge
  // that version in (merging is safe), and the log continues from there.
  const catchUp = async () => {
    const versions = await listVersions(fileId)
    const latest = versions[0]
    if (!latest) return 0
    const r = await api.get(`/files/${fileId}/versions/${latest.id}/download`, { responseType: 'arraybuffer' })
    const blob = new Uint8Array(r.data as ArrayBuffer)
    if (blob.length > 0) {
      const state = await decryptFileBlobV1(blob, await keyOf(latest.keyGeneration), { fileId, generation: latest.keyGeneration })
      Y.applyUpdateV2(doc, state, 'remote')
    }
    return latest.seqAtSnapshot
  }

  // 6. The relay: replays what came after the saved state, then live frames.
  transport = new CollabTransport({
    url: () => collabSocketUrl(fileId, device),
    lastSeenSeq: () => applied,
    onPosition: async (message: PositionMsg) => {
      if (message.type === 'stored') {
        if (message.seq > applied) announced.add(message.seq)
      } else {
        const version = message.floor > message.since ? await catchUp() : 0
        applied = Math.max(applied, message.throughSeq, version)
      }
      advance()
    },
    onHello: (hello: HelloMsg) => {
      docKeyId = hello.currentDocKeyId
      // Continue after the server's record of this device's sequence.
      if (typeof hello.mySenderSeqHigh === 'number' && hello.mySenderSeqHigh > 0) {
        const high = BigInt(hello.mySenderSeqHigh)
        if (outboundSeq <= high) outboundSeq = randomSenderSeqPrefix(high)
      }
      const seed = options.seed
      // The seed claim was ours: insert the first content now, once.
      if (seed && maySeed && seed.isEmpty(doc)) {
        Y.applyUpdate(doc, seed.update(), 'seed')
        maySeed = false
      }
      // A viewer of a file no editor has opened yet shows the first content
      // locally (not sent); an editor's seed, when it comes, is the same item.
      if (seed && readOnly && neverSaved && hello.headSeq === 0 && seed.isEmpty(doc)) {
        Y.applyUpdate(doc, seed.update(), 'remote')
      }
      options.onStatus('ready')
    },
    onFrame: async (bytes) => {
      try {
        // A frame from before a re-key opens with its generation's key.
        const frame = await openCollabFrameAtGenerationV1(bytes, keyOf, { fileId, keyGeneration })
        if (frame.kind === KIND.YJS_UPDATE) Y.applyUpdate(doc, frame.plaintext, 'remote')
        else if (frame.kind === KIND.YJS_AWARENESS) applyAwarenessUpdate(awareness, frame.plaintext, 'remote')
      } catch (error) {
        console.warn('collab: dropped frame', error)
      }
    },
    onError: (error) => {
      console.warn('collab transport error', error)
      options.onStatus('error')
    },
  })

  return { doc, awareness, trigger, restore, close }
}
