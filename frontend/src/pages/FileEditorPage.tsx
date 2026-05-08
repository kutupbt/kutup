import { useEffect, useMemo, useRef, useState, Suspense } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import { Loader2, ArrowLeft, Download, Save, Check } from 'lucide-react'
import { toast } from 'sonner'
import { useAppDispatch, useAppSelector } from '@/store'
import { setColor } from '@/store/authSlice'
import CursorColorPicker from '@/components/editors/CursorColorPicker'
import { broadcastColor } from '@/lib/sessionSync'
import api from '@/api/client'
import {
  decrypt,
  decryptStream,
  encryptStream,
  fromBase64,
  unwrapKeyFromSender,
} from '@/crypto'
import { chooseEditor, chooseOfficeEditor } from '@/components/editors/dispatch'
import type { OfficeEditorHandle } from '@/components/editors/office/OfficeEditor'
import { chooseViewer } from '@/components/viewers/dispatch'
import { Button } from '@/components/ui/button'
import { KutupLogo } from '@/components/KutupLogo'

interface FileMetadata {
  name: string
  mimeType: string
  size: number
}

// Decrypted blob lives entirely in tab memory. A 2 GB video would OOM the
// renderer; cap previews at 100 MB and route the user to the Drive download
// path for anything larger.
const MAX_PREVIEW_BYTES = 100 * 1024 * 1024

export default function FileEditorPage() {
  const { cid, fid } = useParams<{ cid: string; fid: string }>()
  const navigate = useNavigate()
  // selectMasterKey/selectPrivateKey wrap state.auth.masterKey (number[]) in
  // a fresh Uint8Array on every call. Without memoization the file-load
  // effect below sees identity churn on every render — its cleanup re-ran
  // on every authSlice update (e.g. presence-color picks), kicking off
  // /files/{id}/download in a loop and eventually triggering 500s + iframe
  // remounts. Memoize on the underlying number[] which IS stable across
  // dispatches that don't touch the keys.
  const masterKeyArr = useAppSelector(s => s.auth.masterKey)
  const privateKeyArr = useAppSelector(s => s.auth.privateKey)
  const masterKey = useMemo(() => masterKeyArr ? new Uint8Array(masterKeyArr) : null, [masterKeyArr])
  const privateKey = useMemo(() => privateKeyArr ? new Uint8Array(privateKeyArr) : null, [privateKeyArr])
  const userId = useAppSelector((s) => s.auth.userId)
  const publicKey = useAppSelector((s) => s.auth.publicKey)
  const userColor = useAppSelector((s) => s.auth.color)
  const dispatch = useAppDispatch()

  const [phase, setPhase] = useState<'loading' | 'ready' | 'error'>('loading')
  const [error, setError] = useState('')
  const [filename, setFilename] = useState('')
  const [initialContent, setInitialContent] = useState<string | undefined>(undefined)
  const [blobUrl, setBlobUrl] = useState<string | null>(null)
  // Stable Uint8Array reference for the editor — recreating it would cause
  // TextCollabEditor to tear down its provider on every parent render.
  const collectionMasterRef = useRef<Uint8Array | null>(null)
  const [collectionMasterReady, setCollectionMasterReady] = useState(false)
  // Per-file content key — needed for save (encrypt the OOXML output).
  const fileKeyRef = useRef<Uint8Array | null>(null)
  // Imperative handle for OfficeEditor save() calls.
  const officeEditorRef = useRef<OfficeEditorHandle | null>(null)
  const [savingOffice, setSavingOffice] = useState(false)
  const [justSavedOffice, setJustSavedOffice] = useState(false)

  // Pick the right component eagerly so the load step knows whether it needs
  // the bytes as text (editor) or as a blob URL (viewer).
  const Editor = useMemo(() => (filename ? chooseEditor(filename) : null), [filename])
  const Office = useMemo(() => (filename ? chooseOfficeEditor(filename) : null), [filename])
  const viewer = useMemo(() => (filename ? chooseViewer(filename) : null), [filename])
  const [officeBytes, setOfficeBytes] = useState<Uint8Array | null>(null)

  useEffect(() => {
    if (!cid || !fid) return
    if (!masterKey || !privateKey || !userId) {
      const next = encodeURIComponent(`/file/${cid}/${fid}`)
      navigate(`/login?next=${next}`, { replace: true })
      return
    }

    let cancelled = false
    let createdUrl: string | null = null

    ;(async () => {
      try {
        const colRes = await api.get(`/collections/${cid}`)
        if (cancelled) return
        const col = colRes.data

        let collectionKey: Uint8Array
        if (col.ownerUserId !== userId) {
          if (!publicKey) throw new Error('Missing public key for shared collection')
          collectionKey = await unwrapKeyFromSender(
            fromBase64(col.encryptedKey),
            fromBase64(publicKey),
            privateKey,
          )
        } else {
          collectionKey = await decrypt(
            fromBase64(col.encryptedKey),
            fromBase64(col.encryptedKeyNonce),
            masterKey,
          )
        }

        const filesRes = await api.get(`/collections/${cid}/files`)
        if (cancelled) return
        const fileRow = filesRes.data.find((f: any) => f.id === fid)
        if (!fileRow) throw new Error('File not found in this collection')

        const fileKey = await decrypt(
          fromBase64(fileRow.encryptedFileKey),
          fromBase64(fileRow.fileKeyNonce),
          collectionKey,
        )
        const metaBytes = await decrypt(
          fromBase64(fileRow.encryptedMetadata),
          fromBase64(fileRow.metadataNonce),
          fileKey,
        )
        const meta: FileMetadata = JSON.parse(new TextDecoder().decode(metaBytes))
        if (cancelled) return
        setFilename(meta.name)
        document.title = `${meta.name} — Kutup`

        // Decrypt the original blob. Editors need it as text; viewers need it
        // as a blob: URL; office editor wants raw bytes (Phase 3 forwards them
        // to x2t for OOXML→bin conversion). We always do the network + decrypt
        // once; the only difference is how we hand the bytes to the renderer.
        const editorTarget = chooseEditor(meta.name)
        const officeTarget = chooseOfficeEditor(meta.name)
        const viewerTarget = chooseViewer(meta.name)
        if ((editorTarget || officeTarget || viewerTarget) && meta.size > MAX_PREVIEW_BYTES) {
          throw new Error(
            `File is too large to preview in the browser (${Math.round(meta.size / 1024 / 1024)} MB; cap is ${MAX_PREVIEW_BYTES / 1024 / 1024} MB). Download it from Drive instead.`,
          )
        }
        if (editorTarget || officeTarget || viewerTarget) {
          try {
            // Office files: prefer the latest snapshot version (Phase 4a
            // saved one) over the original blob, so reopens see edits.
            // Text/viewer paths still use the original — TextCollabEditor
            // does its own version pickup; viewers just want the raw blob.
            let plain: Uint8Array | null = null
            if (officeTarget) {
              try {
                const versionsRes = await api.get(`/files/${fid}/versions`)
                if (cancelled) return
                const versions = Array.isArray(versionsRes.data) ? versionsRes.data : []
                if (versions.length > 0) {
                  // The endpoint returns versions newest-first per existing
                  // VersionHistoryPanel usage.
                  const latest = versions[0]
                  const vRes = await api.get(`/files/${fid}/versions/${latest.id}/download`, { responseType: 'arraybuffer' })
                  if (cancelled) return
                  plain = await decryptStream(new Uint8Array(vRes.data), fileKey)
                }
              } catch (e) {
                // Fall through to original blob.
                console.warn('office: failed to load latest version, falling back to original', e)
              }
            }
            if (!plain) {
              const dlRes = await api.get(`/files/${fid}/download`, { responseType: 'arraybuffer' })
              if (cancelled) return
              plain = await decryptStream(new Uint8Array(dlRes.data), fileKey)
            }
            if (editorTarget) {
              setInitialContent(new TextDecoder().decode(plain))
            } else if (officeTarget) {
              setOfficeBytes(plain)
            } else if (viewerTarget) {
              const blob = new Blob([plain.buffer as ArrayBuffer], { type: viewerTarget.mimeType })
              createdUrl = URL.createObjectURL(blob)
              setBlobUrl(createdUrl)
            }
          } catch {
            // Editor handles missing initial content; viewer will show the
            // unsupported-state UI below.
          }
        }

        collectionMasterRef.current = collectionKey
        fileKeyRef.current = fileKey
        if (!cancelled) {
          setCollectionMasterReady(true)
          setPhase('ready')
        }
      } catch (err: any) {
        if (cancelled) return
        setError(err?.response?.data?.error ?? err?.message ?? 'Failed to load file')
        setPhase('error')
      }
    })()

    return () => {
      cancelled = true
      if (createdUrl) URL.revokeObjectURL(createdUrl)
    }
  }, [cid, fid, masterKey, privateKey, userId, publicKey, navigate])

  async function handleColorChange(hex: string) {
    const previous = userColor
    dispatch(setColor(hex))
    broadcastColor(hex)
    try {
      await api.patch('/user/me', { color: hex })
    } catch (err: any) {
      dispatch(setColor(previous))
      broadcastColor(previous)
      toast.error(err?.response?.data?.error ?? 'Failed to update color')
    }
  }

  async function handleOfficeSave() {
    if (!fid || !officeEditorRef.current || !fileKeyRef.current) return
    if (savingOffice) return
    setSavingOffice(true)
    const tid = toast.loading('Saving…')
    try {
      // 1. Ask the editor to extract bin → x2t → OOXML.
      const { bytes } = await officeEditorRef.current.save()
      // 2. Encrypt with the file's content key (same scheme as the
      //    original blob upload — see Drive.uploadFile).
      const encrypted = await encryptStream(bytes, fileKeyRef.current)
      // 3. Upload as a new snapshot, then register it as a version.
      const form = new FormData()
      form.append('file', new Blob([encrypted.buffer as ArrayBuffer], { type: 'application/octet-stream' }), 'snapshot')
      const blobRes = await api.post(`/files/${fid}/snapshot-blob`, form)
      await api.post(`/files/${fid}/versions`, {
        s3VersionId: blobRes.data.s3VersionId,
        storagePath: blobRes.data.storagePath,
        seqAtSnapshot: 0,  // Office docs don't use the Yjs delta log.
        docKeyId: 1,
        sizeBytes: encrypted.length,
        keepForever: false,
      })
      toast.success('Saved', { id: tid })
      setJustSavedOffice(true)
      setTimeout(() => setJustSavedOffice(false), 1500)
    } catch (err: any) {
      console.error('office save failed', err)
      toast.error(err?.response?.data?.error ?? err?.message ?? 'Save failed', { id: tid })
    } finally {
      setSavingOffice(false)
    }
  }

  if (phase === 'loading') {
    return (
      <div className="flex min-h-screen items-center justify-center">
        <div className="flex flex-col items-center gap-3 text-sm text-muted-foreground">
          <Loader2 className="h-6 w-6 animate-spin text-primary" />
          <span>Decrypting…</span>
        </div>
      </div>
    )
  }

  // Determine which renderer wins. Office takes precedence for OOXML; editor
  // for text/markdown/code; viewer for static binary content; otherwise we
  // render an unsupported notice.
  const editorReady = !!Editor && collectionMasterReady && !!collectionMasterRef.current
  const officeReady = !!Office && collectionMasterReady && !!collectionMasterRef.current
  const viewerReady = !!viewer && !!blobUrl

  if (phase === 'error' || (!editorReady && !officeReady && !viewerReady)) {
    return (
      <div className="flex min-h-screen items-center justify-center p-6">
        <div className="max-w-md text-center space-y-4">
          <h1 className="text-lg font-semibold">Could not open this file</h1>
          <p className="text-sm text-muted-foreground">
            {error || 'This file type isn\'t previewable yet — download it from the Drive details panel.'}
          </p>
          <Button variant="outline" onClick={() => navigate('/drive')}>
            <ArrowLeft className="h-4 w-4 mr-2" /> Back to Drive
          </Button>
        </div>
      </div>
    )
  }

  return (
    <div className="flex h-screen flex-col overflow-hidden">
      <header className="flex h-12 shrink-0 items-center gap-3 border-b border-border px-4">
        {/* Kutup logo opens Drive in a NEW tab — Google-Docs style: this
            tab IS the document, you exit by closing it. */}
        <a
          href="/drive"
          target="_blank"
          rel="noopener"
          className="flex items-center gap-2 rounded px-1 py-1 hover:bg-accent"
          title="Open Kutup Drive (new tab)"
        >
          <KutupLogo size={22} />
          <span className="text-sm font-semibold tracking-tight">Kutup</span>
        </a>
        <span className="text-sm text-muted-foreground">·</span>
        <span className="text-sm font-medium truncate">{filename}</span>
        {officeReady && (
          <div className="ml-auto flex items-center gap-2">
            <CursorColorPicker color={userColor ?? '#94a3b8'} onChange={handleColorChange} />
            <Button
              type="button"
              size="sm"
              variant="outline"
              disabled={savingOffice}
              onClick={handleOfficeSave}
              className="gap-1.5"
              title="Save as a new version (⌘/Ctrl+S coming in Phase 7)"
            >
              {justSavedOffice
                ? <Check className="h-4 w-4 text-emerald-500" />
                : <Save className="h-4 w-4" />}
              {savingOffice ? 'Saving…' : justSavedOffice ? 'Saved' : 'Save'}
            </Button>
          </div>
        )}
        {viewerReady && blobUrl && (
          <a
            href={blobUrl}
            download={filename}
            className="ml-auto inline-flex items-center gap-1.5 rounded border border-input bg-background px-2.5 py-1 text-xs hover:bg-accent"
          >
            <Download className="h-3.5 w-3.5" /> Download
          </a>
        )}
      </header>
      <div className="flex-1 min-h-0">
        <Suspense fallback={<div className="p-4 text-sm text-muted-foreground">Loading…</div>}>
          {editorReady && Editor && (
            <Editor
              fileId={fid!}
              filename={filename}
              collectionMaster={collectionMasterRef.current!}
              initialContent={initialContent}
            />
          )}
          {!editorReady && officeReady && Office && (
            <Office
              ref={officeEditorRef}
              fileId={fid!}
              filename={filename}
              collectionMaster={collectionMasterRef.current!}
              initialBytes={officeBytes ?? undefined}
            />
          )}
          {!editorReady && !officeReady && viewerReady && viewer && blobUrl && (
            <viewer.Component
              filename={filename}
              blobUrl={blobUrl}
              mimeType={viewer.mimeType}
            />
          )}
        </Suspense>
      </div>
    </div>
  )
}
