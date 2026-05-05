import { useEffect, useMemo, useRef, useState, Suspense } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import { Loader2, ArrowLeft } from 'lucide-react'
import { useAppSelector } from '@/store'
import { selectMasterKey, selectPrivateKey } from '@/store/authSlice'
import api from '@/api/client'
import {
  decrypt,
  decryptStream,
  fromBase64,
  unwrapKeyFromSender,
} from '@/crypto'
import { chooseEditor } from '@/components/editors/dispatch'
import { Button } from '@/components/ui/button'

interface FileMetadata {
  name: string
  mimeType: string
  size: number
}

export default function FileEditorPage() {
  const { cid, fid } = useParams<{ cid: string; fid: string }>()
  const navigate = useNavigate()
  const masterKey = useAppSelector(selectMasterKey)
  const privateKey = useAppSelector(selectPrivateKey)
  const userId = useAppSelector((s) => s.auth.userId)
  const publicKey = useAppSelector((s) => s.auth.publicKey)

  const [phase, setPhase] = useState<'loading' | 'ready' | 'error'>('loading')
  const [error, setError] = useState('')
  const [filename, setFilename] = useState('')
  const [initialContent, setInitialContent] = useState<string | undefined>(undefined)
  // Stable Uint8Array reference for the editor — recreating it would cause
  // TextCollabEditor to tear down its provider on every parent render.
  const collectionMasterRef = useRef<Uint8Array | null>(null)
  const [collectionMasterReady, setCollectionMasterReady] = useState(false)

  useEffect(() => {
    if (!cid || !fid) return
    if (!masterKey || !privateKey || !userId) {
      const next = encodeURIComponent(`/file/${cid}/${fid}`)
      navigate(`/login?next=${next}`, { replace: true })
      return
    }

    let cancelled = false

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

        // Pre-fetch + decrypt original plaintext for the editor's cold-start
        // seed. If a Yjs snapshot already exists, the editor ignores this.
        try {
          const dlRes = await api.get(`/files/${fid}/download`, { responseType: 'arraybuffer' })
          if (cancelled) return
          const plain = await decryptStream(new Uint8Array(dlRes.data), fileKey)
          setInitialContent(new TextDecoder().decode(plain))
        } catch {
          // Editor handles missing initial content.
        }

        collectionMasterRef.current = collectionKey
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

    return () => { cancelled = true }
  }, [cid, fid, masterKey, privateKey, userId, publicKey, navigate])

  const Editor = useMemo(() => (filename ? chooseEditor(filename) : null), [filename])

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

  if (phase === 'error' || !Editor || !collectionMasterReady || !collectionMasterRef.current) {
    return (
      <div className="flex min-h-screen items-center justify-center p-6">
        <div className="max-w-md text-center space-y-4">
          <h1 className="text-lg font-semibold">Could not open this file</h1>
          <p className="text-sm text-muted-foreground">
            {error || (Editor ? 'Editor failed to mount.' : 'This file type is not supported in the collaborative editor yet.')}
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
        <Button variant="ghost" size="icon" onClick={() => navigate('/drive')} aria-label="Back to Drive">
          <ArrowLeft className="h-4 w-4" />
        </Button>
        <span className="text-sm font-medium truncate">{filename}</span>
      </header>
      <div className="flex-1 min-h-0">
        <Suspense fallback={<div className="p-4 text-sm text-muted-foreground">Loading editor…</div>}>
          <Editor
            fileId={fid!}
            filename={filename}
            collectionMaster={collectionMasterRef.current!}
            initialContent={initialContent}
          />
        </Suspense>
      </div>
    </div>
  )
}
