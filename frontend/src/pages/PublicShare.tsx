// Public share viewer — no auth required.
// The linkKey lives ONLY in the URL #fragment (never sent to server).
import { useState, useEffect } from 'react'
import { useParams } from 'react-router-dom'
import { Download, Lock, Loader2, FileText } from 'lucide-react'
import api from '@/api/client'
import { decrypt, decryptStream, fromBase64 } from '@/crypto'
import { KutupLogo } from '@/components/KutupLogo'
import { formatBytes } from '@/lib/format'
import { Button } from '@/components/ui/button'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'
import { Badge } from '@/components/ui/badge'

interface DecryptedFile {
  id: string
  collectionId: string
  encryptedMetadata: string
  metadataNonce: string
  encryptedFileKey: string
  fileKeyNonce: string
  encryptedSizeBytes: number
  createdAt: string
  decryptedName?: string
  decryptedMimeType?: string
  decryptedSize?: number
  _fileKey?: Uint8Array
}

type State = 'loading' | 'ready' | 'error' | 'expired'

export default function PublicShare() {
  const { token } = useParams<{ token: string }>()
  const [state, setState] = useState<State>('loading')
  const [error, setError] = useState('')
  const [files, setFiles] = useState<DecryptedFile[]>([])
  const [downloading, setDownloading] = useState<string | null>(null)

  useEffect(() => {
    if (token) loadShare()
  }, [token])

  async function loadShare() {
    const fragment = window.location.hash.slice(1)
    const params = new URLSearchParams(fragment)
    const linkKeyB64 = params.get('key')

    if (!linkKeyB64) {
      setError('Missing decryption key — the URL may be incomplete. The key must be in the #fragment.')
      setState('error')
      return
    }

    try {
      const linkKey = fromBase64(linkKeyB64)
      const shareRes = await api.get(`/share/${token}`)
      const share = shareRes.data

      if (share.expiresAt && new Date() > new Date(share.expiresAt)) {
        setState('expired')
        return
      }

      const collKey = await decrypt(
        fromBase64(share.encryptedCollectionKey),
        fromBase64(share.encryptedCollectionKeyNonce),
        linkKey,
      )

      const filesRes = await api.get(`/share/${token}/files`)
      const decrypted: DecryptedFile[] = await Promise.all(
        filesRes.data.map(async (file: DecryptedFile) => {
          try {
            const fileKey = await decrypt(fromBase64(file.encryptedFileKey), fromBase64(file.fileKeyNonce), collKey)
            const metaBytes = await decrypt(fromBase64(file.encryptedMetadata), fromBase64(file.metadataNonce), fileKey)
            const meta = JSON.parse(new TextDecoder().decode(metaBytes))
            return { ...file, decryptedName: meta.name, decryptedMimeType: meta.mimeType, decryptedSize: meta.size, _fileKey: fileKey }
          } catch {
            return { ...file, decryptedName: '[could not decrypt]' }
          }
        }),
      )

      setFiles(decrypted)
      setState('ready')
    } catch (err: any) {
      if (err.response?.status === 410) setState('expired')
      else if (err.response?.status === 404) { setError('Share not found'); setState('error') }
      else { setError(err.message ?? 'Failed to load share'); setState('error') }
    }
  }

  async function handleDownload(file: DecryptedFile) {
    if (!file._fileKey) return
    setDownloading(file.id)
    try {
      const res = await api.get(`/share/${token}/download/${file.id}`)
      const encRes = await fetch(res.data.url)
      const encData = new Uint8Array(await encRes.arrayBuffer())
      const plaintext = await decryptStream(encData, file._fileKey)
      const blob = new Blob([plaintext.buffer as ArrayBuffer], { type: file.decryptedMimeType ?? 'application/octet-stream' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = file.decryptedName ?? 'file'
      a.click()
      URL.revokeObjectURL(url)
    } catch {
      setError('Download failed')
    } finally {
      setDownloading(null)
    }
  }

  if (state === 'loading') {
    return (
      <div className="flex min-h-screen flex-col items-center justify-center gap-3">
        <Loader2 className="h-8 w-8 animate-spin text-primary" />
        <p className="text-sm text-muted-foreground">Decrypting…</p>
      </div>
    )
  }

  if (state === 'expired') {
    return (
      <div className="flex min-h-screen items-center justify-center p-4">
        <Card className="w-full max-w-sm text-center">
          <CardHeader><CardTitle>Link expired</CardTitle></CardHeader>
          <CardContent>
            <p className="text-sm text-muted-foreground">This share link is no longer valid.</p>
          </CardContent>
        </Card>
      </div>
    )
  }

  if (state === 'error') {
    return (
      <div className="flex min-h-screen items-center justify-center p-4">
        <Card className="w-full max-w-sm text-center">
          <CardHeader><CardTitle>Cannot access share</CardTitle></CardHeader>
          <CardContent>
            <p className="text-sm text-muted-foreground">{error}</p>
          </CardContent>
        </Card>
      </div>
    )
  }

  return (
    <div className="max-w-3xl mx-auto p-8">
      <div className="flex items-center gap-3 mb-2">
        <KutupLogo size={26} />
        <span className="text-2xl font-bold text-primary tracking-tight">Kutup</span>
      </div>
      <Badge variant="outline" className="border-green-500/50 text-green-400 mb-6 flex items-center gap-1.5 w-fit">
        <Lock className="h-3 w-3" />
        End-to-end encrypted — decrypted in your browser
      </Badge>

      {error && (
        <Alert variant="destructive" className="mb-4">
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}

      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Name</TableHead>
            <TableHead className="w-24">Size</TableHead>
            <TableHead className="w-32">Date</TableHead>
            <TableHead className="w-28" />
          </TableRow>
        </TableHeader>
        <TableBody>
          {files.length === 0 ? (
            <TableRow>
              <TableCell colSpan={4} className="text-center text-muted-foreground py-8">
                No files in this share
              </TableCell>
            </TableRow>
          ) : (
            files.map((file) => (
              <TableRow key={file.id}>
                <TableCell>
                  <div className="flex items-center gap-2">
                    <FileText className="h-4 w-4 text-muted-foreground shrink-0" />
                    {file.decryptedName}
                  </div>
                </TableCell>
                <TableCell className="text-muted-foreground">
                  {file.decryptedSize ? formatBytes(file.decryptedSize) : '—'}
                </TableCell>
                <TableCell className="text-muted-foreground">
                  {new Date(file.createdAt).toLocaleDateString()}
                </TableCell>
                <TableCell>
                  <Button
                    size="sm"
                    variant="outline"
                    onClick={() => handleDownload(file)}
                    disabled={downloading === file.id || !file._fileKey}
                  >
                    {downloading === file.id ? (
                      <Loader2 className="h-3.5 w-3.5 animate-spin mr-2" />
                    ) : (
                      <Download className="h-3.5 w-3.5 mr-2" />
                    )}
                    Download
                  </Button>
                </TableCell>
              </TableRow>
            ))
          )}
        </TableBody>
      </Table>
    </div>
  )
}
