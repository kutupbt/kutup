// Public share viewer — no auth required.
// The linkKey lives ONLY in the URL #fragment (never sent to server).
import { useState, useEffect } from 'react'
import { useParams } from 'react-router-dom'
import api from '../api/client'
import { decrypt, decryptStream, fromBase64 } from '../crypto'
import { KutupLogo } from '../components/KutupLogo'

interface ShareData {
  id: string
  shareType: string
  targetId: string
  encryptedCollectionKey: string
  encryptedCollectionKeyNonce: string
  expiresAt?: string
}

interface FileItem {
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

export default function PublicShare() {
  const { token } = useParams<{ token: string }>()
  const [state, setState] = useState<'loading' | 'ready' | 'error' | 'expired'>('loading')
  const [error, setError] = useState('')
  const [files, setFiles] = useState<FileItem[]>([])
  const [collectionKey, setCollectionKey] = useState<Uint8Array | null>(null)

  useEffect(() => {
    if (token) loadShare()
  }, [token])

  async function loadShare() {
    // Extract linkKey from URL #fragment — this is NEVER sent to the server
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

      // Fetch encrypted share data (no auth)
      const shareRes = await api.get(`/share/${token}`)
      const share: ShareData = shareRes.data

      if (share.expiresAt && new Date() > new Date(share.expiresAt)) {
        setState('expired')
        return
      }

      // Decrypt collection key using linkKey (client-side only)
      const collKey = await decrypt(
        fromBase64(share.encryptedCollectionKey),
        fromBase64(share.encryptedCollectionKeyNonce),
        linkKey,
      )
      setCollectionKey(collKey)

      // Fetch files
      const filesRes = await api.get(`/share/${token}/files`)
      const decrypted = await Promise.all(
        filesRes.data.map(async (file: FileItem) => {
          try {
            const fileKey = await decrypt(
              fromBase64(file.encryptedFileKey),
              fromBase64(file.fileKeyNonce),
              collKey,
            )
            const metaBytes = await decrypt(
              fromBase64(file.encryptedMetadata),
              fromBase64(file.metadataNonce),
              fileKey,
            )
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
      if (err.response?.status === 410) {
        setState('expired')
      } else if (err.response?.status === 404) {
        setError('Share not found')
        setState('error')
      } else {
        setError(err.message || 'Failed to load share')
        setState('error')
      }
    }
  }

  async function handleDownload(file: FileItem) {
    if (!file._fileKey) return
    try {
      const res = await api.get(`/share/${token}/download/${file.id}`)
      const encRes = await fetch(res.data.url)
      const encData = new Uint8Array(await encRes.arrayBuffer())
      const plaintext = await decryptStream(encData, file._fileKey)
      const blob = new Blob([plaintext.buffer as ArrayBuffer], { type: file.decryptedMimeType || 'application/octet-stream' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = file.decryptedName || 'file'
      a.click()
      URL.revokeObjectURL(url)
    } catch {
      alert('Download failed')
    }
  }

  if (state === 'loading') return (
    <div style={styles.center}>
      <div style={styles.spinner} />
      <p style={styles.sub}>Decrypting…</p>
    </div>
  )

  if (state === 'expired') return (
    <div style={styles.center}>
      <div style={styles.card}>
        <h2 style={styles.title}>Link expired</h2>
        <p style={styles.sub}>This share link is no longer valid.</p>
      </div>
    </div>
  )

  if (state === 'error') return (
    <div style={styles.center}>
      <div style={styles.card}>
        <h2 style={styles.title}>Cannot access share</h2>
        <p style={styles.sub}>{error}</p>
      </div>
    </div>
  )

  return (
    <div style={styles.container}>
      <div style={styles.header}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 6 }}>
          <KutupLogo size={28} />
          <h1 style={styles.logo}>Kutup</h1>
        </div>
        <p style={styles.badge}>🔒 End-to-end encrypted — decrypted in your browser</p>
      </div>

      <table style={styles.table}>
        <thead>
          <tr>
            <th style={styles.th}>Name</th>
            <th style={styles.th}>Size</th>
            <th style={styles.th}>Date</th>
            <th style={styles.th}></th>
          </tr>
        </thead>
        <tbody>
          {files.length === 0 ? (
            <tr><td colSpan={4} style={styles.emptyCell}>No files in this share</td></tr>
          ) : (
            files.map((file) => (
              <tr key={file.id} style={styles.tr}>
                <td style={styles.td}>{file.decryptedName}</td>
                <td style={styles.td}>{file.decryptedSize ? formatBytes(file.decryptedSize) : '—'}</td>
                <td style={styles.td}>{new Date(file.createdAt).toLocaleDateString()}</td>
                <td style={styles.td}>
                  <button style={styles.dlBtn} onClick={() => handleDownload(file)}>
                    Download
                  </button>
                </td>
              </tr>
            ))
          )}
        </tbody>
      </table>
    </div>
  )
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / 1024 / 1024).toFixed(1)} MB`
  return `${(bytes / 1024 / 1024 / 1024).toFixed(2)} GB`
}

const styles: Record<string, React.CSSProperties> = {
  center: { display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', minHeight: '100vh' },
  container: { maxWidth: 860, margin: '0 auto', padding: 32 },
  header: { marginBottom: 32 },
  logo: { fontSize: 28, fontWeight: 700, color: '#38bdf8', margin: 0, letterSpacing: -1 },
  badge: { fontSize: 13, color: '#22c55e', margin: 0 },
  card: { background: '#0c1a27', border: '1px solid #1a3045', borderRadius: 12, padding: 40, textAlign: 'center' },
  title: { margin: '0 0 12px', fontSize: 20, fontWeight: 600 },
  sub: { color: '#4e7a97', fontSize: 14, margin: 0 },
  spinner: { width: 32, height: 32, border: '3px solid #1a3045', borderTop: '3px solid #0ea5e9', borderRadius: '50%', marginBottom: 16, animation: 'spin 1s linear infinite' },
  table: { width: '100%', borderCollapse: 'collapse' },
  th: { padding: '10px 12px', textAlign: 'left', fontSize: 12, color: '#4e7a97', borderBottom: '1px solid #1a3045', fontWeight: 500 },
  tr: { borderBottom: '1px solid #0c2030' },
  td: { padding: '12px', fontSize: 13, color: '#93c0d8' },
  emptyCell: { padding: '32px', textAlign: 'center', color: '#4e7a97' },
  dlBtn: { padding: '6px 14px', background: '#0ea5e9', color: '#fff', border: 'none', borderRadius: 6, cursor: 'pointer', fontSize: 13 },
}
