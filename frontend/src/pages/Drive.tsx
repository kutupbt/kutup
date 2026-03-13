import { useState, useEffect, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAppSelector, useAppDispatch } from '../store'
import { selectMasterKey, selectPrivateKey, selectIsLoggedIn, logout, updateStorageUsed, updateStorageQuota } from '../store/authSlice'
import api from '../api/client'
import {
  encrypt, decrypt, generateKey, encryptStream, decryptStream,
  wrapKeyForRecipient, unwrapKeyFromSender,
  toBase64, fromBase64,
} from '../crypto'

interface Collection {
  id: string
  ownerUserId: string
  encryptedName: string
  nameNonce: string
  encryptedKey: string
  encryptedKeyNonce: string
  parentCollectionId?: string
  color?: string
  decryptedName?: string
  collectionKey?: Uint8Array
}

const FOLDER_COLORS = [
  { label: 'Purple', value: 'purple', hex: '#7c3aed' },
  { label: 'Blue',   value: 'blue',   hex: '#3b82f6' },
  { label: 'Green',  value: 'green',  hex: '#10b981' },
  { label: 'Amber',  value: 'amber',  hex: '#f59e0b' },
  { label: 'Red',    value: 'red',    hex: '#ef4444' },
]
const DEFAULT_FOLDER_COLOR = '#6366f1'

function folderHex(color?: string) {
  return FOLDER_COLORS.find(c => c.value === color)?.hex ?? DEFAULT_FOLDER_COLOR
}

function FolderIcon({ color, size = 48 }: { color?: string; size?: number }) {
  const fill = folderHex(color)
  return (
    <svg width={size} height={size * 0.8} viewBox="0 0 48 38" fill="none">
      <path d="M2 10 C2 8.9 2.9 8 4 8 L20 8 L23 4 H44 C45.1 4 46 4.9 46 6 V10 Z" fill={fill} />
      <rect x="2" y="10" width="44" height="24" rx="3" fill={fill} opacity="0.85" />
    </svg>
  )
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
}

interface FileMetadata {
  name: string
  mimeType: string
  size: number
}

export default function Drive() {
  const navigate = useNavigate()
  const dispatch = useAppDispatch()
  const isLoggedIn = useAppSelector(selectIsLoggedIn)
  const masterKey = useAppSelector(selectMasterKey)
  const privateKey = useAppSelector(selectPrivateKey)
  const auth = useAppSelector((s) => s.auth)

  const [collections, setCollections] = useState<Collection[]>([])
  const [currentFolder, setCurrentFolder] = useState<Collection | null>(null)
  const [navigationStack, setNavigationStack] = useState<Collection[]>([])
  const [files, setFiles] = useState<FileItem[]>([])
  const [newFolderName, setNewFolderName] = useState('')
  const [uploading, setUploading] = useState(false)
  const [uploadState, setUploadState] = useState<{
    active: boolean
    currentFile: number
    totalFiles: number
    filePercent: number
    overallPercent: number
    speedBps: number
  } | null>(null)
  const [shareEmail, setShareEmail] = useState('')
  const [shareModal, setShareModal] = useState<Collection | null>(null)
  const [error, setError] = useState('')
  const [showNewFolderModal, setShowNewFolderModal] = useState(false)
  const [isDragging, setIsDragging] = useState(false)
  const [contextMenu, setContextMenu] = useState<{ x: number; y: number } | null>(null)
  const [folderContextTarget, setFolderContextTarget] = useState<Collection | null>(null)
  const [dragOverFolder, setDragOverFolder] = useState<string | null>(null)
  const [showFabMenu, setShowFabMenu] = useState(false)
  const [myFilesCollection, setMyFilesCollection] = useState<Collection | null>(null)
  const [viewMode, setViewMode] = useState<'myfiles' | 'shared'>('myfiles')
  const [hoveredFolder, setHoveredFolder] = useState<string | null>(null)
  const [renameFolderTarget, setRenameFolderTarget] = useState<Collection | null>(null)
  const [renameValue, setRenameValue] = useState('')
  const fileInputRef = useRef<HTMLInputElement>(null)
  const contextMenuRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (!isLoggedIn) navigate('/login')
  }, [isLoggedIn])

  useEffect(() => {
    if (masterKey) loadCollections()
  }, [masterKey])

  useEffect(() => {
    if (currentFolder?.collectionKey) loadFiles(currentFolder)
  }, [currentFolder])

  // Auto-navigate to My Files on first load
  useEffect(() => {
    if (myFilesCollection && !currentFolder) {
      setCurrentFolder(myFilesCollection)
      setNavigationStack([])
    }
  }, [myFilesCollection])

  // Close context menu on outside click
  useEffect(() => {
    function handleMouseDown(e: MouseEvent) {
      if (contextMenuRef.current && !contextMenuRef.current.contains(e.target as Node)) {
        setContextMenu(null)
      }
    }
    document.addEventListener('mousedown', handleMouseDown)
    return () => document.removeEventListener('mousedown', handleMouseDown)
  }, [])

  async function autoCreateMyFiles(): Promise<Collection> {
    const collectionKey = await generateKey()
    const encKey = await encrypt(collectionKey, masterKey!)
    const nameBytes = new TextEncoder().encode('My Files')
    const encName = await encrypt(nameBytes, collectionKey)
    const res = await api.post('/collections/', {
      encryptedName: toBase64(encName.ciphertext),
      nameNonce: toBase64(encName.nonce),
      encryptedKey: toBase64(encKey.ciphertext),
      encryptedKeyNonce: toBase64(encKey.nonce),
      parentCollectionId: null,
    })
    return {
      id: res.data.id,
      ownerUserId: auth.userId!,
      encryptedName: toBase64(encName.ciphertext),
      nameNonce: toBase64(encName.nonce),
      encryptedKey: toBase64(encKey.ciphertext),
      encryptedKeyNonce: toBase64(encKey.nonce),
      parentCollectionId: undefined,
      decryptedName: 'My Files',
      collectionKey,
    }
  }

  async function loadCollections() {
    if (!masterKey) return
    try {
      const meRes = await api.get('/user/me')
      if (meRes.status === 404) { dispatch(logout()); navigate('/login'); return }
      dispatch(updateStorageUsed(meRes.data.storageUsedBytes))
      dispatch(updateStorageQuota(meRes.data.storageQuotaBytes))
      const res = await api.get('/collections/')
      const decrypted = await Promise.all(
        res.data.map(async (col: Collection) => {
          try {
            let collectionKey: Uint8Array
            if (col.ownerUserId !== auth.userId) {
              collectionKey = await unwrapKeyFromSender(
                fromBase64(col.encryptedKey),
                fromBase64(auth.publicKey!),
                privateKey!,
              )
            } else {
              collectionKey = await decrypt(
                fromBase64(col.encryptedKey),
                fromBase64(col.encryptedKeyNonce),
                masterKey,
              )
            }
            const nameBytes = await decrypt(
              fromBase64(col.encryptedName),
              fromBase64(col.nameNonce),
              collectionKey,
            )
            const decryptedName = new TextDecoder().decode(nameBytes)
            return { ...col, decryptedName, collectionKey }
          } catch {
            return { ...col, decryptedName: '[encrypted]' }
          }
        }),
      )
      setCollections(decrypted)

      const myFiles = decrypted.find(
        (c: Collection) => !c.parentCollectionId && c.ownerUserId === auth.userId && c.decryptedName === 'My Files'
      )
      if (myFiles) {
        setMyFilesCollection(myFiles)
      } else {
        const created = await autoCreateMyFiles()
        setMyFilesCollection(created)
        setCollections(prev => [...prev, created])
      }
    } catch (err) {
      setError('Failed to load collections')
    }
  }

  async function loadFiles(collection: Collection) {
    if (!collection.collectionKey) return
    try {
      const res = await api.get(`/collections/${collection.id}/files`)
      const decrypted = await Promise.all(
        res.data.map(async (file: FileItem) => {
          try {
            const fileKey = await decrypt(
              fromBase64(file.encryptedFileKey),
              fromBase64(file.fileKeyNonce),
              collection.collectionKey!,
            )
            const metaBytes = await decrypt(
              fromBase64(file.encryptedMetadata),
              fromBase64(file.metadataNonce),
              fileKey,
            )
            const meta: FileMetadata = JSON.parse(new TextDecoder().decode(metaBytes))
            return {
              ...file,
              decryptedName: meta.name,
              decryptedMimeType: meta.mimeType,
              decryptedSize: meta.size,
              _fileKey: fileKey,
            }
          } catch {
            return { ...file, decryptedName: '[encrypted]' }
          }
        }),
      )
      setFiles(decrypted)
    } catch (err) {
      setError('Failed to load files')
    }
  }

  function enterFolder(col: Collection) {
    setNavigationStack(prev => currentFolder ? [...prev, currentFolder] : prev)
    setCurrentFolder(col)
    setFiles([])
  }

  function goHome() {
    setCurrentFolder(myFilesCollection)
    setNavigationStack([])
    setFiles([])
    setViewMode('myfiles')
  }

  function goToShared() {
    setCurrentFolder(null)
    setNavigationStack([])
    setFiles([])
    setViewMode('shared')
  }

  function navigateTo(index: number) {
    if (index === -1) {
      goHome()
    } else {
      const target = navigationStack[index]
      setNavigationStack(prev => prev.slice(0, index))
      setCurrentFolder(target)
      setFiles([])
    }
  }

  async function createFolderFromModal() {
    if (!masterKey || !newFolderName.trim()) return
    try {
      const collectionKey = await generateKey()
      const encKey = await encrypt(collectionKey, masterKey)
      const nameBytes = new TextEncoder().encode(newFolderName.trim())
      const encName = await encrypt(nameBytes, collectionKey)

      await api.post('/collections/', {
        encryptedName: toBase64(encName.ciphertext),
        nameNonce: toBase64(encName.nonce),
        encryptedKey: toBase64(encKey.ciphertext),
        encryptedKeyNonce: toBase64(encKey.nonce),
        parentCollectionId: currentFolder?.id ?? null,
      })

      setNewFolderName('')
      setShowNewFolderModal(false)
      await loadCollections()
    } catch (err: any) {
      setError(err.response?.data?.error || 'Failed to create folder')
    }
  }

  async function handleDeleteFolder(col: Collection) {
    if (!confirm(`Delete folder "${col.decryptedName || 'this folder'}"?`)) return
    try {
      await api.delete(`/collections/${col.id}`)
      await loadCollections()
      if (currentFolder?.id === col.id) {
        navigateTo(-1)
      }
    } catch {
      setError('Failed to delete folder')
    }
  }

  async function uploadFile(
    file: File,
    collection: Collection,
    onProgress?: (loaded: number, total: number) => void,
  ): Promise<void> {
    const fileKey = await generateKey()
    const buffer = await file.arrayBuffer()
    const plaintext = new Uint8Array(buffer)
    const encryptedData = await encryptStream(plaintext, fileKey)

    const meta: FileMetadata = { name: file.name, mimeType: file.type || 'application/octet-stream', size: file.size }
    const metaBytes = new TextEncoder().encode(JSON.stringify(meta))
    const encMeta = await encrypt(metaBytes, fileKey)
    const encFileKey = await encrypt(fileKey, collection.collectionKey!)

    const form = new FormData()
    form.append('collectionId', collection.id)
    form.append('encryptedMetadata', toBase64(encMeta.ciphertext))
    form.append('metadataNonce', toBase64(encMeta.nonce))
    form.append('encryptedFileKey', toBase64(encFileKey.ciphertext))
    form.append('fileKeyNonce', toBase64(encFileKey.nonce))
    form.append('file', new Blob([encryptedData.buffer as ArrayBuffer], { type: 'application/octet-stream' }), 'encrypted')

    await api.post('/files/upload', form, {
      onUploadProgress: (e) => {
        if (e.total && onProgress) onProgress(e.loaded, e.total)
      },
    })
  }

  async function uploadFiles(files: File[], targetFolder?: Collection) {
    const folder = targetFolder ?? currentFolder
    if (!folder?.collectionKey) return
    setUploading(true)

    let speedSample = { time: Date.now(), loaded: 0 }
    let speedBps = 0

    try {
      for (let i = 0; i < files.length; i++) {
        setUploadState({
          active: true,
          currentFile: i + 1,
          totalFiles: files.length,
          filePercent: 0,
          overallPercent: Math.round((i / files.length) * 100),
          speedBps: 0,
        })

        await uploadFile(files[i], folder, (loaded, total) => {
          const now = Date.now()
          const dt = (now - speedSample.time) / 1000
          const db = loaded - speedSample.loaded
          if (dt > 0.5) {
            speedBps = Math.round(db / dt)
            speedSample = { time: now, loaded }
          }
          const filePercent = Math.round((loaded / total) * 100)
          const overallPercent = Math.round(((i + filePercent / 100) / files.length) * 100)
          setUploadState({
            active: true,
            currentFile: i + 1,
            totalFiles: files.length,
            filePercent,
            overallPercent,
            speedBps,
          })
        })
      }
    } catch (err: any) {
      setError(err.response?.data?.error || 'Upload failed')
    } finally {
      try {
        const meRes = await api.get('/user/me')
        dispatch(updateStorageUsed(meRes.data.storageUsedBytes))
      } catch {}
      setUploading(false)
      setUploadState(null)
      if (folder.id === currentFolder?.id) await loadFiles(folder)
      if (fileInputRef.current) fileInputRef.current.value = ''
    }
  }

  async function handleDrop(e: React.DragEvent) {
    e.preventDefault()
    setIsDragging(false)
    if (!currentFolder?.collectionKey) return
    const droppedFiles = Array.from(e.dataTransfer.files).filter(f => f.size > 0)
    if (droppedFiles.length) await uploadFiles(droppedFiles)
  }

  async function handleDropOnFolder(e: React.DragEvent, col: Collection) {
    e.preventDefault()
    e.stopPropagation()
    setDragOverFolder(null)
    const droppedFiles = Array.from(e.dataTransfer.files).filter(f => f.size > 0)
    if (droppedFiles.length && col.collectionKey) await uploadFiles(droppedFiles, col)
  }

  async function handleDownload(file: FileItem & { _fileKey?: Uint8Array }) {
    if (!file._fileKey) return
    try {
      const res = await api.get(`/files/${file.id}/download`, { responseType: 'arraybuffer' })
      const encryptedData = new Uint8Array(res.data)
      const plaintext = await decryptStream(encryptedData, file._fileKey)
      const blob = new Blob([plaintext.buffer as ArrayBuffer], { type: file.decryptedMimeType || 'application/octet-stream' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = file.decryptedName || 'file'
      a.click()
      URL.revokeObjectURL(url)
    } catch (err) {
      setError('Download failed')
    }
  }

  async function handleDelete(file: FileItem) {
    if (!confirm(`Delete "${file.decryptedName || 'this file'}"?`)) return
    try {
      await api.delete(`/files/${file.id}`)
      setFiles((prev) => prev.filter((f) => f.id !== file.id))
    } catch {
      setError('Delete failed')
    }
  }

  async function handleShare(e: React.FormEvent) {
    e.preventDefault()
    if (!shareModal?.collectionKey || !shareEmail.trim()) return
    try {
      const res = await api.get(`/users/by-email/${encodeURIComponent(shareEmail.trim())}`)
      const recipientPublicKey = fromBase64(res.data.publicKey)
      const sealedKey = await wrapKeyForRecipient(shareModal.collectionKey, recipientPublicKey)
      await api.post(`/collections/${shareModal.id}/share`, {
        recipientUserId: res.data.userId,
        encryptedCollectionKey: toBase64(sealedKey),
        canWrite: false,
      })
      setShareModal(null)
      setShareEmail('')
    } catch (err: any) {
      setError(err.response?.data?.error || 'Share failed')
    }
  }

  async function handleRenameFolder(col: Collection, newName: string) {
    if (!col.collectionKey || !newName.trim()) return
    try {
      const nameBytes = new TextEncoder().encode(newName.trim())
      const encName = await encrypt(nameBytes, col.collectionKey)
      await api.put(`/collections/${col.id}`, {
        encryptedName: toBase64(encName.ciphertext),
        nameNonce: toBase64(encName.nonce),
      })
      setCollections(prev => prev.map(c =>
        c.id === col.id ? { ...c, decryptedName: newName.trim() } : c
      ))
      if (myFilesCollection?.id === col.id) setMyFilesCollection(prev => prev ? { ...prev, decryptedName: newName.trim() } : prev)
      if (currentFolder?.id === col.id) setCurrentFolder(prev => prev ? { ...prev, decryptedName: newName.trim() } : prev)
    } catch {
      setError('Failed to rename folder')
    }
  }

  async function handleColorFolder(col: Collection, colorValue: string | null) {
    try {
      await api.patch(`/collections/${col.id}/color`, { color: colorValue })
      setCollections(prev => prev.map(c =>
        c.id === col.id ? { ...c, color: colorValue ?? undefined } : c
      ))
      if (currentFolder?.id === col.id) setCurrentFolder(prev => prev ? { ...prev, color: colorValue ?? undefined } : prev)
      if (myFilesCollection?.id === col.id) setMyFilesCollection(prev => prev ? { ...prev, color: colorValue ?? undefined } : prev)
    } catch {
      setError('Failed to update folder color')
    }
  }

  async function createPublicLink(collection: Collection) {
    if (!collection.collectionKey) return
    try {
      const linkKey = await generateKey()
      const encCollKey = await encrypt(collection.collectionKey, linkKey)
      const res = await api.post('/share/', {
        shareType: 'collection',
        targetId: collection.id,
        encryptedCollectionKey: toBase64(encCollKey.ciphertext),
        encryptedCollectionKeyNonce: toBase64(encCollKey.nonce),
      })
      const link = `${window.location.origin}/s/${res.data.token}#key=${toBase64(linkKey)}`
      await copyText(link)
      alert(`Link copied to clipboard!\n\nRemember: anyone with this link can access the files.`)
    } catch (err: any) {
      setError(err.response?.data?.error || 'Failed to create link')
    }
  }

  const quotaPercent = auth.storageQuotaBytes > 0
    ? Math.round((auth.storageUsedBytes / auth.storageQuotaBytes) * 100)
    : 0

  const sharedCollections = collections.filter(c => c.ownerUserId !== auth.userId)

  const subFolders = viewMode === 'shared'
    ? (currentFolder
        ? collections.filter(c => c.parentCollectionId === currentFolder.id)
        : sharedCollections)
    : currentFolder
      ? collections.filter(c => c.parentCollectionId === currentFolder.id)
      : []

  return (
    <div style={styles.layout}>
      {/* Sidebar */}
      <aside style={styles.sidebar}>
        <h1 style={styles.logo}>Depo</h1>

        <div style={styles.quota}>
          <div style={styles.quotaLabel}>
            {formatBytes(auth.storageUsedBytes)} / {formatBytes(auth.storageQuotaBytes)}
          </div>
          <div style={styles.quotaBar}>
            <div style={{ ...styles.quotaFill, width: `${Math.min(quotaPercent, 100)}%` }} />
          </div>
        </div>

        <div style={styles.sidenavSection}>
          <button
            style={viewMode === 'myfiles' ? styles.sidenavItemActive : styles.sidenavItem}
            onClick={goHome}
          >
            📁 My Files
          </button>
          <button
            style={viewMode === 'shared' ? styles.sidenavItemActive : styles.sidenavItem}
            onClick={goToShared}
          >
            👥 Shared with me
          </button>
        </div>

        <div style={{ flex: 1 }} />

        {auth.isAdmin && (
          <button style={styles.adminBtn} onClick={() => navigate('/admin')}>
            Admin
          </button>
        )}

        <button style={styles.adminBtn} onClick={() => navigate('/settings')}>
          Settings
        </button>

        <button style={styles.logoutBtn} onClick={() => { dispatch(logout()); navigate('/login') }}>
          Sign out
        </button>
      </aside>

      {/* Main content */}
      <main
        style={styles.main}
        onContextMenu={e => { e.preventDefault(); setFolderContextTarget(null); setContextMenu({ x: e.clientX, y: e.clientY }) }}
        onDragOver={e => { e.preventDefault(); if (currentFolder?.collectionKey) setIsDragging(true) }}
        onDragEnter={e => { e.preventDefault(); if (currentFolder?.collectionKey) setIsDragging(true) }}
        onDragLeave={e => { if (!e.currentTarget.contains(e.relatedTarget as Node)) setIsDragging(false) }}
        onDrop={handleDrop}
      >
        {isDragging && currentFolder && (
          <div style={styles.dropOverlay}>
            <div style={styles.dropOverlayText}>
              Drop to upload to "{currentFolder.decryptedName}"
            </div>
          </div>
        )}

        {error && (
          <div style={styles.errorBanner}>
            {error}
            <button onClick={() => setError('')} style={styles.errorClose}>×</button>
          </div>
        )}

        {/* Hidden file input (multi) */}
        <input
          ref={fileInputRef}
          type="file"
          multiple
          style={{ display: 'none' }}
          onChange={e => uploadFiles(Array.from(e.target.files ?? []))}
        />

        {/* Breadcrumb */}
        <div style={styles.breadcrumb}>
          <button style={styles.breadcrumbItem} onClick={viewMode === 'shared' ? goToShared : goHome}>
            {viewMode === 'shared' ? 'Shared with me' : 'My Files'}
          </button>
          {navigationStack.map((col, i) => (
            <span key={col.id} style={{ display: 'contents' }}>
              <span style={styles.breadcrumbSep}>/</span>
              <button style={styles.breadcrumbItem} onClick={() => navigateTo(i)}>{col.decryptedName}</button>
            </span>
          ))}
          {currentFolder && currentFolder.id !== myFilesCollection?.id && (
            <>
              <span style={styles.breadcrumbSep}>/</span>
              <span style={styles.breadcrumbCurrent}>{currentFolder.decryptedName}</span>
            </>
          )}
        </div>

        {/* Subfolder grid */}
        {subFolders.length > 0 ? (
          <div style={styles.folderGrid}>
            {subFolders.map(col => (
              <div
                key={col.id}
                style={{
                  ...styles.folderCard,
                  ...(dragOverFolder === col.id ? styles.folderCardDragOver : {}),
                  position: 'relative',
                }}
                onClick={() => enterFolder(col)}
                onMouseEnter={() => setHoveredFolder(col.id)}
                onMouseLeave={() => setHoveredFolder(null)}
                onContextMenu={e => {
                  e.preventDefault()
                  e.stopPropagation()
                  setFolderContextTarget(col)
                  setContextMenu({ x: e.clientX, y: e.clientY })
                }}
                onDragOver={e => { e.preventDefault(); e.stopPropagation(); setDragOverFolder(col.id) }}
                onDragEnter={e => { e.preventDefault(); e.stopPropagation(); setDragOverFolder(col.id) }}
                onDragLeave={e => { e.stopPropagation(); setDragOverFolder(null) }}
                onDrop={e => handleDropOnFolder(e, col)}
              >
                {hoveredFolder === col.id && (
                  <button
                    style={styles.folderDots}
                    onClick={e => {
                      e.stopPropagation()
                      setFolderContextTarget(col)
                      const rect = e.currentTarget.getBoundingClientRect()
                      setContextMenu({ x: rect.right, y: rect.bottom })
                    }}
                  >⋮</button>
                )}
                <FolderIcon color={col.color} size={48} />
                <div style={styles.folderCardName}>{col.decryptedName}</div>
              </div>
            ))}
          </div>
        ) : viewMode === 'shared' && !currentFolder ? (
          <div style={styles.empty}>
            <p>No folders have been shared with you yet.</p>
          </div>
        ) : null}

        {/* File table (only when inside a folder) */}
        {currentFolder && (
          <>
            {files.length === 0 ? (
              <div
                style={styles.emptyDropZone}
                onClick={() => !uploading && fileInputRef.current?.click()}
              >
                <div style={styles.emptyDropIcon}>⬆</div>
                <div>Drop files here or <span style={{ color: '#7c3aed', cursor: 'pointer' }}>click to upload</span></div>
              </div>
            ) : (
              <table style={styles.table}>
                <thead>
                  <tr>
                    <th style={styles.th}>Name</th>
                    <th style={styles.th}>Size</th>
                    <th style={styles.th}>Uploaded</th>
                    <th style={styles.th}></th>
                  </tr>
                </thead>
                <tbody>
                  {files.map((file: any) => (
                    <tr key={file.id} style={styles.tr}>
                      <td style={styles.td}>{file.decryptedName || '[encrypted]'}</td>
                      <td style={styles.td}>{file.decryptedSize ? formatBytes(file.decryptedSize) : '—'}</td>
                      <td style={styles.td}>{new Date(file.createdAt).toLocaleDateString()}</td>
                      <td style={styles.td}>
                        <button style={styles.fileBtn} onClick={() => handleDownload(file)}>↓</button>
                        <button style={{ ...styles.fileBtn, color: '#ef4444' }} onClick={() => handleDelete(file)}>×</button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </>
        )}

      </main>

      {/* Context menu */}
      {contextMenu && (
        <div
          ref={contextMenuRef}
          style={{ ...styles.contextMenu, left: contextMenu.x, top: contextMenu.y }}
        >
          <button
            style={styles.contextMenuItem}
            onClick={() => { setShowNewFolderModal(true); setContextMenu(null) }}
          >
            📁 New folder
          </button>
          {currentFolder && (
            <button
              style={styles.contextMenuItem}
              onClick={() => { fileInputRef.current?.click(); setContextMenu(null) }}
            >
              ⬆ Upload files
            </button>
          )}
          {folderContextTarget && (
            <>
              <div style={styles.contextMenuDivider} />
              <button
                style={styles.contextMenuItem}
                onClick={() => {
                  setRenameFolderTarget(folderContextTarget)
                  setRenameValue(folderContextTarget.decryptedName ?? '')
                  setContextMenu(null)
                }}
              >
                ✏ Rename
              </button>
              <div style={styles.contextMenuColorRow}>
                {FOLDER_COLORS.map(fc => (
                  <button
                    key={fc.value}
                    title={fc.label}
                    style={{
                      ...styles.colorSwatch,
                      background: fc.hex,
                      outline: folderContextTarget.color === fc.value ? '2px solid #fff' : 'none',
                    }}
                    onClick={e => { e.stopPropagation(); handleColorFolder(folderContextTarget, fc.value); setContextMenu(null) }}
                  />
                ))}
                <button
                  title="Default"
                  style={{
                    ...styles.colorSwatch,
                    background: DEFAULT_FOLDER_COLOR,
                    outline: !folderContextTarget.color ? '2px solid #fff' : 'none',
                  }}
                  onClick={e => { e.stopPropagation(); handleColorFolder(folderContextTarget, null); setContextMenu(null) }}
                />
              </div>
              <div style={styles.contextMenuDivider} />
              <button
                style={styles.contextMenuItem}
                onClick={() => {
                  const target = folderContextTarget
                  setContextMenu(null)
                  setFolderContextTarget(null)
                  const input = document.createElement('input')
                  input.type = 'file'
                  input.multiple = true
                  input.onchange = e => {
                    const files = Array.from((e.target as HTMLInputElement).files ?? [])
                    if (files.length) uploadFiles(files, target)
                  }
                  input.click()
                }}
              >
                ⬆ Upload here
              </button>
              <button
                style={styles.contextMenuItem}
                onClick={() => { setShareModal(folderContextTarget); setContextMenu(null) }}
              >
                👤 Share
              </button>
              <button
                style={styles.contextMenuItem}
                onClick={() => { createPublicLink(folderContextTarget); setContextMenu(null) }}
              >
                🔗 Copy link
              </button>
              <button
                style={{ ...styles.contextMenuItem, color: '#ef4444' }}
                onClick={() => { handleDeleteFolder(folderContextTarget); setContextMenu(null) }}
              >
                🗑 Delete folder
              </button>
            </>
          )}
        </div>
      )}

      {/* Share modal */}
      {shareModal && (
        <div style={styles.modalOverlay} onClick={() => setShareModal(null)}>
          <div style={styles.modal} onClick={(e) => e.stopPropagation()}>
            <h3 style={styles.modalTitle}>Share "{shareModal.decryptedName}"</h3>
            <form onSubmit={handleShare}>
              <label style={styles.label}>Recipient email</label>
              <input
                type="email"
                value={shareEmail}
                onChange={(e) => setShareEmail(e.target.value)}
                style={styles.input}
                required
                autoFocus
              />
              <div style={{ display: 'flex', gap: 8, marginTop: 16 }}>
                <button type="submit" style={{ ...styles.actionBtn, background: '#7c3aed', flex: 1 }}>
                  Share (read-only)
                </button>
                <button type="button" style={{ ...styles.actionBtn, flex: 1 }} onClick={() => setShareModal(null)}>
                  Cancel
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* New folder modal */}
      {showNewFolderModal && (
        <div style={styles.modalOverlay} onClick={() => setShowNewFolderModal(false)}>
          <div style={styles.modal} onClick={e => e.stopPropagation()}>
            <h3 style={styles.modalTitle}>New folder</h3>
            <input
              autoFocus
              value={newFolderName}
              onChange={e => setNewFolderName(e.target.value)}
              onKeyDown={e => { if (e.key === 'Enter') createFolderFromModal() }}
              placeholder="Folder name"
              style={styles.input}
            />
            <div style={{ display: 'flex', gap: 8, marginTop: 16 }}>
              <button onClick={createFolderFromModal} style={{ ...styles.actionBtn, background: '#7c3aed', flex: 1 }}>Create</button>
              <button onClick={() => { setShowNewFolderModal(false); setNewFolderName('') }} style={{ ...styles.actionBtn, flex: 1 }}>Cancel</button>
            </div>
          </div>
        </div>
      )}

      {/* Rename folder modal */}
      {renameFolderTarget && (
        <div style={styles.modalOverlay} onClick={() => setRenameFolderTarget(null)}>
          <div style={styles.modal} onClick={e => e.stopPropagation()}>
            <h3 style={styles.modalTitle}>Rename folder</h3>
            <input
              autoFocus
              value={renameValue}
              onChange={e => setRenameValue(e.target.value)}
              onKeyDown={e => {
                if (e.key === 'Enter') {
                  handleRenameFolder(renameFolderTarget, renameValue)
                  setRenameFolderTarget(null)
                }
              }}
              style={styles.input}
            />
            <div style={{ display: 'flex', gap: 8, marginTop: 16 }}>
              <button
                onClick={() => { handleRenameFolder(renameFolderTarget, renameValue); setRenameFolderTarget(null) }}
                style={{ ...styles.actionBtn, background: '#7c3aed', flex: 1 }}
              >Rename</button>
              <button onClick={() => setRenameFolderTarget(null)} style={{ ...styles.actionBtn, flex: 1 }}>Cancel</button>
            </div>
          </div>
        </div>
      )}

      {/* Upload progress panel */}
      {uploadState?.active && (
        <div style={styles.uploadPanel}>
          <div style={styles.uploadPanelTitle}>
            Uploading&nbsp;
            <span style={{ color: '#e8e8ea' }}>{uploadState.currentFile} / {uploadState.totalFiles}</span>
          </div>
          <div style={styles.uploadBarTrack}>
            <div style={{ ...styles.uploadBarFill, width: `${uploadState.overallPercent}%` }} />
          </div>
          <div style={styles.uploadPanelMeta}>
            <span>{uploadState.overallPercent}%</span>
            <span>{formatSpeed(uploadState.speedBps)}</span>
          </div>
        </div>
      )}

      {/* Floating action button */}
      <div style={styles.fab}>
        {showFabMenu && (
          <div style={styles.fabMenu}>
            {(viewMode === 'myfiles' || currentFolder) && (
              <button style={styles.fabMenuItem}
                onClick={() => { fileInputRef.current?.click(); setShowFabMenu(false) }}>
                ⬆ Upload files
              </button>
            )}
            <button
              style={styles.fabMenuItem}
              onClick={() => { setShowNewFolderModal(true); setShowFabMenu(false) }}
            >
              📁 New folder
            </button>
          </div>
        )}
        <button
          style={styles.fabBtn}
          onClick={() => setShowFabMenu(v => !v)}
          title="New"
        >
          {showFabMenu ? '×' : '+'}
        </button>
      </div>
    </div>
  )
}

function copyText(text: string): Promise<void> {
  if (navigator.clipboard && window.isSecureContext) {
    return navigator.clipboard.writeText(text)
  }
  const ta = document.createElement('textarea')
  ta.value = text
  ta.style.cssText = 'position:fixed;opacity:0'
  document.body.appendChild(ta)
  ta.focus(); ta.select()
  document.execCommand('copy')
  document.body.removeChild(ta)
  return Promise.resolve()
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / 1024 / 1024).toFixed(1)} MB`
  return `${(bytes / 1024 / 1024 / 1024).toFixed(2)} GB`
}

function formatSpeed(bps: number): string {
  if (bps <= 0) return ''
  if (bps < 1024) return `${bps} B/s`
  if (bps < 1024 * 1024) return `${(bps / 1024).toFixed(1)} KB/s`
  return `${(bps / 1024 / 1024).toFixed(1)} MB/s`
}

const styles: Record<string, React.CSSProperties> = {
  layout: { display: 'flex', minHeight: '100vh' },
  sidebar: { width: 240, background: '#13131a', borderRight: '1px solid #2a2a30', display: 'flex', flexDirection: 'column', padding: 16, gap: 8 },
  logo: { fontSize: 24, fontWeight: 700, color: '#7c3aed', margin: '0 0 16px', letterSpacing: -1 },
  quota: { marginBottom: 8 },
  quotaLabel: { fontSize: 11, color: '#8888aa', marginBottom: 4 },
  quotaBar: { height: 4, background: '#2a2a30', borderRadius: 4, overflow: 'hidden' },
  quotaFill: { height: '100%', background: '#7c3aed', borderRadius: 4, transition: 'width 0.3s' },
  sidenavSection: { display: 'flex', flexDirection: 'column', gap: 2, marginTop: 8, marginBottom: 8 },
  sidenavItem: { padding: '8px 10px', background: 'transparent', border: 'none', color: '#8888aa', cursor: 'pointer', textAlign: 'left', fontSize: 13, borderRadius: 6, width: '100%' },
  sidenavItemActive: { padding: '8px 10px', background: '#1e1a2e', border: 'none', color: '#c8c8da', cursor: 'pointer', textAlign: 'left', fontSize: 13, borderRadius: 6, width: '100%' },
  adminBtn: { padding: '8px', background: '#1e1e2a', border: '1px solid #2a2a30', color: '#8888aa', borderRadius: 6, cursor: 'pointer', fontSize: 12 },
  logoutBtn: { padding: '8px', background: 'transparent', border: '1px solid #2a2a30', color: '#8888aa', borderRadius: 6, cursor: 'pointer', fontSize: 12 },
  main: { flex: 1, padding: 32, overflow: 'auto', position: 'relative' },
  breadcrumb: { display: 'flex', alignItems: 'center', gap: 4, marginBottom: 16, fontSize: 13, color: '#8888aa' },
  breadcrumbItem: { background: 'transparent', border: 'none', color: '#8888aa', cursor: 'pointer', padding: '2px 4px', borderRadius: 4 },
  breadcrumbCurrent: { color: '#e8e8ea', fontWeight: 500, padding: '2px 4px' },
  breadcrumbSep: { color: '#2a2a30' },
  folderGrid: { display: 'flex', flexWrap: 'wrap', gap: 12, marginBottom: 24 },
  folderCard: { width: 120, padding: '16px 12px', background: '#1a1a1f', border: '1px solid #2a2a30', borderRadius: 10, cursor: 'pointer', textAlign: 'center', userSelect: 'none' },
  folderCardDragOver: { border: '1px solid #7c3aed', background: '#1e1a2e' },
  folderCardName: { fontSize: 12, color: '#c8c8da', wordBreak: 'break-word', marginTop: 8 },
  folderDots: { position: 'absolute', top: 4, right: 4, background: 'rgba(0,0,0,0.4)', border: 'none', color: '#fff', borderRadius: 4, width: 22, height: 22, cursor: 'pointer', fontSize: 14, display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 10 } as React.CSSProperties,
  contextMenuColorRow: { display: 'flex', gap: 6, padding: '6px 14px', alignItems: 'center' },
  colorSwatch: { width: 20, height: 20, borderRadius: '50%', border: 'none', cursor: 'pointer', padding: 0, outlineOffset: 2 },
  contextMenu: { position: 'fixed', background: '#1a1a1f', border: '1px solid #2a2a30', borderRadius: 8, zIndex: 300, minWidth: 180, padding: '4px 0', boxShadow: '0 8px 24px rgba(0,0,0,0.4)' },
  contextMenuItem: { width: '100%', padding: '8px 14px', background: 'transparent', border: 'none', color: '#c8c8da', cursor: 'pointer', textAlign: 'left', fontSize: 13, display: 'block' },
  contextMenuDivider: { height: 1, background: '#2a2a30', margin: '4px 0' },
  actionBtn: { padding: '8px 14px', background: '#1e1e2a', border: '1px solid #2a2a30', color: '#e8e8ea', borderRadius: 6, cursor: 'pointer', fontSize: 13 },
  table: { width: '100%', borderCollapse: 'collapse' },
  th: { padding: '8px 12px', textAlign: 'left', fontSize: 12, color: '#8888aa', borderBottom: '1px solid #2a2a30', fontWeight: 500 },
  tr: { borderBottom: '1px solid #1e1e2a' },
  td: { padding: '10px 12px', fontSize: 13, color: '#c8c8da' },
  fileBtn: { padding: '4px 10px', background: 'transparent', border: '1px solid #2a2a30', color: '#8888aa', borderRadius: 4, cursor: 'pointer', fontSize: 14, marginRight: 4 },
  empty: { display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', height: '60vh', color: '#8888aa' },
  emptyDropZone: { border: '2px dashed #2a2a30', borderRadius: 12, padding: '60px 20px', textAlign: 'center', color: '#8888aa', cursor: 'pointer', fontSize: 14, marginTop: 24 },
  emptyDropIcon: { fontSize: 32, marginBottom: 12, color: '#7c3aed' },
  dropOverlay: { position: 'fixed', inset: 0, zIndex: 200, background: 'rgba(124,58,237,0.15)', border: '2px dashed #7c3aed', pointerEvents: 'none', display: 'flex', alignItems: 'center', justifyContent: 'center' },
  dropOverlayText: { fontSize: 24, fontWeight: 600, color: '#fff' },
  errorBanner: { background: '#2d1a1a', border: '1px solid #ef444440', borderRadius: 8, padding: '12px 16px', marginBottom: 16, color: '#ef4444', fontSize: 13, display: 'flex', justifyContent: 'space-between', alignItems: 'center' },
  errorClose: { background: 'transparent', border: 'none', color: '#ef4444', cursor: 'pointer', fontSize: 18, padding: 0 },
  modalOverlay: { position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.7)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 100 },
  modal: { background: '#1a1a1f', border: '1px solid #2a2a30', borderRadius: 12, padding: 32, width: '100%', maxWidth: 400 },
  modalTitle: { margin: '0 0 20px', fontSize: 18, fontWeight: 600 },
  label: { display: 'block', marginBottom: 6, fontSize: 13, color: '#8888aa', fontWeight: 500 },
  input: { width: '100%', padding: '10px 12px', background: '#0f0f11', border: '1px solid #2a2a30', borderRadius: 8, color: '#e8e8ea', fontSize: 14, outline: 'none', boxSizing: 'border-box' },
  uploadPanel: { position: 'fixed', bottom: 104, right: 32, width: 240, background: '#1a1a1f', border: '1px solid #2a2a30', borderRadius: 10, padding: '12px 14px', zIndex: 210, boxShadow: '0 8px 24px rgba(0,0,0,0.5)' },
  uploadPanelTitle: { fontSize: 12, color: '#8888aa', marginBottom: 8 },
  uploadBarTrack: { height: 4, background: '#2a2a30', borderRadius: 4, overflow: 'hidden', marginBottom: 6 },
  uploadBarFill: { height: '100%', background: '#7c3aed', borderRadius: 4, transition: 'width 0.2s' },
  uploadPanelMeta: { display: 'flex', justifyContent: 'space-between', fontSize: 11, color: '#8888aa' },
  fab: { position: 'fixed', bottom: 32, right: 32, display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: 8, zIndex: 200 },
  fabBtn: { width: 56, height: 56, borderRadius: '50%', background: '#7c3aed', border: 'none', color: '#fff', fontSize: 28, cursor: 'pointer', boxShadow: '0 4px 16px rgba(124,58,237,0.5)', display: 'flex', alignItems: 'center', justifyContent: 'center', lineHeight: 1 },
  fabMenu: { display: 'flex', flexDirection: 'column', gap: 4, background: '#1a1a1f', border: '1px solid #2a2a30', borderRadius: 8, padding: '4px 0', boxShadow: '0 8px 24px rgba(0,0,0,0.4)', minWidth: 160 },
  fabMenuItem: { padding: '10px 16px', background: 'transparent', border: 'none', color: '#c8c8da', cursor: 'pointer', textAlign: 'left', fontSize: 13, whiteSpace: 'nowrap' },
}
