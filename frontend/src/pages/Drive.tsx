import { useState, useEffect, useMemo, useRef, Suspense } from 'react'
import { useTranslation } from 'react-i18next'
import { Download, Trash2, X } from 'lucide-react'
import { useAppSelector, useAppDispatch } from '@/store'
import { selectMasterKey, selectPrivateKey, updateStorageUsed, updateStorageQuota } from '@/store/authSlice'
import api from '@/api/client'
import {
  encrypt, decrypt, generateKey, encryptStream, decryptStream,
  wrapKeyForRecipient, unwrapKeyFromSender,
  toBase64, fromBase64,
} from '@/crypto'
import { toast } from 'sonner'
import { formatBytes } from '@/lib/format'
import { copyText } from '@/lib/format'
import { downloadAsZip, FsaRequiredError } from '@/lib/zipDownload'

import Sidebar from '@/components/layout/Sidebar'
import DriveBreadcrumb from '@/components/drive/DriveBreadcrumb'
import DriveTopBar from '@/components/drive/DriveTopBar'
import {
  ContextMenu,
  ContextMenuContent,
  ContextMenuItem,
  ContextMenuSeparator,
  ContextMenuTrigger,
} from '@/components/ui/context-menu'
import { FolderPlus, FileText as FileTextIcon, Upload as UploadIcon, RefreshCw } from 'lucide-react'
import ShortcutsDialog from '@/components/drive/ShortcutsDialog'
import CollectionGrid from '@/components/drive/CollectionGrid'
import FileTable from '@/components/drive/FileTable'
import UploadPanel from '@/components/drive/UploadPanel'
import EmptyState from '@/components/drive/EmptyState'
import DetailsPanel from '@/components/drive/DetailsPanel'
import NewFolderDialog from '@/components/drive/dialogs/NewFolderDialog'
import NewNoteDialog from '@/components/drive/dialogs/NewNoteDialog'
import RenameDialog from '@/components/drive/dialogs/RenameDialog'
import ShareDialog from '@/components/drive/dialogs/ShareDialog'
import PublicShareDialog from '@/components/drive/dialogs/PublicShareDialog'
import AddRemoteShareDialog from '@/components/drive/dialogs/AddRemoteShareDialog'
import { chooseEditor } from '@/components/editors/dispatch'

import { Button } from '@/components/ui/button'
import { Progress } from '@/components/ui/progress'
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '@/components/ui/alert-dialog'
import type { Collection, DecryptedFile, UploadState } from '@/types/drive'

interface FileMetadata { name: string; mimeType: string; size: number }

export default function Drive() {
  const { t } = useTranslation()
  const dispatch = useAppDispatch()
  const masterKey = useAppSelector(selectMasterKey)
  const privateKey = useAppSelector(selectPrivateKey)
  const auth = useAppSelector((s) => s.auth)

  const [collections, setCollections] = useState<Collection[]>([])
  const [currentFolder, setCurrentFolder] = useState<Collection | null>(null)
  const [navigationStack, setNavigationStack] = useState<Collection[]>([])
  const [files, setFiles] = useState<DecryptedFile[]>([])
  const [myFilesCollection, setMyFilesCollection] = useState<Collection | null>(null)
  const [viewMode, setViewMode] = useState<'myfiles' | 'shared'>('myfiles')
  const [uploadState, setUploadState] = useState<UploadState | null>(null)
  const [isDragging, setIsDragging] = useState(false)

  // Details panel
  const [detailItem, setDetailItem] = useState<Collection | DecryptedFile | null>(null)

  // Selection
  const [selectedFileIds, setSelectedFileIds] = useState<Set<string>>(new Set())
  const [selectedFolderIds, setSelectedFolderIds] = useState<Set<string>>(new Set())
  const [batchDeleteOpen, setBatchDeleteOpen] = useState(false)

  // Dialog states
  const [newFolderOpen, setNewFolderOpen] = useState(false)
  const [newNoteOpen, setNewNoteOpen] = useState(false)
  const [shortcutsOpen, setShortcutsOpen] = useState(false)
  const [newMenuOpen, setNewMenuOpen] = useState(false)
  const [searchQuery, setSearchQuery] = useState('')
  const [renameTarget, setRenameTarget] = useState<Collection | null>(null)
  const [shareTarget, setShareTarget] = useState<Collection | null>(null)
  const [publicShareUrl, setPublicShareUrl] = useState<string | null>(null)
  const [addRemoteOpen, setAddRemoteOpen] = useState(false)
  const [deleteFile, setDeleteFile] = useState<DecryptedFile | null>(null)
  const [deleteFolder, setDeleteFolder] = useState<Collection | null>(null)
  const [fedInviteUrl, setFedInviteUrl] = useState<string | null>(null)

  // Collab editor state: when set, opens an in-place modal editor. The collectionMaster
  // here is the file's parent collection key (already-decrypted on collection load),
  // NOT the user's masterKey — the editor derives per-file content keys from it.
  const [editorOpen, setEditorOpen] = useState<{ fileId: string; filename: string; collectionMaster: Uint8Array; initialContent?: string } | null>(null)

  const fileInputRef = useRef<HTMLInputElement>(null)
  const downloadAbortRef = useRef<AbortController | null>(null)
  const searchInputRef = useRef<HTMLInputElement>(null)

  useEffect(() => {
    if (masterKey) loadCollections()
  }, [masterKey])

  useEffect(() => {
    if (myFilesCollection && !currentFolder) {
      setCurrentFolder(myFilesCollection)
    }
  }, [myFilesCollection])

  useEffect(() => {
    if (currentFolder?.collectionKey) loadFiles(currentFolder)
    else setFiles([])
    clearSelection()
  }, [currentFolder?.id])

  function clearSelection() {
    setSelectedFileIds(new Set())
    setSelectedFolderIds(new Set())
  }

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
      parentCollectionId: null,
      color: null,
      decryptedName: 'My Files',
      collectionKey,
    }
  }

  async function loadCollections() {
    if (!masterKey) return
    try {
      const meRes = await api.get('/user/me')
      dispatch(updateStorageUsed(meRes.data.storageUsedBytes))
      dispatch(updateStorageQuota(meRes.data.storageQuotaBytes))

      const res = await api.get('/collections/')
      const decrypted: Collection[] = await Promise.all(
        res.data.map(async (col: Collection) => {
          try {
            let collectionKey: Uint8Array
            if (col.ownerUserId !== auth.userId) {
              collectionKey = await unwrapKeyFromSender(fromBase64(col.encryptedKey), fromBase64(auth.publicKey!), privateKey!)
            } else {
              collectionKey = await decrypt(fromBase64(col.encryptedKey), fromBase64(col.encryptedKeyNonce!), masterKey)
            }
            const nameBytes = await decrypt(fromBase64(col.encryptedName), fromBase64(col.nameNonce), collectionKey)
            return { ...col, decryptedName: new TextDecoder().decode(nameBytes), collectionKey }
          } catch {
            return { ...col, decryptedName: '[encrypted]' }
          }
        }),
      )
      setCollections(decrypted)

      const myFiles = decrypted.find(
        (c) => !c.parentCollectionId && c.ownerUserId === auth.userId && c.decryptedName === 'My Files',
      )
      if (myFiles) {
        setMyFilesCollection(myFiles)
      } else {
        const created = await autoCreateMyFiles()
        setMyFilesCollection(created)
        setCollections((prev) => [...prev, created])
      }

      // Load federated incoming shares
      try {
        const remoteRes = await api.get('/fed-proxy/incoming')
        const remoteDecrypted: Collection[] = (
          await Promise.all(
            remoteRes.data.map(async (share: any) => {
              try {
                const collectionKey = await unwrapKeyFromSender(fromBase64(share.encryptedCollectionKey), fromBase64(auth.publicKey!), privateKey!)
                const nameBytes = await decrypt(fromBase64(share.encryptedName), fromBase64(share.nameNonce), collectionKey)
                return {
                  id: share.id,
                  ownerUserId: '',
                  encryptedName: share.encryptedName,
                  nameNonce: share.nameNonce,
                  encryptedKey: share.encryptedCollectionKey,
                  encryptedKeyNonce: '',
                  parentCollectionId: null,
                  color: null,
                  decryptedName: new TextDecoder().decode(nameBytes),
                  collectionKey,
                  isRemote: true,
                  remoteShareId: share.id,
                  canUpload: share.canUpload,
                  canDelete: share.canDelete,
                  uploadQuotaBytes: share.uploadQuotaBytes ?? null,
                } as Collection
              } catch {
                return null
              }
            }),
          )
        ).filter(Boolean) as Collection[]

        if (remoteDecrypted.length > 0) {
          setCollections((prev) => [...prev.filter((c) => !c.isRemote), ...remoteDecrypted])
        }
      } catch {
        // No remote shares yet
      }
    } catch {
      toast.error(t('drive.toast.loadFailed'))
    }
  }

  async function loadFiles(collection: Collection): Promise<DecryptedFile[]> {
    if (!collection.collectionKey) return []
    try {
      const res = collection.isRemote
        ? await api.get(`/fed-proxy/${collection.remoteShareId}/files`)
        : await api.get(`/collections/${collection.id}/files`)
      const decrypted: DecryptedFile[] = await Promise.all(
        res.data.map(async (file: DecryptedFile) => {
          try {
            const fileKey = await decrypt(fromBase64(file.encryptedFileKey), fromBase64(file.fileKeyNonce), collection.collectionKey!)
            const metaBytes = await decrypt(fromBase64(file.encryptedMetadata), fromBase64(file.metadataNonce), fileKey)
            const meta: FileMetadata = JSON.parse(new TextDecoder().decode(metaBytes))
            return { ...file, decryptedName: meta.name, decryptedMimeType: meta.mimeType, decryptedSize: meta.size, _fileKey: fileKey }
          } catch {
            return { ...file, decryptedName: '[encrypted]' }
          }
        }),
      )
      setFiles(decrypted)
      return decrypted
    } catch {
      toast.error(t('drive.toast.loadFailed'))
      return []
    }
  }

  function enterFolder(col: Collection) {
    if (currentFolder?.id === col.id) return
    if (currentFolder && currentFolder.id !== myFilesCollection?.id) {
      setNavigationStack((prev) => [...prev, currentFolder])
    }
    setCurrentFolder(col)
    setFiles([])
  }

  function goHome() {
    setNavigationStack([])
    setViewMode('myfiles')
    clearSelection()
    // Only swap folder + clear file cache if we're actually navigating away.
    if (currentFolder?.id !== myFilesCollection?.id) {
      setCurrentFolder(myFilesCollection)
      setFiles([])
    }
  }

  function goToShared() {
    setNavigationStack([])
    setViewMode('shared')
    clearSelection()
    if (currentFolder !== null) {
      setCurrentFolder(null)
      setFiles([])
    }
  }

  function navigateTo(index: number) {
    const target = navigationStack[index]
    setNavigationStack((prev) => prev.slice(0, index))
    if (currentFolder?.id !== target?.id) {
      setCurrentFolder(target)
      setFiles([])
    }
  }

  // --- Selection handlers ---

  function toggleFileSelect(id: string) {
    setSelectedFileIds((prev) => {
      const next = new Set(prev)
      next.has(id) ? next.delete(id) : next.add(id)
      return next
    })
  }

  function toggleAllFiles() {
    const allSelected = files.every((f) => selectedFileIds.has(f.id))
    setSelectedFileIds(allSelected ? new Set() : new Set(files.map((f) => f.id)))
  }

  function toggleFolderSelect(id: string) {
    setSelectedFolderIds((prev) => {
      const next = new Set(prev)
      next.has(id) ? next.delete(id) : next.add(id)
      return next
    })
  }

  // --- Batch actions ---

  async function handleBatchDownload() {
    const selected = files.filter((f) => selectedFileIds.has(f.id))
    if (selected.length === 0) return
    toast.info(t('drive.toast.downloading', { count: selected.length }))
    for (const file of selected) {
      await handleDownload(file)
    }
  }

  async function handleFolderDownload(col: Collection) {
    if (!col.collectionKey) return
    const ac = new AbortController()
    downloadAbortRef.current = ac
    const tid = toast.loading(t('drive.toast.zipPreparing'))
    try {
      const res = col.isRemote
        ? await api.get(`/fed-proxy/${col.remoteShareId}/files`, { signal: ac.signal })
        : await api.get(`/collections/${col.id}/files`, { signal: ac.signal })

      const zipFiles = (
        await Promise.all(
          res.data.map(async (f: any) => {
            try {
              const fileKey = await decrypt(fromBase64(f.encryptedFileKey), fromBase64(f.fileKeyNonce), col.collectionKey!)
              const metaBytes = await decrypt(fromBase64(f.encryptedMetadata), fromBase64(f.metadataNonce), fileKey)
              const meta = JSON.parse(new TextDecoder().decode(metaBytes))
              return { id: f.id, name: meta.name, size: meta.size, fileKey, isRemote: col.isRemote, remoteShareId: col.remoteShareId }
            } catch { return null }
          }),
        )
      ).filter(Boolean)

      if (zipFiles.length === 0) { toast.dismiss(tid); return }

      await downloadAsZip(zipFiles as any, col.decryptedName ?? 'folder', (done, total) => {
        toast.loading(t('drive.toast.zipProgress', { done, total }), { id: tid })
      }, ac.signal)
      toast.success(t('drive.toast.zipDone'), { id: tid })
    } catch (err: any) {
      if (err?.name === 'AbortError') { toast.dismiss(tid); return }
      if (err instanceof FsaRequiredError) { toast.error(t('drive.toast.zipNoFsa'), { id: tid }); return }
      toast.error(t('drive.toast.zipFailed'), { id: tid })
    } finally {
      downloadAbortRef.current = null
    }
  }

  async function handleBatchFolderDownload() {
    const selected = collections.filter((c) => selectedFolderIds.has(c.id))
    for (const col of selected) {
      await handleFolderDownload(col)
    }
  }

  async function handleBatchDelete() {
    const fileCount = selectedFileIds.size
    const folderCount = selectedFolderIds.size
    const selectedFiles = files.filter((f) => selectedFileIds.has(f.id))
    const selectedFolders = collections.filter((c) => selectedFolderIds.has(c.id))

    try {
      await Promise.all([
        ...selectedFiles.map((f) => handleDeleteFile(f, true)),
        ...selectedFolders.map((c) => handleDeleteFolder(c, true)),
      ])
      const total = fileCount + folderCount
      toast.success(t('drive.toast.deleted', { count: total }))
    } catch {
      toast.error(t('drive.toast.someFailed'))
    } finally {
      clearSelection()
      setBatchDeleteOpen(false)
      if (currentFolder) await loadFiles(currentFolder)
      await loadCollections()
    }
  }

  // --- File/folder operations ---

  async function uploadFile(file: File, collection: Collection, onProgress?: (loaded: number, total: number) => void) {
    const fileKey = await generateKey()
    const buffer = await file.arrayBuffer()
    const encryptedData = await encryptStream(new Uint8Array(buffer), fileKey)
    const meta: FileMetadata = { name: file.name, mimeType: file.type || 'application/octet-stream', size: file.size }
    const encMeta = await encrypt(new TextEncoder().encode(JSON.stringify(meta)), fileKey)
    const encFileKey = await encrypt(fileKey, collection.collectionKey!)
    const form = new FormData()
    form.append('collectionId', collection.id)
    form.append('encryptedMetadata', toBase64(encMeta.ciphertext))
    form.append('metadataNonce', toBase64(encMeta.nonce))
    form.append('encryptedFileKey', toBase64(encFileKey.ciphertext))
    form.append('fileKeyNonce', toBase64(encFileKey.nonce))
    form.append('file', new Blob([encryptedData.buffer as ArrayBuffer], { type: 'application/octet-stream' }), 'encrypted')
    const uploadUrl = collection.isRemote ? `/fed-proxy/${collection.remoteShareId}/upload` : '/files/upload'
    await api.post(uploadUrl, form, { onUploadProgress: (e) => { if (e.total && onProgress) onProgress(e.loaded, e.total) } })
  }

  async function uploadFiles(filesToUpload: File[], targetFolder?: Collection) {
    const folder = targetFolder ?? currentFolder
    if (!folder?.collectionKey) return
    let speedSample = { time: Date.now(), loaded: 0 }
    let speedBps = 0
    try {
      for (let i = 0; i < filesToUpload.length; i++) {
        setUploadState({ active: true, currentFile: i + 1, totalFiles: filesToUpload.length, filePercent: 0, overallPercent: Math.round((i / filesToUpload.length) * 100), speedBps: 0 })
        await uploadFile(filesToUpload[i], folder, (loaded, total) => {
          const now = Date.now()
          const dt = (now - speedSample.time) / 1000
          const db = loaded - speedSample.loaded
          if (dt > 0.5) { speedBps = Math.round(db / dt); speedSample = { time: now, loaded } }
          const filePercent = Math.round((loaded / total) * 100)
          setUploadState({ active: true, currentFile: i + 1, totalFiles: filesToUpload.length, filePercent, overallPercent: Math.round(((i + filePercent / 100) / filesToUpload.length) * 100), speedBps })
        })
      }
      toast.success(t('drive.toast.uploaded', { count: filesToUpload.length }))
    } catch (err: any) {
      toast.error(err.response?.data?.error ?? t('drive.toast.uploadFailed'))
    } finally {
      try { const meRes = await api.get('/user/me'); dispatch(updateStorageUsed(meRes.data.storageUsedBytes)) } catch {}
      setUploadState(null)
      if (folder.id === currentFolder?.id) await loadFiles(folder)
      if (fileInputRef.current) fileInputRef.current.value = ''
    }
  }

  async function handleFileClick(file: DecryptedFile) {
    const name = file.decryptedName
    if (name && currentFolder?.collectionKey && chooseEditor(name) && file._fileKey) {
      // Pre-fetch + decrypt the file's original plaintext so the editor can seed
      // Y.Text on cold-start (no Yjs snapshot yet). Once a snapshot exists, the
      // editor uses that instead and ignores initialContent.
      let initialContent: string | undefined
      try {
        const downloadUrl = currentFolder.isRemote
          ? `/fed-proxy/${currentFolder.remoteShareId}/files/${file.id}/download`
          : `/files/${file.id}/download`
        const res = await api.get(downloadUrl, { responseType: 'arraybuffer' })
        const plain = await decryptStream(new Uint8Array(res.data), file._fileKey)
        initialContent = new TextDecoder().decode(plain)
      } catch (e) {
        console.warn('failed to preload file content for editor', e)
        // Open editor anyway — it'll start empty and the user can edit from scratch.
      }
      setEditorOpen({
        fileId: file.id,
        filename: name,
        collectionMaster: currentFolder.collectionKey,
        initialContent,
      })
      return
    }
    setDetailItem(file)
  }

  async function handleDownload(file: DecryptedFile) {
    if (!file._fileKey) return
    try {
      const downloadUrl = currentFolder?.isRemote
        ? `/fed-proxy/${currentFolder.remoteShareId}/files/${file.id}/download`
        : `/files/${file.id}/download`
      const res = await api.get(downloadUrl, { responseType: 'arraybuffer' })
      const plaintext = await decryptStream(new Uint8Array(res.data), file._fileKey)
      const blob = new Blob([plaintext.buffer as ArrayBuffer], { type: file.decryptedMimeType ?? 'application/octet-stream' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = file.decryptedName ?? 'file'
      a.click()
      URL.revokeObjectURL(url)
    } catch {
      toast.error(t('drive.toast.downloadFailed'))
    }
  }

  async function handleDeleteFile(file: DecryptedFile, silent = false) {
    try {
      if (currentFolder?.isRemote) {
        await api.delete(`/fed-proxy/${currentFolder.remoteShareId}/files/${file.id}`)
      } else {
        await api.delete(`/files/${file.id}`)
      }
      setFiles((prev) => prev.filter((f) => f.id !== file.id))
      if (!silent) toast.success(t('drive.toast.fileDeleted'))
    } catch {
      if (!silent) toast.error(t('drive.toast.deleteFailed'))
      throw new Error('Delete failed')
    }
  }

  async function handleCreateNote(filename: string) {
    if (!currentFolder?.collectionKey) {
      toast.error(t('drive.toast.uploadFailed'))
      return
    }
    if (!canUploadToCurrentFolder()) {
      toast.error(t('drive.toast.uploadFailed'))
      return
    }
    if (files.some((f) => f.decryptedName === filename)) {
      toast.error(`A file named "${filename}" already exists`)
      return
    }
    const tid = toast.loading('Creating note…')
    try {
      const baseName = filename.replace(/\.md$/i, '')
      const initialContent = `# ${baseName}\n\n`
      const noteFile = new File([new Blob([initialContent], { type: 'text/markdown' })], filename, {
        type: 'text/markdown',
      })
      await uploadFile(noteFile, currentFolder)
      const fresh = await loadFiles(currentFolder)
      const created = fresh.find((f) => f.decryptedName === filename)
      if (!created) {
        toast.error('Note uploaded, but could not be opened — refresh the page.', { id: tid })
        return
      }
      setEditorOpen({
        fileId: created.id,
        filename,
        collectionMaster: currentFolder.collectionKey,
        initialContent,
      })
      try {
        const meRes = await api.get('/user/me')
        dispatch(updateStorageUsed(meRes.data.storageUsedBytes))
      } catch {}
      toast.success('Note created', { id: tid })
    } catch (err: any) {
      toast.error(err?.response?.data?.error ?? 'Failed to create note', { id: tid })
    }
  }

  async function handleCreateFolder(name: string) {
    if (!masterKey) throw new Error('Not logged in')
    const collectionKey = await generateKey()
    const encKey = await encrypt(collectionKey, masterKey)
    const encName = await encrypt(new TextEncoder().encode(name), collectionKey)
    await api.post('/collections/', {
      encryptedName: toBase64(encName.ciphertext),
      nameNonce: toBase64(encName.nonce),
      encryptedKey: toBase64(encKey.ciphertext),
      encryptedKeyNonce: toBase64(encKey.nonce),
      parentCollectionId: currentFolder?.id ?? null,
    })
    await loadCollections()
  }

  async function handleDeleteFolder(col: Collection, silent = false) {
    try {
      await api.delete(`/collections/${col.id}`)
      if (!silent) {
        await loadCollections()
        if (currentFolder?.id === col.id) goHome()
        toast.success(t('drive.toast.folderDeleted'))
      }
    } catch {
      if (!silent) toast.error(t('drive.toast.folderDeleteFailed'))
      throw new Error('Delete failed')
    }
  }

  async function handleRenameFolder(col: Collection, newName: string) {
    if (!col.collectionKey) return
    const encName = await encrypt(new TextEncoder().encode(newName), col.collectionKey)
    await api.put(`/collections/${col.id}`, { encryptedName: toBase64(encName.ciphertext), nameNonce: toBase64(encName.nonce) })
    setCollections((prev) => prev.map((c) => c.id === col.id ? { ...c, decryptedName: newName } : c))
    if (currentFolder?.id === col.id) setCurrentFolder((prev) => prev ? { ...prev, decryptedName: newName } : prev)
    if (myFilesCollection?.id === col.id) setMyFilesCollection((prev) => prev ? { ...prev, decryptedName: newName } : prev)
  }

  async function handleColorFolder(col: Collection, color: string | null) {
    await api.patch(`/collections/${col.id}/color`, { color })
    setCollections((prev) => prev.map((c) => c.id === col.id ? { ...c, color } : c))
    if (currentFolder?.id === col.id) setCurrentFolder((prev) => prev ? { ...prev, color } : prev)
    setDetailItem((prev) =>
      prev && 'ownerUserId' in prev && (prev as Collection).id === col.id
        ? { ...(prev as Collection), color }
        : prev,
    )
  }

  async function handleShare(params: { recipient: string; canUpload: boolean; canDelete: boolean; quotaBytes: number | null; isFederated: boolean }) {
    if (!shareTarget?.collectionKey) return
    if (params.isFederated) {
      const at = params.recipient.lastIndexOf('@')
      const username = params.recipient.slice(0, at)
      const server = params.recipient.slice(at + 1)
      const serverUrl = server.startsWith('http') ? server : `https://${server}`
      const pkRes = await api.get(`/collections/fed-pubkey?username=${encodeURIComponent(username)}&server=${encodeURIComponent(serverUrl)}`)
      const sealedKey = await wrapKeyForRecipient(shareTarget.collectionKey, fromBase64(pkRes.data.publicKey))
      const res = await api.post(`/collections/${shareTarget.id}/share-federated`, {
        recipientUsername: username,
        recipientServer: serverUrl,
        encryptedCollectionKey: toBase64(sealedKey),
        canUpload: params.canUpload,
        canDelete: params.canDelete,
        uploadQuotaBytes: params.canUpload && params.quotaBytes ? params.quotaBytes : null,
      })
      setFedInviteUrl(res.data.inviteUrl)
    } else {
      const res = await api.get(`/users/by-email/${encodeURIComponent(params.recipient)}`)
      const sealedKey = await wrapKeyForRecipient(shareTarget.collectionKey, fromBase64(res.data.publicKey))
      await api.post(`/collections/${shareTarget.id}/share`, {
        recipientUserId: res.data.userId,
        encryptedCollectionKey: toBase64(sealedKey),
        canUpload: params.canUpload,
        canDelete: params.canDelete,
        uploadQuotaBytes: params.canUpload && params.quotaBytes ? params.quotaBytes : null,
      })
      toast.success(t('drive.toast.folderShared'))
    }
  }

  async function handleCreatePublicLink(col: Collection) {
    if (!col.collectionKey) return
    const linkKey = await generateKey()
    const encCollKey = await encrypt(col.collectionKey, linkKey)
    const res = await api.post('/share/', {
      shareType: 'collection',
      targetId: col.id,
      encryptedCollectionKey: toBase64(encCollKey.ciphertext),
      encryptedCollectionKeyNonce: toBase64(encCollKey.nonce),
    })
    const link = `${window.location.origin}/s/${res.data.token}#key=${toBase64(linkKey)}`
    setPublicShareUrl(link)
  }

  async function handleAddRemoteShare(inviteUrl: string) {
    await api.post('/fed-proxy/incoming', { inviteUrl })
    await loadCollections()
    toast.success(t('drive.toast.remoteAdded'))
  }

  async function handleRevokeRemoteShare(col: Collection) {
    await api.delete(`/fed-proxy/incoming/${col.remoteShareId}`)
    setCollections((prev) => prev.filter((c) => c.id !== col.id))
    if (currentFolder?.id === col.id) goToShared()
    toast.success(t('drive.toast.remoteRemoved'))
  }

  function canUploadToCurrentFolder(): boolean {
    if (!currentFolder) return false
    if (!currentFolder.isShared && !currentFolder.isRemote) return true
    return currentFolder.canUpload === true
  }

  function canDeleteFile(): boolean {
    if (!currentFolder) return false
    if (!currentFolder.isShared && !currentFolder.isRemote) return true
    return currentFolder.canDelete === true
  }

  const sharedCollections = collections.filter((c) => c.ownerUserId !== auth.userId || c.isRemote)
  const subFolders =
    viewMode === 'shared'
      ? currentFolder
        ? collections.filter((c) => c.parentCollectionId === currentFolder.id)
        : sharedCollections
      : currentFolder
        ? collections.filter((c) => c.parentCollectionId === currentFolder.id)
        : []

  const visibleFolders = useMemo(() => {
    const q = searchQuery.trim().toLowerCase()
    if (!q) return subFolders
    return subFolders.filter((c) => (c.decryptedName ?? '').toLowerCase().includes(q))
  }, [subFolders, searchQuery])

  const visibleFiles = useMemo(() => {
    const q = searchQuery.trim().toLowerCase()
    if (!q) return files
    return files.filter((f) => (f.decryptedName ?? '').toLowerCase().includes(q))
  }, [files, searchQuery])

  function triggerUpload(targetFolder?: Collection) {
    if (fileInputRef.current) {
      if (targetFolder) {
        fileInputRef.current.onchange = (e) => {
          const fs = Array.from((e.target as HTMLInputElement).files ?? [])
          if (fs.length) uploadFiles(fs, targetFolder)
        }
      } else {
        fileInputRef.current.onchange = (e) => {
          const fs = Array.from((e.target as HTMLInputElement).files ?? [])
          if (fs.length) uploadFiles(fs)
        }
      }
      fileInputRef.current.click()
    }
  }

  const totalSelected = selectedFileIds.size + selectedFolderIds.size

  return (
    <div className="flex min-h-screen">
      <Sidebar
        viewMode={viewMode}
        sharedCount={sharedCollections.length}
        onGoHome={goHome}
        onGoShared={goToShared}
      />

      <div className="flex-1 flex flex-col min-w-0">
        <DriveTopBar
          ref={searchInputRef}
          searchValue={searchQuery}
          onSearchChange={setSearchQuery}
          canUpload={canUploadToCurrentFolder()}
          onShowHelp={() => setShortcutsOpen(true)}
          onUpload={() => triggerUpload()}
          onNewFolder={() => setNewFolderOpen(true)}
          onNewNote={() => setNewNoteOpen(true)}
          onAddRemote={() => setAddRemoteOpen(true)}
          newMenuOpen={newMenuOpen}
          onNewMenuOpenChange={setNewMenuOpen}
        />

        <ContextMenu>
        <ContextMenuTrigger asChild>
        <main
          className="flex-1 p-8 overflow-auto relative"
          onDragOver={(e) => { e.preventDefault(); if (currentFolder?.collectionKey) setIsDragging(true) }}
          onDragEnter={(e) => { e.preventDefault(); if (currentFolder?.collectionKey) setIsDragging(true) }}
          onDragLeave={(e) => { if (!e.currentTarget.contains(e.relatedTarget as Node)) setIsDragging(false) }}
          onDrop={(e) => {
            e.preventDefault()
            setIsDragging(false)
            if (!currentFolder?.collectionKey || !canUploadToCurrentFolder()) return
            const dropped = Array.from(e.dataTransfer.files).filter((f) => f.size > 0)
            if (dropped.length) uploadFiles(dropped)
          }}
        >
          {/* Drag overlay */}
          {isDragging && currentFolder && (
            <div className="fixed inset-0 z-50 bg-primary/15 border-2 border-dashed border-primary pointer-events-none flex items-center justify-center">
              <p className="text-2xl font-semibold text-primary">
                {t('drive.dropToUpload', { name: currentFolder.decryptedName })}
              </p>
            </div>
          )}

          <input ref={fileInputRef} type="file" multiple className="hidden" />

          <DriveBreadcrumb
          viewMode={viewMode}
          currentFolder={currentFolder}
          myFilesCollection={myFilesCollection}
          navigationStack={navigationStack}
          onNavigateTo={navigateTo}
          onGoHome={goHome}
          onGoShared={goToShared}
        />

        {/* Per-share upload quota bar */}
        {currentFolder?.uploadQuotaBytes != null && currentFolder.uploadQuotaBytes > 0 && (
          <div className="mb-4 p-3 bg-card border border-border rounded-lg">
            <div className="flex justify-between text-xs text-muted-foreground mb-2">
              <span>{t('drive.uploadQuota')}</span>
              <span>
                {formatBytes(files.reduce((acc, f) => acc + (f.decryptedSize ?? 0), 0))}
                {' / '}
                {formatBytes(currentFolder.uploadQuotaBytes)}
              </span>
            </div>
            <Progress
              value={Math.min(
                (files.reduce((acc, f) => acc + (f.decryptedSize ?? 0), 0) / currentFolder.uploadQuotaBytes) * 100,
                100,
              )}
              className="h-1.5"
            />
          </div>
        )}

        {/* Selection toolbar — always reserves space to avoid layout shift */}
        <div className="h-10 mb-4 flex items-center">
          {totalSelected > 0 && (
            <div className="flex items-center gap-3 w-full px-3 py-1.5 bg-primary/10 border border-primary/30 rounded-lg">
              <span className="text-sm font-medium">
                {t('drive.selected', { count: totalSelected })}
              </span>
              {selectedFileIds.size > 0 && (
                <Button size="sm" variant="outline" onClick={handleBatchDownload}>
                  <Download className="h-4 w-4 mr-1.5" />
                  {t('drive.downloadFiles', { count: selectedFileIds.size })}
                </Button>
              )}
              {selectedFolderIds.size > 0 && (
                <Button size="sm" variant="outline" onClick={handleBatchFolderDownload}>
                  <Download className="h-4 w-4 mr-1.5" />
                  {t('drive.downloadFolders', { count: selectedFolderIds.size })}
                </Button>
              )}
              <Button size="sm" variant="destructive" onClick={() => setBatchDeleteOpen(true)}>
                <Trash2 className="h-4 w-4 mr-1.5" />
                {t('common.delete')}
              </Button>
              <Button size="sm" variant="ghost" onClick={clearSelection} className="ml-auto">
                {t('drive.clear')}
              </Button>
            </div>
          )}
        </div>

        {/* Folders */}
        <CollectionGrid
          collections={visibleFolders}
          currentUserId={auth.userId}
          selectedIds={selectedFolderIds}
          onEnter={enterFolder}
          onDetails={setDetailItem}
          onToggleSelect={toggleFolderSelect}
          onRename={(col) => setRenameTarget(col)}
          onColor={handleColorFolder}
          onShare={(col) => setShareTarget(col)}
          onPublicLink={handleCreatePublicLink}
          onDelete={(col) => setDeleteFolder(col)}
          onRevoke={handleRevokeRemoteShare}
          onUploadTo={(col) => triggerUpload(col)}
          onDrop={(e, col) => {
            const dropped = Array.from(e.dataTransfer.files).filter((f) => f.size > 0)
            if (dropped.length && col.collectionKey) uploadFiles(dropped, col)
          }}
        />

        {/* Shared empty state */}
        {viewMode === 'shared' && !currentFolder && sharedCollections.length === 0 && (
          <div className="flex flex-col items-center justify-center h-64 text-muted-foreground">
            <p>{t('drive.noSharedFolders')}</p>
          </div>
        )}

        {/* Files */}
        {currentFolder && (
          <>
            {visibleFiles.length === 0 ? (
              searchQuery.trim() ? (
                <div className="flex flex-col items-center justify-center h-48 text-muted-foreground text-sm">
                  <p>No matches for &ldquo;{searchQuery}&rdquo; in this folder.</p>
                </div>
              ) : (
                <EmptyState
                  canUpload={canUploadToCurrentFolder()}
                  onClick={() => canUploadToCurrentFolder() && triggerUpload()}
                />
              )
            ) : (
              <FileTable
                files={visibleFiles}
                canDelete={canDeleteFile()}
                selectedIds={selectedFileIds}
                onSelect={handleFileClick}
                onToggleSelect={toggleFileSelect}
                onToggleSelectAll={toggleAllFiles}
                onDownload={handleDownload}
                onDelete={(file) => setDeleteFile(file)}
              />
            )}
          </>
        )}
        </main>
        </ContextMenuTrigger>
        <ContextMenuContent className="w-52">
          <ContextMenuItem
            onSelect={() => setNewFolderOpen(true)}
            disabled={!canUploadToCurrentFolder()}
          >
            <FolderPlus className="h-4 w-4 mr-2" />
            New folder
          </ContextMenuItem>
          <ContextMenuItem
            onSelect={() => setNewNoteOpen(true)}
            disabled={!canUploadToCurrentFolder()}
          >
            <FileTextIcon className="h-4 w-4 mr-2" />
            New note (.md)
          </ContextMenuItem>
          <ContextMenuSeparator />
          <ContextMenuItem
            onSelect={() => triggerUpload()}
            disabled={!canUploadToCurrentFolder()}
          >
            <UploadIcon className="h-4 w-4 mr-2" />
            Upload files
          </ContextMenuItem>
          <ContextMenuSeparator />
          <ContextMenuItem
            onSelect={() => {
              loadCollections()
              if (currentFolder) loadFiles(currentFolder)
            }}
          >
            <RefreshCw className="h-4 w-4 mr-2" />
            Refresh
          </ContextMenuItem>
        </ContextMenuContent>
        </ContextMenu>
      </div>

      {/* Upload progress */}
      {uploadState && <UploadPanel state={uploadState} />}

      {/* Details panel */}
      <DetailsPanel
        item={detailItem}
        canDelete={
          'ownerUserId' in (detailItem ?? {})
            ? true
            : canDeleteFile()
        }
        onClose={() => setDetailItem(null)}
        onDownload={handleDownload}
        onDownloadFolder={handleFolderDownload}
        onDelete={(item) => {
          if ('ownerUserId' in item) setDeleteFolder(item as Collection)
          else setDeleteFile(item as DecryptedFile)
        }}
        onRename={(col) => setRenameTarget(col)}
        onColor={handleColorFolder}
        onShare={(col) => setShareTarget(col)}
        onPublicLink={handleCreatePublicLink}
        onEnter={enterFolder}
      />

      {/* Collab editor overlay */}
      {editorOpen && (() => {
        const Editor = chooseEditor(editorOpen.filename)
        if (!Editor) return null
        return (
          <div className="fixed inset-0 z-50 flex flex-col bg-background">
            <div className="flex items-center justify-between border-b px-4 py-2">
              <span className="text-sm font-medium truncate">{editorOpen.filename}</span>
              <Button
                size="icon"
                variant="ghost"
                aria-label={t('common.close')}
                onClick={() => setEditorOpen(null)}
              >
                <X className="h-4 w-4" />
              </Button>
            </div>
            <div className="flex-1 min-h-0">
              <Suspense fallback={<div className="p-4 text-sm text-muted-foreground">Loading editor…</div>}>
                <Editor
                  fileId={editorOpen.fileId}
                  filename={editorOpen.filename}
                  collectionMaster={editorOpen.collectionMaster}
                  initialContent={editorOpen.initialContent}
                />
              </Suspense>
            </div>
          </div>
        )
      })()}

      {/* Dialogs */}
      <NewFolderDialog
        open={newFolderOpen}
        onOpenChange={setNewFolderOpen}
        onConfirm={handleCreateFolder}
      />

      <NewNoteDialog
        open={newNoteOpen}
        onOpenChange={setNewNoteOpen}
        onConfirm={handleCreateNote}
      />

      <ShortcutsDialog open={shortcutsOpen} onOpenChange={setShortcutsOpen} />

      <RenameDialog
        collection={renameTarget}
        onOpenChange={(open) => { if (!open) setRenameTarget(null) }}
        onConfirm={handleRenameFolder}
      />

      <ShareDialog
        collection={shareTarget}
        onOpenChange={(open) => { if (!open) setShareTarget(null) }}
        onShare={handleShare}
      />

      <PublicShareDialog
        url={publicShareUrl}
        onOpenChange={(open) => { if (!open) setPublicShareUrl(null) }}
        title={t('drive.publicLink.title')}
        description={t('drive.publicLink.desc')}
      />

      <PublicShareDialog
        url={fedInviteUrl}
        onOpenChange={(open) => { if (!open) setFedInviteUrl(null) }}
        title={t('drive.inviteLink.title')}
        description={t('drive.inviteLink.desc')}
      />

      <AddRemoteShareDialog
        open={addRemoteOpen}
        onOpenChange={setAddRemoteOpen}
        onConfirm={handleAddRemoteShare}
      />

      {/* Delete file confirmation */}
      <AlertDialog open={deleteFile !== null} onOpenChange={() => setDeleteFile(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{t('drive.deleteFile.title', { name: deleteFile?.decryptedName })}</AlertDialogTitle>
            <AlertDialogDescription>{t('drive.deleteFile.desc')}</AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>{t('common.cancel')}</AlertDialogCancel>
            <AlertDialogAction
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
              onClick={() => { if (deleteFile) handleDeleteFile(deleteFile); setDeleteFile(null) }}
            >
              {t('common.delete')}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* Delete folder confirmation */}
      <AlertDialog open={deleteFolder !== null} onOpenChange={() => setDeleteFolder(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{t('drive.deleteFolder.title', { name: deleteFolder?.decryptedName })}</AlertDialogTitle>
            <AlertDialogDescription>{t('drive.deleteFolder.desc')}</AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>{t('common.cancel')}</AlertDialogCancel>
            <AlertDialogAction
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
              onClick={() => { if (deleteFolder) handleDeleteFolder(deleteFolder); setDeleteFolder(null) }}
            >
              {t('common.delete')}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* Batch delete confirmation */}
      <AlertDialog open={batchDeleteOpen} onOpenChange={setBatchDeleteOpen}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{t('drive.batchDelete.title', { count: totalSelected })}</AlertDialogTitle>
            <AlertDialogDescription>
              {selectedFileIds.size > 0 && t('drive.batchDelete.files', { count: selectedFileIds.size })}
              {selectedFileIds.size > 0 && selectedFolderIds.size > 0 && ` ${t('drive.batchDelete.and')} `}
              {selectedFolderIds.size > 0 && t('drive.batchDelete.folders', { count: selectedFolderIds.size })}
              {' '}{t('drive.batchDelete.willBeDeleted')}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>{t('common.cancel')}</AlertDialogCancel>
            <AlertDialogAction
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
              onClick={handleBatchDelete}
            >
              {t('drive.batchDelete.deleteAll')}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  )
}
