import { useState, useEffect, useMemo, useRef } from 'react'
import { useTranslation } from 'react-i18next'
import { useNavigate } from 'react-router-dom'
import { isTauri } from '@/lib/isTauri'
import {
  Download,
  Trash2,
  FolderPlus,
  FileText as FileTextIcon,
  Upload as UploadIcon,
  RefreshCw,
} from 'lucide-react'
import { useAppSelector, useAppDispatch } from '@/store'
import { selectMasterKey, selectPrivateKey, updateStorageUsed, updateStorageQuota, setColor } from '@/store/authSlice'
import api from '@/api/client'
import { resolveApiBase } from '@/lib/apiBase'
import { streamUpload } from '@/upload/streamUpload'
import { streamDownload } from '@/download/streamDownload'
import {
  uploadFolder,
  filesToFolderEntries,
  dataTransferToFolderEntries,
  type FolderEntry,
} from '@/upload/uploadFolder'
import {
  encrypt, decrypt, generateKey, encryptStream, decryptStream,
  wrapKeyForRecipient, unwrapKeyFromSender,
  toBase64, fromBase64,
} from '@/crypto'
import { toast } from 'sonner'
import { formatBytes } from '@/lib/format'
import { downloadAsZip, FsaRequiredError } from '@/lib/zipDownload'

import Sidebar from '@/components/layout/Sidebar'
import DriveBreadcrumb from '@/components/drive/DriveBreadcrumb'
import DriveTopBar from '@/components/drive/DriveTopBar'
import { useIsMobile } from '@/hooks/useIsMobile'
import { MobileShell } from '@/components/mobile/MobileShell'
import { MobileFilesPage } from '@/pages/mobile/MobileFilesPage'
import { MobileItemSheet } from '@/components/mobile/MobileItemSheet'
import {
  ContextMenu,
  ContextMenuContent,
  ContextMenuItem,
  ContextMenuSeparator,
  ContextMenuTrigger,
} from '@/components/ui/context-menu'
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
import { chooseEditor, chooseOfficeEditor, chooseWhiteboardEditor } from '@/components/editors/dispatch'
import { chooseViewer } from '@/components/viewers/dispatch'
import { useKeyboardShortcuts } from '@/hooks/useKeyboardShortcuts'

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
  const navigate = useNavigate()
  const dispatch = useAppDispatch()
  const masterKey = useAppSelector(selectMasterKey)
  const privateKey = useAppSelector(selectPrivateKey)
  const auth = useAppSelector((s) => s.auth)
  // Below `md:` we render the mobile shell (bottom-tab nav + design-driven
  // file/folder views). Desktop keeps the existing Sidebar + DriveTopBar +
  // ContextMenu-wrapped FileTable. Both branches share the data state below.
  const isMobile = useIsMobile()

  const [collections, setCollections] = useState<Collection[]>([])
  const [currentFolder, setCurrentFolder] = useState<Collection | null>(null)
  const [navigationStack, setNavigationStack] = useState<Collection[]>([])
  const [files, setFiles] = useState<DecryptedFile[]>([])
  const [myFilesCollection, setMyFilesCollection] = useState<Collection | null>(null)
  const [viewMode, setViewMode] = useState<'myfiles' | 'shared' | 'trash'>('myfiles')
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
  const [renameTarget, setRenameTarget] = useState<import('@/components/drive/dialogs/RenameDialog').RenameTarget | null>(null)
  const [shareTarget, setShareTarget] = useState<Collection | null>(null)
  const [publicShareUrl, setPublicShareUrl] = useState<string | null>(null)
  const [addRemoteOpen, setAddRemoteOpen] = useState(false)
  const [deleteFile, setDeleteFile] = useState<DecryptedFile | null>(null)
  const [deleteFolder, setDeleteFolder] = useState<Collection | null>(null)
  const [fedInviteUrl, setFedInviteUrl] = useState<string | null>(null)


  const fileInputRef = useRef<HTMLInputElement>(null)
  const folderInputRef = useRef<HTMLInputElement>(null)
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
      dispatch(setColor(meRes.data.color || null))

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

  function goToTrash() {
    setNavigationStack([])
    setViewMode('trash')
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
    const accessToken = auth.accessToken
    if (!accessToken) { toast.error(t('drive.toast.zipFailed')); return }
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

      if (zipFiles.length === 0) {
        toast.error(t('drive.toast.zipNoFiles'), { id: tid })
        return
      }

      await downloadAsZip(zipFiles as any, col.decryptedName ?? 'folder', accessToken, (done, total) => {
        toast.loading(t('drive.toast.zipProgress', { done, total }), { id: tid })
      }, ac.signal)
      toast.success(t('drive.toast.zipDone'), { id: tid })
    } catch (err: any) {
      // Cancelling the save dialog surfaces as AbortError — silent.
      if (err?.name === 'AbortError') { toast.dismiss(tid); return }
      if (err instanceof FsaRequiredError) { toast.error(t('drive.toast.zipNoFsa'), { id: tid }); return }
      console.error('ZIP download failed:', err)
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
    // Federated uploads still use the old in-memory multipart path — the
    // remote peer doesn't speak tus yet. Local uploads go through the
    // streaming tus endpoint: memory stays bounded at ~10 MB regardless
    // of file size, replacing the previous full-file-in-RAM pipeline.
    if (collection.isRemote) {
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
      await api.post(`/fed-proxy/${collection.remoteShareId}/upload`, form, {
        onUploadProgress: (e) => { if (e.total && onProgress) onProgress(e.loaded, e.total) },
      })
      return
    }

    const accessToken = auth.accessToken
    if (!accessToken) throw new Error('Not logged in')
    await streamUpload({
      file,
      collection: { id: collection.id, collectionKey: collection.collectionKey! },
      accessToken,
      onProgress: onProgress
        ? (plainSent, plainTotal) => onProgress(plainSent, plainTotal)
        : undefined,
    })
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

  function handleFileClick(file: DecryptedFile) {
    const name = file.decryptedName
    const previewable = !!name && (
      chooseEditor(name) !== null ||
      chooseOfficeEditor(name) !== null ||
      chooseWhiteboardEditor(name) !== null ||
      chooseViewer(name) !== null
    )
    if (name && currentFolder && !currentFolder.isRemote && previewable) {
      // Open in a new tab — FileEditorPage dispatches to text-collab editor,
      // OnlyOffice office editor, or static viewer based on extension. Tauri
      // blocks new tabs, so navigate in-window there.
      const url = `/file/${currentFolder.id}/${file.id}`
      if (isTauri) navigate(url)
      else window.open(url, '_blank', 'noopener')
      return
    }
    setDetailItem(file)
  }

  async function handleDownload(file: DecryptedFile) {
    if (!file._fileKey) return
    // Federated downloads stay on the old buffered path until the
    // peer's download endpoint can stream — there's no streaming
    // wire contract over `/fed-proxy/.../download` yet.
    if (currentFolder?.isRemote) {
      try {
        const res = await api.get(
          `/fed-proxy/${currentFolder.remoteShareId}/files/${file.id}/download`,
          { responseType: 'arraybuffer' },
        )
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
      return
    }

    // Local files: streaming-decrypt path. RAM stays bounded at
    // ~10 MB on Chromium (FSA writes per chunk); Firefox / Safari
    // degrade to a Blob accumulator inside streamDownload.
    const accessToken = auth.accessToken
    if (!accessToken) {
      toast.error(t('drive.toast.downloadFailed'))
      return
    }
    try {
      // Use the resolved API base (so the Tauri shell hits the
      // user-selected backend, not `tauri://localhost/api/...`). On the
      // web this is just `/api`, unchanged.
      const base = await resolveApiBase()
      await streamDownload({
        url: `${base}/files/${file.id}/download`,
        fileKey: file._fileKey,
        filename: file.decryptedName ?? 'file',
        mimeType: file.decryptedMimeType ?? 'application/octet-stream',
        expectedPlainSize: file.decryptedSize,
        accessToken,
      })
    } catch (err) {
      // showSaveFilePicker user-cancel surfaces as AbortError —
      // silent in that case.
      if (err instanceof DOMException && err.name === 'AbortError') return
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
      {
        const url = `/file/${currentFolder.id}/${created.id}`
        if (isTauri) navigate(url)
        else window.open(url, '_blank', 'noopener')
      }
      try {
        const meRes = await api.get('/user/me')
        dispatch(updateStorageUsed(meRes.data.storageUsedBytes))
      } catch {}
      toast.success('Note created', { id: tid })
    } catch (err: any) {
      toast.error(err?.response?.data?.error ?? 'Failed to create note', { id: tid })
    }
  }

  async function handleCreateOffice(kind: 'docx' | 'xlsx' | 'pptx' | 'excalidraw') {
    if (!currentFolder?.collectionKey) {
      toast.error(t('drive.toast.uploadFailed'))
      return
    }
    if (!canUploadToCurrentFolder()) {
      toast.error(t('drive.toast.uploadFailed'))
      return
    }
    // Auto-name "Untitled.docx", "Untitled (2).docx", … to dodge collisions.
    let base = 'Untitled'
    let suffix = 0
    let filename = `${base}.${kind}`
    while (files.some((f) => f.decryptedName === filename)) {
      suffix += 1
      filename = `${base} (${suffix}).${kind}`
    }
    const mimeByKind: Record<string, string> = {
      docx: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
      xlsx: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
      pptx: 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
      excalidraw: 'application/vnd.excalidraw+json',
    }
    const tid = toast.loading(`Creating ${kind}…`)
    try {
      // Office: 1-byte placeholder (the editor renders an empty template
      // and replaces with real OOXML on first save). Excalidraw needs a
      // valid empty JSON shape so the editor can parse it on first open.
      let initialBytes: Uint8Array
      if (kind === 'excalidraw') {
        const empty = JSON.stringify({
          type: 'excalidraw',
          version: 2,
          source: 'kutup',
          elements: [],
          appState: { gridSize: null, viewBackgroundColor: '#ffffff' },
          files: {},
        })
        initialBytes = new TextEncoder().encode(empty)
      } else {
        initialBytes = new Uint8Array([0])
      }
      const officeFile = new File([new Blob([initialBytes.buffer as ArrayBuffer], { type: mimeByKind[kind] })], filename, {
        type: mimeByKind[kind],
      })
      await uploadFile(officeFile, currentFolder)
      const fresh = await loadFiles(currentFolder)
      const created = fresh.find((f) => f.decryptedName === filename)
      if (!created) {
        toast.error('File uploaded, but could not be opened — refresh the page.', { id: tid })
        return
      }
      {
        const url = `/file/${currentFolder.id}/${created.id}`
        if (isTauri) navigate(url)
        else window.open(url, '_blank', 'noopener')
      }
      try {
        const meRes = await api.get('/user/me')
        dispatch(updateStorageUsed(meRes.data.storageUsedBytes))
      } catch {}
      toast.success(`${filename} created`, { id: tid })
    } catch (err: any) {
      toast.error(err?.response?.data?.error ?? `Failed to create ${kind}`, { id: tid })
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

  async function handleRenameFile(file: DecryptedFile, newName: string) {
    if (!file._fileKey) {
      toast.error(t('drive.toast.renameFailed', { defaultValue: 'Rename failed' }))
      return
    }
    try {
      const { renameFile } = await import('@/lib/renameFile')
      await renameFile(file, newName, file._fileKey)
      setFiles((prev) => prev.map((f) => f.id === file.id ? { ...f, decryptedName: newName } : f))
      // If the details panel currently shows this file, update it too.
      setDetailItem((prev) =>
        prev && !('ownerUserId' in prev) && (prev as DecryptedFile).id === file.id
          ? { ...(prev as DecryptedFile), decryptedName: newName }
          : prev,
      )
    } catch (err) {
      console.error('rename file failed', err)
      toast.error(t('drive.toast.renameFailed', { defaultValue: 'Rename failed' }))
    }
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

  async function handleFolderUploadEntries(entries: FolderEntry[]) {
    if (entries.length === 0) return
    const folder = currentFolder
    if (!folder?.collectionKey || !masterKey) return
    const accessToken = auth.accessToken
    if (!accessToken) {
      toast.error(t('drive.toast.uploadFailed'))
      return
    }
    const totalBytes = entries.reduce((s, e) => s + e.file.size, 0)
    const tid = toast.loading(t('drive.toast.uploadingFolder', { count: entries.length }))
    try {
      let filesDone = 0
      await uploadFolder({
        entries,
        parentCollection: { id: folder.id, collectionKey: folder.collectionKey },
        masterKey,
        accessToken,
        onProgress: (done, total, current) => {
          filesDone = done
          toast.loading(
            t('drive.toast.uploadingFolderProgress', { done, total, current }),
            { id: tid },
          )
        },
      })
      toast.success(
        t('drive.toast.folderUploaded', { count: filesDone, bytes: totalBytes }),
        { id: tid },
      )
      await loadCollections()
      await loadFiles(folder)
    } catch (err) {
      const aborted = err instanceof DOMException && err.name === 'AbortError'
      toast.error(aborted ? t('drive.toast.uploadCancelled') : t('drive.toast.uploadFailed'), { id: tid })
    }
  }

  function triggerFolderUpload() {
    if (!folderInputRef.current) return
    folderInputRef.current.onchange = (e) => {
      const input = e.target as HTMLInputElement
      const files = input.files
      if (!files || files.length === 0) return
      void handleFolderUploadEntries(filesToFolderEntries(files))
      // Clear so picking the same folder again triggers onchange.
      input.value = ''
    }
    folderInputRef.current.click()
  }

  const totalSelected = selectedFileIds.size + selectedFolderIds.size

  useKeyboardShortcuts({
    onUpload: () => {
      if (canUploadToCurrentFolder()) triggerUpload()
    },
    onNew: () => {
      // Open the topbar's "+ New" dropdown
      setNewMenuOpen(true)
    },
    onFocusSearch: () => {
      searchInputRef.current?.focus()
      searchInputRef.current?.select()
    },
    onClearOrClose: () => {
      if (searchQuery) {
        setSearchQuery('')
        searchInputRef.current?.blur()
      }
    },
    onSelectAll: () => {
      if (visibleFiles.length === 0) return
      setSelectedFileIds(new Set(visibleFiles.map((f) => f.id)))
    },
    onDelete: () => {
      if (totalSelected > 0) setBatchDeleteOpen(true)
    },
    onToggleHelp: () => {
      setShortcutsOpen((o) => !o)
    },
  })

  // Mobile branch — bottom-tab navigation shell, design-driven Files page.
  // Returns early so the desktop layout below never mounts on phones (avoids
  // mounting the desktop Sidebar / drag-and-drop main / FileTable, all of
  // which assume a wide viewport).
  //
  // PR 2 wires the actions that DON'T require dialogs (upload-files,
  // upload-folder, new-whiteboard); New folder / New note / item-actions
  // (rename / share / details) get wired in PR 3 once the design's mobile
  // sheet variants for those flows are in place.
  if (isMobile) {
    // "At root" = we're at the user's My Files collection AND there are no
    // sub-folders on the breadcrumb stack. Drives the large-title pattern +
    // suppresses the Back button. kutup's root is a non-null Collection
    // (unlike the design prototype's `null` root) so this can't be inferred
    // from `currentFolder == null`.
    const isAtRoot =
      navigationStack.length === 0 &&
      (!currentFolder ||
        (myFilesCollection != null && currentFolder.id === myFilesCollection.id))

    return (
      <MobileShell>
        <MobileFilesPage
          folders={visibleFolders}
          files={visibleFiles}
          currentFolder={currentFolder}
          isAtRoot={isAtRoot}
          usedBytes={auth.storageUsedBytes}
          quotaBytes={auth.storageQuotaBytes}
          onOpenFolder={enterFolder}
          onOpenFile={handleFileClick}
          onBack={() => {
            if (navigationStack.length > 0) {
              const next = navigationStack[navigationStack.length - 1]
              setNavigationStack((prev) => prev.slice(0, -1))
              setCurrentFolder(next)
              setFiles([])
            } else {
              goHome()
            }
          }}
          onItemMore={setDetailItem}
          onUploadFiles={() => triggerUpload()}
          onUploadFolder={() => triggerFolderUpload()}
          onNewFolder={() => {
            // PR 3: mobile NewFolder sheet. For now show a stub toast so the
            // FAB sheet item isn't silently dead.
            toast.message(t('mobile.sheet.add.newFolder', 'New folder'), {
              description: t('mobile.actionUnavailable', 'Tap a folder on desktop to create one — mobile flow coming soon.'),
            })
          }}
          onNewNote={() => {
            toast.message(t('mobile.sheet.add.newNote', 'New note'), {
              description: t('mobile.actionUnavailable', 'Tap a folder on desktop to create one — mobile flow coming soon.'),
            })
          }}
          onNewWhiteboard={() => handleCreateOffice('excalidraw')}
        />

        {/* Item-actions sheet — opens when the user taps the ⋯ button on a
            folder tile or file row. Wires the actions that don't require a
            dialog (Open, Color, Download) directly; the rest surface stub
            toasts until a follow-up PR moves RenameDialog / ShareDialog /
            delete-confirm AlertDialogs out of the desktop branch so mobile
            can share them. */}
        <MobileItemSheet
          item={detailItem}
          onClose={() => setDetailItem(null)}
          onOpen={(it) => {
            if ('encryptedName' in it) enterFolder(it)
            else handleFileClick(it)
          }}
          onChangeColor={(folder, color) => handleColorFolder(folder, color)}
          onDownload={(file) => handleDownload(file)}
          onRename={() =>
            toast.message(t('mobile.item.rename', 'Rename'), {
              description: t('mobile.actionUnavailable', 'Tap a folder on desktop to create one — mobile flow coming soon.'),
            })
          }
          onShare={() =>
            toast.message(t('mobile.item.share', 'Share'), {
              description: t('mobile.actionUnavailable', 'Tap a folder on desktop to create one — mobile flow coming soon.'),
            })
          }
          onDelete={() =>
            toast.message(t('mobile.item.trash', 'Move to Trash'), {
              description: t('mobile.actionUnavailable', 'Tap a folder on desktop to create one — mobile flow coming soon.'),
            })
          }
        />
      </MobileShell>
    )
  }

  return (
    <div className="flex h-screen overflow-hidden">
      <Sidebar
        viewMode={viewMode}
        sharedCount={sharedCollections.length}
        onGoHome={goHome}
        onGoShared={goToShared}
        onGoTrash={goToTrash}
      />

      <div className="flex-1 flex flex-col min-w-0 min-h-0">
        <DriveTopBar
          ref={searchInputRef}
          searchValue={searchQuery}
          onSearchChange={setSearchQuery}
          canUpload={canUploadToCurrentFolder()}
          onShowHelp={() => setShortcutsOpen(true)}
          onUpload={() => triggerUpload()}
          onUploadFolder={() => triggerFolderUpload()}
          onNewFolder={() => setNewFolderOpen(true)}
          onNewNote={() => setNewNoteOpen(true)}
          onNewOffice={(kind) => handleCreateOffice(kind)}
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
            const items = e.dataTransfer.items
            const hasDirEntry = (() => {
              for (let i = 0; i < items.length; i++) {
                const it = items[i] as DataTransferItem & {
                  webkitGetAsEntry?: () => FileSystemEntry | null
                }
                const entry = it.webkitGetAsEntry?.()
                if (entry?.isDirectory) return true
              }
              return false
            })()
            if (hasDirEntry) {
              void (async () => {
                const entries = await dataTransferToFolderEntries(items)
                if (entries.length) await handleFolderUploadEntries(entries)
              })()
              return
            }
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
          {/* eslint-disable-next-line @typescript-eslint/ban-ts-comment */}
          {/* @ts-expect-error — webkitdirectory isn't in React's typing yet */}
          <input ref={folderInputRef} type="file" webkitdirectory="" directory="" multiple className="hidden" />

          {viewMode === 'trash' ? (
            // Trash view lives inside the same Sidebar + DriveTopBar chrome
            // as My Files / Shared (per user request: "should be like My
            // Files tab and Shared with me tab just change the main board").
            // PR 2 ships the empty hero; PRs 6/7 (backend soft-delete +
            // wired UI) add the items list + Restore / Delete-permanently
            // controls.
            <div className="flex flex-col items-center justify-center h-full text-center py-12">
              <div className="w-16 h-16 rounded-2xl bg-muted text-muted-foreground inline-flex items-center justify-center mb-3">
                <Trash2 className="h-7 w-7" />
              </div>
              <div className="text-base font-semibold text-foreground">
                {t('mobile.trash.empty.title', 'Trash is empty')}
              </div>
              <div className="text-sm text-muted-foreground mt-1 max-w-md">
                {t('mobile.trash.empty.subtitle', 'Deleted files appear here for 30 days')}
              </div>
            </div>
          ) : (<>

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
          onRename={(col) => setRenameTarget({ kind: "collection", collection: col })}
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
                onDetails={setDetailItem}
                onRename={(file) => setRenameTarget({ kind: 'file', file })}
              />
            )}
          </>
        )}
          </>)}
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
        onRename={(col) => setRenameTarget({ kind: "collection", collection: col })}
        onRenameFile={(file) => setRenameTarget({ kind: 'file', file })}
        onColor={handleColorFolder}
        onShare={(col) => setShareTarget(col)}
        onPublicLink={handleCreatePublicLink}
        onEnter={enterFolder}
      />

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
        target={renameTarget}
        onOpenChange={(open) => { if (!open) setRenameTarget(null) }}
        onConfirmCollection={handleRenameFolder}
        onConfirmFile={handleRenameFile}
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
