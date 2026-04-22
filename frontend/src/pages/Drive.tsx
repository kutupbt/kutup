import { useState, useEffect, useRef, useCallback } from 'react'
import { Plus, FolderPlus, Upload, Globe } from 'lucide-react'
import { useAppSelector, useAppDispatch } from '@/store'
import { selectMasterKey, selectPrivateKey, logout, updateStorageUsed, updateStorageQuota } from '@/store/authSlice'
import api from '@/api/client'
import {
  encrypt, decrypt, generateKey, encryptStream, decryptStream,
  wrapKeyForRecipient, unwrapKeyFromSender,
  toBase64, fromBase64,
} from '@/crypto'
import { toast } from 'sonner'
import { formatBytes } from '@/lib/format'
import { copyText } from '@/lib/format'

import Sidebar from '@/components/layout/Sidebar'
import DriveBreadcrumb from '@/components/drive/DriveBreadcrumb'
import CollectionGrid from '@/components/drive/CollectionGrid'
import FileTable from '@/components/drive/FileTable'
import UploadPanel from '@/components/drive/UploadPanel'
import EmptyState from '@/components/drive/EmptyState'
import NewFolderDialog from '@/components/drive/dialogs/NewFolderDialog'
import RenameDialog from '@/components/drive/dialogs/RenameDialog'
import ShareDialog from '@/components/drive/dialogs/ShareDialog'
import PublicShareDialog from '@/components/drive/dialogs/PublicShareDialog'
import AddRemoteShareDialog from '@/components/drive/dialogs/AddRemoteShareDialog'

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
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'

import type { Collection, DecryptedFile, UploadState } from '@/types/drive'

interface FileMetadata { name: string; mimeType: string; size: number }

export default function Drive() {
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

  // Dialog states
  const [newFolderOpen, setNewFolderOpen] = useState(false)
  const [renameTarget, setRenameTarget] = useState<Collection | null>(null)
  const [shareTarget, setShareTarget] = useState<Collection | null>(null)
  const [publicShareUrl, setPublicShareUrl] = useState<string | null>(null)
  const [addRemoteOpen, setAddRemoteOpen] = useState(false)
  const [deleteFile, setDeleteFile] = useState<DecryptedFile | null>(null)
  const [deleteFolder, setDeleteFolder] = useState<Collection | null>(null)
  const [fedInviteUrl, setFedInviteUrl] = useState<string | null>(null)

  const fileInputRef = useRef<HTMLInputElement>(null)

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
  }, [currentFolder?.id])

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
      toast.error('Failed to load collections')
    }
  }

  async function loadFiles(collection: Collection) {
    if (!collection.collectionKey) return
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
    } catch {
      toast.error('Failed to load files')
    }
  }

  function enterFolder(col: Collection) {
    if (currentFolder && currentFolder.id !== myFilesCollection?.id) {
      setNavigationStack((prev) => [...prev, currentFolder])
    }
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
    const target = navigationStack[index]
    setNavigationStack((prev) => prev.slice(0, index))
    setCurrentFolder(target)
    setFiles([])
  }

  // Upload logic
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
      toast.success(`Uploaded ${filesToUpload.length} file${filesToUpload.length > 1 ? 's' : ''}`)
    } catch (err: any) {
      toast.error(err.response?.data?.error ?? 'Upload failed')
    } finally {
      try { const meRes = await api.get('/user/me'); dispatch(updateStorageUsed(meRes.data.storageUsedBytes)) } catch {}
      setUploadState(null)
      if (folder.id === currentFolder?.id) await loadFiles(folder)
      if (fileInputRef.current) fileInputRef.current.value = ''
    }
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
      toast.error('Download failed')
    }
  }

  async function handleDeleteFile(file: DecryptedFile) {
    try {
      if (currentFolder?.isRemote) {
        await api.delete(`/fed-proxy/${currentFolder.remoteShareId}/files/${file.id}`)
      } else {
        await api.delete(`/files/${file.id}`)
      }
      setFiles((prev) => prev.filter((f) => f.id !== file.id))
      toast.success('File deleted')
    } catch {
      toast.error('Delete failed')
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

  async function handleDeleteFolder(col: Collection) {
    try {
      await api.delete(`/collections/${col.id}`)
      await loadCollections()
      if (currentFolder?.id === col.id) goHome()
      toast.success('Folder deleted')
    } catch {
      toast.error('Failed to delete folder')
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
      toast.success('Folder shared')
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
    toast.success('Remote share added')
  }

  async function handleRevokeRemoteShare(col: Collection) {
    await api.delete(`/fed-proxy/incoming/${col.remoteShareId}`)
    setCollections((prev) => prev.filter((c) => c.id !== col.id))
    if (currentFolder?.id === col.id) goToShared()
    toast.success('Remote share removed')
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

  return (
    <div className="flex min-h-screen">
      <Sidebar viewMode={viewMode} onGoHome={goHome} onGoShared={goToShared} />

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
            <p className="text-2xl font-semibold text-white">
              Drop to upload to "{currentFolder.decryptedName}"
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
              <span>Upload quota</span>
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

        {/* Folders */}
        <CollectionGrid
          collections={subFolders}
          currentUserId={auth.userId}
          onEnter={enterFolder}
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
            <p>No folders have been shared with you yet.</p>
          </div>
        )}

        {/* Files */}
        {currentFolder && (
          <>
            {files.length === 0 ? (
              <EmptyState
                canUpload={canUploadToCurrentFolder()}
                onClick={() => canUploadToCurrentFolder() && triggerUpload()}
              />
            ) : (
              <FileTable
                files={files}
                canDelete={canDeleteFile()}
                onDownload={handleDownload}
                onDelete={(file) => setDeleteFile(file)}
              />
            )}
          </>
        )}
      </main>

      {/* FAB */}
      <div className="fixed bottom-8 right-8 z-40">
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button
              size="icon"
              className="h-14 w-14 rounded-full shadow-lg shadow-primary/30"
            >
              <Plus className="h-6 w-6" />
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end" className="mb-2">
            {canUploadToCurrentFolder() && (
              <DropdownMenuItem onSelect={() => triggerUpload()}>
                <Upload className="h-4 w-4 mr-2" />
                Upload files
              </DropdownMenuItem>
            )}
            <DropdownMenuItem onSelect={() => setNewFolderOpen(true)}>
              <FolderPlus className="h-4 w-4 mr-2" />
              New folder
            </DropdownMenuItem>
            <DropdownMenuSeparator />
            <DropdownMenuItem onSelect={() => setAddRemoteOpen(true)}>
              <Globe className="h-4 w-4 mr-2" />
              Add remote share
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </div>

      {/* Upload progress */}
      {uploadState && <UploadPanel state={uploadState} />}

      {/* Dialogs */}
      <NewFolderDialog
        open={newFolderOpen}
        onOpenChange={setNewFolderOpen}
        onConfirm={handleCreateFolder}
      />

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
        title="Public link ready"
        description="Anyone with this link can access the files. The decryption key is in the fragment and is never sent to the server."
      />

      <PublicShareDialog
        url={fedInviteUrl}
        onOpenChange={(open) => { if (!open) setFedInviteUrl(null) }}
        title="Invite link ready"
        description="Send this link to the recipient. They'll paste it in 'Add remote share'."
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
            <AlertDialogTitle>Delete "{deleteFile?.decryptedName}"?</AlertDialogTitle>
            <AlertDialogDescription>This cannot be undone.</AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
              onClick={() => { if (deleteFile) handleDeleteFile(deleteFile); setDeleteFile(null) }}
            >
              Delete
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* Delete folder confirmation */}
      <AlertDialog open={deleteFolder !== null} onOpenChange={() => setDeleteFolder(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete folder "{deleteFolder?.decryptedName}"?</AlertDialogTitle>
            <AlertDialogDescription>
              All files and subfolders will be permanently deleted.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
              onClick={() => { if (deleteFolder) handleDeleteFolder(deleteFolder); setDeleteFolder(null) }}
            >
              Delete
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  )
}
