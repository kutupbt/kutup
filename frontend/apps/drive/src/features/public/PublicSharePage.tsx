import { useQuery } from '@tanstack/react-query'
import { Download } from 'lucide-react'
import { useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useParams } from 'react-router-dom'
import { toast } from 'sonner'
import { fromBase64, openFileMetadataV1, openFileRecordV1, openPublicLinkCollectionKeyV1, openPublicLinkFileKeyV1 } from '@kutup/crypto'
import { unlockCollectionKeyring, type EpochLinkV1 } from '@kutup/crypto/collectionKeyring'
import { fileKeyAtV1 } from '@kutup/crypto/fileKeyring'
import { decryptFileBlobV1 } from '@kutup/crypto/fileBlob'
import { isListName, stateToListJson } from '@kutup/map/list'
import { editorKindFor } from '@kutup/editors/editorKind'
import { streamDownload } from '@kutup/files/download/streamDownload'
import { resolveApiBase } from '@kutup/session/apiBase'
import type { FileKeyHistoryEntry } from '@kutup/session/api-types'
import api from '@kutup/session/client'
import { Alert } from '@kutup/ui/components/alert'
import { KutupLogo } from '@kutup/ui/components/brand'
import { LocaleToggle } from '@kutup/ui/components/locale-toggle'
import { EmptyState, LoadingPanel } from '@kutup/ui/components/states'
import { ThemeToggle } from '@kutup/ui/components/theme-toggle'
import { apiErrorCode } from '@kutup/ui/lib/apiError'
import { Explorer } from '../explorer/Explorer'
import { fileKind } from '@kutup/drive-core/kinds'
import { useExplorerPrefs } from '../explorer/prefs'
import { filterItems, sortItems, type ExplorerItem } from '../explorer/sort'
import { Toolbar } from '../explorer/Toolbar'

interface ShareInfo {
  /** 'collection': a folder's files; 'file': one file (docs/plans/drive-file-sharing.md). */
  shareType: 'collection' | 'file'
  targetId: string
  collectionKeyEnvelope: string
  collectionKeyEpoch: number
  ownerUserId: string
  /** Signs the folder's key history. */
  ownerAuthorityPublicKey: string
  expiresAt?: string | null
  /** A link to one file: the file (its key is `collectionKeyEnvelope`, of generation `collectionKeyEpoch`). */
  file?: PublicFileRow
}

interface PublicFileRow {
  id: string
  collectionId: string
  metadataEnvelope: string
  fileKeyEnvelope: string
  keyEpoch: number
  keyGeneration: number
  metadataRevision: number
  createdAt: string
  /** The key generation of what a download serves (docs/plans/drive-move.md). */
  contentKeyGeneration: number
  keyHistory?: FileKeyHistoryEntry[]
}

interface PublicFile {
  row: PublicFileRow
  /** The key the downloaded content opens with (of `row.contentKeyGeneration`). */
  fileKey: Uint8Array | null
  /** The file's current key (of `row.keyGeneration`), to reach any older one. */
  currentKey: Uint8Array | null
  name: string | null
  mimeType: string
  size: number
}

type Failure = 'missingKey' | 'notFound' | 'expired' | 'badKey' | 'waiting' | 'other'

/** The key lives only in the fragment (`#key=…`), which browsers never send to a server. */
function linkKey(): Uint8Array | null {
  try {
    const key = new URLSearchParams(window.location.hash.slice(1)).get('key')
    const bytes = key ? fromBase64(key) : null
    return bytes && bytes.length === 32 ? bytes : null
  } catch {
    return null
  }
}

async function loadShare(token: string): Promise<PublicFile[]> {
  const key = linkKey()
  if (!key) throw new PublicLinkError('missingKey')
  let share: ShareInfo
  try {
    share = (await api.get<ShareInfo>(`/share/${encodeURIComponent(token)}`)).data
  } catch (error) {
    const code = apiErrorCode(error)
    throw new PublicLinkError(code === 'not_found' ? 'notFound' : (error as { response?: { status?: number } }).response?.status === 410 ? 'expired' : 'other')
  }
  if (share.expiresAt && Date.parse(share.expiresAt) < Date.now()) throw new PublicLinkError('expired')
  if (share.shareType === 'file') return [await loadFile(share, key)]
  let collectionKey: Uint8Array
  try {
    collectionKey = await openPublicLinkCollectionKeyV1(share.collectionKeyEnvelope, key, {
      collectionId: share.targetId,
      ownerUserId: share.ownerUserId,
      epoch: share.collectionKeyEpoch,
    })
  } catch {
    throw new PublicLinkError('badKey')
  }
  // Older folder keys, for files stored before the folder's last rotation:
  // unlocked through its owner-signed history, fetched only if needed.
  let keyring: Promise<Uint8Array[]> | null = null
  const keyAt = (epoch: number): Promise<Uint8Array> => {
    if (epoch === share.collectionKeyEpoch) return Promise.resolve(collectionKey)
    keyring ??= api
      .get<EpochLinkV1[]>(`/share/${encodeURIComponent(token)}/epochs`)
      .then(({ data: chain }) => {
        if (chain.length !== share.collectionKeyEpoch) throw new Error('incomplete folder key history')
        return unlockCollectionKeyring(collectionKey, share.targetId, share.ownerUserId, share.ownerAuthorityPublicKey, chain)
      })
    return keyring.then((keys) => {
      const key = keys[epoch - 1]
      if (!key) throw new Error('no such folder key epoch')
      return key
    })
  }
  const { data } = await api.get<PublicFileRow[]>(`/share/${encodeURIComponent(token)}/files`)
  return Promise.all(
    data.map(async (row) => {
      const opened = await keyAt(row.keyEpoch)
        .then((key) => openFileRecordV1(row, key))
        .catch(() => null)
      // What a download serves may be sealed under a key the file left
      // behind at a re-key; the file's own chain reaches it.
      const contentKey = opened
        ? await fileKeyAtV1(opened.fileKey, row.id, row.keyGeneration, row.keyHistory ?? [], row.contentKeyGeneration)
            .catch(() => null)
        : null
      return {
        row,
        fileKey: contentKey,
        currentKey: opened?.fileKey ?? null,
        name: opened?.metadata.name ?? null,
        mimeType: opened?.metadata.mimeType ?? 'application/octet-stream',
        size: opened?.metadata.size ?? 0,
      }
    }),
  )
}

/** A link to one file: its key from the link, then its name and content by its own key. */
async function loadFile(share: ShareInfo, key: Uint8Array): Promise<PublicFile> {
  const row = share.file
  if (!row) throw new PublicLinkError('notFound')
  let fileKey: Uint8Array
  try {
    fileKey = await openPublicLinkFileKeyV1(share.collectionKeyEnvelope, key, {
      fileId: share.targetId,
      ownerUserId: share.ownerUserId,
      generation: share.collectionKeyEpoch,
    })
  } catch {
    throw new PublicLinkError('badKey')
  }
  // The file moved to a newer key the owner has not handed to the link yet.
  if (share.collectionKeyEpoch !== row.keyGeneration) throw new PublicLinkError('waiting')
  const metadata = await openFileMetadataV1(row, fileKey).catch(() => null)
  const contentKey = await fileKeyAtV1(fileKey, row.id, row.keyGeneration, row.keyHistory ?? [], row.contentKeyGeneration).catch(() => null)
  return {
    row,
    fileKey: contentKey,
    currentKey: fileKey,
    name: metadata?.name ?? null,
    mimeType: metadata?.mimeType ?? 'application/octet-stream',
    size: metadata?.size ?? 0,
  }
}

/**
 * A note's text or a place list's places as last saved. Their edits are Yjs
 * state, not whole-file versions, so the download alone is the upload. Null
 * for other files, or when nothing was saved since the upload.
 */
async function editedContent(token: string, file: PublicFile): Promise<Uint8Array | null> {
  const name = file.name ?? ''
  const list = isListName(name)
  if (!file.currentKey || (!list && editorKindFor(name) !== 'text')) return null
  let response
  try {
    response = await api.get<ArrayBuffer>(`/share/${encodeURIComponent(token)}/state/${file.row.id}`, { responseType: 'arraybuffer' })
  } catch (error) {
    if ((error as { response?: { status?: number } }).response?.status === 404) return null
    throw error
  }
  const generation = Number(response.headers['x-kutup-key-generation'])
  const key = await fileKeyAtV1(file.currentKey, file.row.id, file.row.keyGeneration, file.row.keyHistory ?? [], generation)
  const state = await decryptFileBlobV1(new Uint8Array(response.data), key, { fileId: file.row.id, generation })
  if (list) return stateToListJson(state)
  const Y = await import('yjs')
  const doc = new Y.Doc()
  try {
    Y.applyUpdateV2(doc, state)
    return new TextEncoder().encode(doc.getText('content').toJSON())
  } finally {
    doc.destroy()
  }
}

function saveBytes(bytes: Uint8Array, filename: string, mimeType: string) {
  const url = URL.createObjectURL(new Blob([bytes.slice()], { type: mimeType }))
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  a.click()
  setTimeout(() => URL.revokeObjectURL(url), 1000)
}

class PublicLinkError extends Error {
  constructor(readonly failure: Failure) {
    super(failure)
  }
}

/**
 * A public link: the files directly in one folder, readable without an
 * account. Decrypted here with the key from the link; the server only ever
 * served ciphertext.
 */
export function PublicSharePage() {
  const { t, i18n } = useTranslation()
  const { token = '' } = useParams()
  const [prefs, updatePrefs] = useExplorerPrefs()
  const [selection, setSelection] = useState<Set<string>>(new Set())
  const share = useQuery({ queryKey: ['public-share', token], queryFn: () => loadShare(token), retry: false })

  const byId = useMemo(() => new Map((share.data ?? []).map((f) => [f.row.id, f])), [share.data])
  const items: ExplorerItem[] = (share.data ?? []).map((f) => ({
    type: 'file',
    id: f.row.id,
    name: f.name ?? t('drive.encrypted'),
    kind: f.name ? fileKind(f.name, f.mimeType) : 'other',
    size: f.name ? f.size : null,
    modifiedAt: f.row.createdAt,
  }))
  const shown = sortItems(filterItems(items, prefs.kinds), prefs.sort, i18n.language)

  async function download(file: PublicFile) {
    if (!file.fileKey || !file.name) return
    try {
      // A note or place list: its saved edits, turned back into the file.
      const edited = await editedContent(token, file)
      if (edited) {
        saveBytes(edited, file.name, file.mimeType)
        return
      }
      await streamDownload({
        url: `${await resolveApiBase()}/share/${encodeURIComponent(token)}/download/${file.row.id}`,
        fileKey: file.fileKey,
        context: { fileId: file.row.id, generation: file.row.contentKeyGeneration },
        filename: file.name,
        mimeType: file.mimeType,
        expectedPlainSize: file.size,
        accessToken: '',
      })
    } catch (error) {
      if (!(error instanceof DOMException && error.name === 'AbortError')) toast.error(t('drive.downloadFailed'))
    }
  }

  const failure = share.error instanceof PublicLinkError ? share.error.failure : share.isError ? 'other' : null

  return (
    <div className="flex min-h-svh flex-col bg-background">
      <header className="flex h-14 items-center gap-3 border-b border-border px-4 md:px-6">
        <KutupLogo size={22} />
        <span className="font-display text-lg font-semibold">{t('public.title')}</span>
        <span className="ml-auto flex items-center gap-2">
          <LocaleToggle onChrome={false} />
          <ThemeToggle onChrome={false} />
        </span>
      </header>
      {share.isPending ? <LoadingPanel label={t('public.decrypting')} /> : null}
      {failure ? (
        <div className="mx-auto w-full max-w-lg p-6">
          <Alert variant="error" title={t(`public.failure.${failure}.title`)}>
            {t(`public.failure.${failure}.description`)}
          </Alert>
        </div>
      ) : null}
      {share.data ? (
        <>
          <div className="flex min-h-12 flex-wrap items-center gap-2 border-b border-border px-3 py-1.5 md:px-6">
            <p className="min-w-0 flex-1 text-sm text-muted-foreground">{t('public.description', { count: items.length })}</p>
            <Toolbar prefs={prefs} update={updatePrefs} />
          </div>
          {shown.length === 0 ? (
            <EmptyState title={t('public.emptyTitle')} description={t('public.emptyDescription')} />
          ) : (
            <Explorer
              items={shown}
              view={prefs.view}
              sort={prefs.sort}
              onSortField={(field) =>
                updatePrefs(field === prefs.sort.field ? { dir: prefs.sort.dir === 'asc' ? 'desc' : 'asc' } : { field })
              }
              selection={selection}
              onSelectionChange={setSelection}
              onOpen={(item) => {
                const f = byId.get(item.id)
                if (f) void download(f)
              }}
              actionsFor={(item) => {
                const f = byId.get(item.id)
                return f?.fileKey
                  ? [{ id: 'download', label: t('drive.actions.download'), icon: <Download />, onSelect: () => void download(f) }]
                  : []
              }}
            />
          )}
        </>
      ) : null}
      <p className="mt-auto px-6 py-4 text-center text-xs text-muted-foreground">{t('public.footer')}</p>
    </div>
  )
}
