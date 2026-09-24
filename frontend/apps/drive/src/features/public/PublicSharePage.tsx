import { useQuery } from '@tanstack/react-query'
import { Download } from 'lucide-react'
import { useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useParams } from 'react-router-dom'
import { toast } from 'sonner'
import { fromBase64, openFileRecordV1, openPublicLinkCollectionKeyV1 } from '@kutup/crypto'
import { unlockCollectionKeyring, type EpochLinkV1 } from '@kutup/crypto/collectionKeyring'
import { DRIVE_ENVELOPE_PURPOSE, openDriveEnvelope } from '@kutup/crypto/driveEnvelope'
import { streamDownload } from '@kutup/files/download/streamDownload'
import { resolveApiBase } from '@kutup/session/apiBase'
import api from '@kutup/session/client'
import { Alert } from '@kutup/ui/components/alert'
import { KutupLogo } from '@kutup/ui/components/brand'
import { LocaleToggle } from '@kutup/ui/components/locale-toggle'
import { EmptyState, LoadingPanel } from '@kutup/ui/components/states'
import { ThemeToggle } from '@kutup/ui/components/theme-toggle'
import { apiErrorCode } from '@kutup/ui/lib/apiError'
import { Explorer } from '../explorer/Explorer'
import { fileKind } from '../explorer/kinds'
import { useExplorerPrefs } from '../explorer/prefs'
import { filterItems, sortItems, type ExplorerItem } from '../explorer/sort'
import { Toolbar } from '../explorer/Toolbar'

interface ShareInfo {
  targetId: string
  collectionKeyEnvelope: string
  collectionKeyEpoch: number
  ownerUserId: string
  /** Signs the folder's key history. */
  ownerAuthorityPublicKey: string
  expiresAt?: string | null
}

interface PublicFileRow {
  id: string
  collectionId: string
  metadataEnvelope: string
  fileKeyEnvelope: string
  keyEpoch: number
  metadataRevision: number
  createdAt: string
  /** The epoch of what a download serves (docs/plans/drive-share-revocation.md). */
  contentKeyEpoch: number
  keyHistory?: { epoch: number; fileKeyEnvelope: string }[]
}

interface PublicFile {
  row: PublicFileRow
  /** The key the downloaded content opens with (at `row.contentKeyEpoch`). */
  fileKey: Uint8Array | null
  name: string | null
  mimeType: string
  size: number
}

type Failure = 'missingKey' | 'notFound' | 'expired' | 'badKey' | 'other'

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
      // What a download serves may be sealed under a key the file left behind.
      const history = (row.keyHistory ?? []).find((h) => h.epoch === row.contentKeyEpoch)
      const contentKey =
        !opened || row.contentKeyEpoch === row.keyEpoch
          ? (opened?.fileKey ?? null)
          : history
            ? await keyAt(history.epoch)
                .then((key) =>
                  openDriveEnvelope(history.fileKeyEnvelope, key, {
                    purpose: DRIVE_ENVELOPE_PURPOSE.fileKey,
                    epoch: history.epoch,
                    revision: 1n,
                    objectId: row.id,
                    parentId: row.collectionId,
                  }),
                )
                .catch(() => null)
            : null
      return {
        row,
        fileKey: contentKey,
        name: opened?.metadata.name ?? null,
        mimeType: opened?.metadata.mimeType ?? 'application/octet-stream',
        size: opened?.metadata.size ?? 0,
      }
    }),
  )
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
      await streamDownload({
        url: `${await resolveApiBase()}/share/${encodeURIComponent(token)}/download/${file.row.id}`,
        fileKey: file.fileKey,
        context: { fileId: file.row.id, collectionId: file.row.collectionId, epoch: file.row.contentKeyEpoch },
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
