import { useQuery } from '@tanstack/react-query'
import { Download, ExternalLink } from 'lucide-react'
import { useEffect, useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useParams } from 'react-router-dom'
import { toast } from 'sonner'
import { opensInOffice } from '@kutup/drive-core/editorKind'
import { PublicNotice } from '@kutup/drive-ui/PublicNotice'
import { publicDocumentUrl } from '@kutup/editors/paths'
import { appUrl, loadAppDirectory } from '@kutup/session/apps'
import { downloadPublicFile, loadShare, publicFailure, type PublicFile } from '@kutup/editors/public/share'
import { Alert } from '@kutup/ui/components/alert'
import { KutupLogo } from '@kutup/ui/components/brand'
import { LocaleToggle } from '@kutup/ui/components/locale-toggle'
import { EmptyState, LoadingPanel } from '@kutup/ui/components/states'
import { ThemeToggle } from '@kutup/ui/components/theme-toggle'
import { Explorer } from '../explorer/Explorer'
import { fileKind } from '@kutup/drive-core/kinds'
import { useExplorerPrefs } from '../explorer/prefs'
import { filterItems, sortItems, type ExplorerItem } from '../explorer/sort'
import { Toolbar } from '../explorer/Toolbar'

/** A link to one document, on Office: the same token and key. */
function officeLinkUrl(token: string): string {
  return appUrl('office', `/s/${encodeURIComponent(token)}${window.location.hash}`)
}

/** A document opens on Office (docs/architecture.md, "File editor route"), the link's key going along. */
function documentUrl(token: string, file: PublicFile): string | null {
  return file.name && file.fileKey && opensInOffice(file.name) ? publicDocumentUrl(token, file.row.id, window.location.hash) : null
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
  const share = useQuery({
    queryKey: ['public-share', token],
    // The app origins first: a document's address on Office comes from them.
    queryFn: async () => (await loadAppDirectory(), loadShare(token)),
    retry: false,
  })
  const files = useMemo(() => share.data?.files ?? [], [share.data])
  // A link to one document: its page is on Office (a link made before it was).
  const single = share.data?.shareType === 'file' ? files[0] : undefined
  const moved = single?.name && opensInOffice(single.name) ? officeLinkUrl(token) : null
  useEffect(() => {
    if (moved) window.location.replace(moved)
  }, [moved])

  const byId = useMemo(() => new Map(files.map((f) => [f.row.id, f])), [files])
  const items: ExplorerItem[] = files.map((f) => ({
    type: 'file',
    id: f.row.id,
    name: f.name ?? t('drive.encrypted'),
    kind: f.name ? fileKind(f.name, f.mimeType) : 'other',
    size: f.name ? f.size : null,
    modifiedAt: f.row.createdAt,
  }))
  const shown = sortItems(filterItems(items, prefs.kinds), prefs.sort, i18n.language)

  async function download(file: PublicFile) {
    try {
      await downloadPublicFile(token, file)
    } catch (error) {
      if (!(error instanceof DOMException && error.name === 'AbortError')) toast.error(t('drive.downloadFailed'))
    }
  }

  /** A document opens on Office; anything else downloads, as before. */
  function open(file: PublicFile) {
    const url = documentUrl(token, file)
    if (url) window.location.assign(url)
    else void download(file)
  }

  const failure = share.isError ? publicFailure(share.error) : null

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
      {share.isPending || moved ? <LoadingPanel label={t('public.decrypting')} /> : null}
      {failure ? (
        <div className="mx-auto w-full max-w-lg p-6">
          <Alert variant="error" title={t(`public.failure.${failure}.title`)}>
            {t(`public.failure.${failure}.description`)}
          </Alert>
        </div>
      ) : null}
      {share.data && !moved ? (
        <>
          <PublicNotice owner={share.data.ownerAccount} />
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
                if (f) open(f)
              }}
              actionsFor={(item) => {
                const f = byId.get(item.id)
                if (!f?.fileKey) return []
                const url = documentUrl(token, f)
                return [
                  ...(url ? [{ id: 'open', label: t('drive.actions.open'), icon: <ExternalLink />, onSelect: () => window.location.assign(url) }] : []),
                  { id: 'download', label: t('drive.actions.download'), icon: <Download />, onSelect: () => void download(f) },
                ]
              }}
            />
          )}
        </>
      ) : null}
      <p className="mt-auto px-6 py-4 text-center text-xs text-muted-foreground">{t('public.footer')}</p>
    </div>
  )
}
