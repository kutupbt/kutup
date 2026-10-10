import { useQuery } from '@tanstack/react-query'
import { ArrowLeft, Download } from 'lucide-react'
import { lazy, Suspense, useCallback, useEffect, useMemo, useRef, type ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import { useParams } from 'react-router-dom'
import { toast } from 'sonner'
import { fetchAsset } from '@kutup/collab/whiteboardAssets'
import { editorKindFor, extensionOf, opensInOffice } from '@kutup/drive-core/editorKind'
import { PublicNotice } from '@kutup/drive-ui/PublicNotice'
import { loadAppDirectory } from '@kutup/session/apps'
import { Alert } from '@kutup/ui/components/alert'
import { KutupLogo } from '@kutup/ui/components/brand'
import { Button } from '@kutup/ui/components/button'
import { LocaleToggle } from '@kutup/ui/components/locale-toggle'
import { LoadingPanel } from '@kutup/ui/components/states'
import { ThemeToggle } from '@kutup/ui/components/theme-toggle'
import { formatBytes } from '@kutup/ui/lib/format'
import { OfficeEditor } from '../dispatch'
import { publicFolderUrl } from '../paths'
import { chooseViewer } from '../viewers/dispatch'
import {
  downloadPublicFile,
  loadShare,
  publicFailure,
  publicFileBase,
  publicFileKeyAt,
  readPublicFile,
  type PublicFile,
  type PublicShare,
} from './share'

const MarkdownPreview = lazy(() => import('../text/markdown/MarkdownPreview'))
const CodeView = lazy(() => import('./CodeView'))
const WhiteboardView = lazy(() => import('./WhiteboardView'))

/** Decrypted content lives in tab memory: anything larger is downloaded instead (as on the file page). */
const MAX_OPEN_BYTES = 100 * 1024 * 1024

/**
 * `/s/:token` and `/s/:token/:fid` on Office: a document reached by a public
 * link — a link to the document itself, or one in a linked folder — shown
 * as it is now, read-only, without an account. Its key is in the address
 * fragment and never reaches the server. A folder's list and anything that
 * is not a document live in Drive (`publicFolderUrl`); a link to one lands
 * there.
 */
export function PublicFilePage() {
  const { token = '', fid } = useParams()
  const share = useQuery({
    queryKey: ['public-share', token],
    // The app origins first: the editor's sandbox and Drive's address come from them.
    queryFn: async () => (await loadAppDirectory(), loadShare(token)),
    retry: false,
  })
  const file = share.data ? pick(share.data, fid) : undefined
  // A file Office does not show (a photo, an archive): Drive's page has it.
  const elsewhere = file ? !file.name || !opensInOffice(file.name) : false

  const toDrive = Boolean(share.data && ((share.data.shareType === 'collection' && !fid) || elsewhere))
  // A folder's list, or a file Office does not show: Drive's page.
  useEffect(() => {
    if (toDrive) {
      window.location.replace(publicFolderUrl(token, window.location.hash))
    }
  }, [toDrive, token])

  if (share.isError) return <Failure failure={publicFailure(share.error)} />
  if (!share.data || toDrive) return <Opening />
  if (!file) return <Failure failure="notFound" />
  return <PublicDocument token={token} share={share.data} file={file} />
}

/** The file the address names: a file link's one file, or `fid` in a folder's. */
function pick(share: PublicShare, fid: string | undefined): PublicFile | undefined {
  return share.shareType === 'file' ? share.files[0] : share.files.find((f) => f.row.id === fid)
}

function Opening() {
  const { t } = useTranslation()
  return (
    <div className="flex min-h-svh items-center justify-center bg-background">
      <LoadingPanel label={t('publicFile.decrypting')} />
    </div>
  )
}

function Failure({ failure }: { failure: ReturnType<typeof publicFailure> }) {
  const { t } = useTranslation()
  return (
    <div className="flex min-h-svh flex-col bg-background">
      <header className="flex h-14 items-center gap-3 border-b border-border px-4 md:px-6">
        <KutupLogo size={22} />
        <span className="ml-auto flex items-center gap-2">
          <LocaleToggle onChrome={false} />
          <ThemeToggle onChrome={false} />
        </span>
      </header>
      <div className="mx-auto w-full max-w-lg p-6">
        <Alert variant="error" title={t(`publicFile.failure.${failure}.title`)}>
          {t(`publicFile.failure.${failure}.description`)}
        </Alert>
      </div>
    </div>
  )
}

function PublicDocument({ token, share, file }: { token: string; share: PublicShare; file: PublicFile }) {
  const { t, i18n } = useTranslation()
  const name = file.name ?? ''
  const tooLarge = file.size > MAX_OPEN_BYTES
  const content = useQuery({
    queryKey: ['public-file', token, file.row.id],
    queryFn: ({ signal }) => readPublicFile(token, file, signal),
    enabled: !tooLarge,
    retry: false,
    staleTime: Infinity,
  })

  useEffect(() => {
    const previous = document.title
    document.title = `${name} · Kutup`
    return () => {
      document.title = previous
    }
  }, [name])

  async function download() {
    try {
      await downloadPublicFile(token, file)
    } catch (error) {
      if (!(error instanceof DOMException && error.name === 'AbortError')) toast.error(t('file.downloadFailed'))
    }
  }

  let body: ReactNode
  if (tooLarge) {
    body = (
      <Centered>
        <p className="text-sm text-muted-foreground">
          {t('file.tooLarge', { size: formatBytes(file.size, i18n.language), limit: formatBytes(MAX_OPEN_BYTES, i18n.language) })}
        </p>
        <Button onClick={() => void download()}>
          <Download /> {t('file.actions.download')}
        </Button>
      </Centered>
    )
  } else if (content.isError) {
    body = (
      <Centered>
        <Alert variant="error" title={t('publicFile.failure.other.title')}>
          {t('publicFile.failure.other.description')}
        </Alert>
      </Centered>
    )
  } else if (!content.data) {
    body = <LoadingPanel label={t('publicFile.decrypting')} />
  } else {
    body = <Shown token={token} file={file} bytes={content.data} />
  }

  return (
    <div className="flex h-svh flex-col overflow-hidden bg-background">
      <header className="flex h-12 shrink-0 items-center gap-2 border-b border-border px-2 sm:px-3">
        {share.shareType === 'collection' ? (
          <Button variant="ghost" size="icon" asChild>
            <a href={publicFolderUrl(token, window.location.hash)} aria-label={t('publicFile.backToFolder')} title={t('publicFile.backToFolder')}>
              <ArrowLeft />
            </a>
          </Button>
        ) : null}
        <KutupLogo size={22} className="hidden shrink-0 sm:block" />
        <span className="min-w-0 truncate px-1.5 text-sm font-medium">{name}</span>
        <div className="ml-auto flex shrink-0 items-center gap-1.5">
          <Button variant="ghost" size="icon" onClick={() => void download()} title={t('file.actions.download')} aria-label={t('file.actions.download')}>
            <Download />
          </Button>
          <LocaleToggle onChrome={false} />
          <ThemeToggle onChrome={false} />
        </div>
      </header>
      <PublicNotice owner={share.ownerAccount} />
      <main className="min-h-0 flex-1">
        <Suspense fallback={<LoadingPanel label={t('file.opening')} />}>{body}</Suspense>
      </main>
    </div>
  )
}

function Centered({ children }: { children: ReactNode }) {
  return (
    <div className="flex h-full items-center justify-center p-6">
      <div className="max-w-md space-y-4 text-center">{children}</div>
    </div>
  )
}

/** The document in the viewer its kind needs, all read-only. */
function Shown({ token, file, bytes }: { token: string; file: PublicFile; bytes: Uint8Array }) {
  const name = file.name ?? ''
  const kind = editorKindFor(name)
  const fileKeyAt = useCallback((generation: number) => publicFileKeyAt(file, generation), [file])
  const assetBase = publicFileBase(token, file.row.id)
  if (kind === 'office' && file.currentKey) {
    return (
      <OfficeEditor
        live={false}
        readOnly
        fileId={file.row.id}
        filename={name}
        fileKey={file.currentKey}
        keyGeneration={file.row.keyGeneration}
        fileKeyAt={fileKeyAt}
        initialBytes={bytes}
      />
    )
  }
  if (kind === 'whiteboard' && file.currentKey) {
    return (
      <WhiteboardView
        fileId={file.row.id}
        fileKey={file.currentKey}
        keyGeneration={file.row.keyGeneration}
        fileKeyAt={fileKeyAt}
        assetBase={assetBase}
        bytes={bytes}
      />
    )
  }
  if (kind === 'text') {
    const text = new TextDecoder().decode(bytes)
    const ext = extensionOf(name)
    return ext === 'md' || ext === 'markdown' ? <Note file={file} assetBase={assetBase} text={text} /> : <CodeView filename={name} text={text} />
  }
  return <PdfView name={name} bytes={bytes} />
}

/** A note, rendered; its own pictures open through the link. */
function Note({ file, assetBase, text }: { file: PublicFile; assetBase: string; text: string }) {
  const urls = useRef<string[]>([])
  useEffect(
    () => () => {
      for (const url of urls.current) URL.revokeObjectURL(url)
    },
    [],
  )
  const resolveAsset = useCallback(
    async (assetId: string) => {
      if (!file.currentKey) return null
      try {
        const plain = await fetchAsset(
          { fileId: file.row.id, assetId, generation: file.row.keyGeneration },
          file.currentKey,
          (generation) => publicFileKeyAt(file, generation),
          assetBase,
        )
        const url = URL.createObjectURL(new Blob([plain as BlobPart]))
        urls.current.push(url)
        return url
      } catch {
        return null
      }
    },
    [file, assetBase],
  )
  return <MarkdownPreview source={text} resolveAsset={resolveAsset} className="h-full" />
}

function PdfView({ name, bytes }: { name: string; bytes: Uint8Array }) {
  const viewer = chooseViewer(name)
  const url = useMemo(() => URL.createObjectURL(new Blob([bytes as BlobPart], { type: 'application/pdf' })), [bytes])
  useEffect(() => () => URL.revokeObjectURL(url), [url])
  return viewer ? <viewer.Component filename={name} blobUrl={url} mimeType={viewer.mimeType} /> : null
}

