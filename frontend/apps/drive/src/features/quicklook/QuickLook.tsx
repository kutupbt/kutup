import { ChevronLeft, ChevronRight, Download, ExternalLink } from 'lucide-react'
import { lazy, Suspense, useEffect, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Button } from '@kutup/ui/components/button'
import { Dialog, DialogContent, DialogDescription, DialogTitle } from '@kutup/ui/components/dialog'
import { LoadingPanel } from '@kutup/ui/components/states'
import { formatBytes, formatInstant } from '@kutup/ui/lib/format'
import { readFile } from '../drive/copy'
import type { DriveFile, Folder } from '@kutup/drive-core/model'
import { editorKindFor, extensionOf } from '../editor/editorKind'
import { chooseViewer } from '../editor/viewers/dispatch'
import { KindIcon } from '../explorer/KindIcon'
import { thumbnailUrl } from '../thumbnails/store'

const MarkdownPreview = lazy(() => import('../editor/text/markdown/MarkdownPreview'))

/** Quick Look decrypts in memory; beyond this, open or download instead. */
const MAX_PREVIEW_BYTES = 100 * 1024 * 1024
/** Text beyond this is cut: a preview, not the editor. */
const MAX_TEXT_BYTES = 512 * 1024

export interface QuickLookTarget {
  folder: Folder
  file: DriveFile
}

type Loaded =
  | { kind: 'viewer'; url: string; mimeType: string }
  | { kind: 'text'; text: string; markdown: boolean; cut: boolean }
  /** The file's large thumbnail, where there is no viewer or the file is too big. */
  | { kind: 'picture'; url: string; reason: 'type' | 'size' }
  | { kind: 'none'; reason: 'type' | 'size' | 'failed' }

/**
 * A look at a file without leaving the folder (Space, as in Finder and
 * Dolphin): images, PDFs, audio and video in their viewers, notes and code
 * as text, anything else as its icon with Open. ← and → step through the
 * folder's files; Space or Escape closes.
 */
export function QuickLook({
  target,
  onClose,
  onStep,
  onOpen,
  onDownload,
}: {
  target: QuickLookTarget | null
  onClose: () => void
  /** Move to the previous (-1) or next (+1) file; absent at the ends. */
  onStep?: (direction: -1 | 1) => void
  onOpen: (target: QuickLookTarget) => void
  onDownload: (target: QuickLookTarget) => void
}) {
  const { t, i18n } = useTranslation()
  const [loaded, setLoaded] = useState<Loaded | null>(null)
  const content = useRef<HTMLDivElement>(null)
  const file = target?.file

  useEffect(() => {
    if (!target) return
    const { folder, file: f } = target
    let cancelled = false
    let url: string | null = null
    setLoaded(null)
    const name = f.name ?? ''
    const viewer = chooseViewer(name)
    const text = editorKindFor(name) === 'text'
    // No viewer, or too large to decrypt whole: its large thumbnail if it
    // has one (cached blob: URLs are owned by the thumbnail store).
    const fallback = (reason: 'type' | 'size') =>
      void thumbnailUrl(f, 'lg').then((picture) => {
        if (!cancelled) setLoaded(picture ? { kind: 'picture', url: picture, reason } : { kind: 'none', reason })
      })
    if (!viewer && !text) {
      fallback('type')
      return () => {
        cancelled = true
      }
    }
    if (f.size > MAX_PREVIEW_BYTES) {
      fallback('size')
      return () => {
        cancelled = true
      }
    }
    const controller = new AbortController()
    readFile(folder, f, controller.signal)
      .then(async (blob) => {
        if (cancelled) return
        if (viewer) {
          url = URL.createObjectURL(new Blob([blob], { type: viewer.mimeType }))
          setLoaded({ kind: 'viewer', url, mimeType: viewer.mimeType })
        } else {
          const ext = extensionOf(name)
          const body = await blob.slice(0, MAX_TEXT_BYTES).text()
          if (!cancelled) {
            setLoaded({ kind: 'text', text: body, markdown: ext === 'md' || ext === 'markdown', cut: blob.size > MAX_TEXT_BYTES })
          }
        }
      })
      .catch(() => {
        if (!cancelled) setLoaded({ kind: 'none', reason: 'failed' })
      })
    return () => {
      cancelled = true
      controller.abort()
      if (url) URL.revokeObjectURL(url)
    }
  }, [target])

  // An embedded viewer (the browser's PDF viewer) takes the keyboard when it
  // loads, and then Space and the arrows stop reaching Quick Look. Take it
  // back once; clicking into the document still gives it the keys.
  useEffect(() => {
    const el = content.current
    if (!el || loaded?.kind !== 'viewer') return
    const reclaim = (event: Event) => {
      if (event.target instanceof HTMLIFrameElement) setTimeout(() => content.current?.focus(), 0)
    }
    el.addEventListener('load', reclaim, true)
    return () => el.removeEventListener('load', reclaim, true)
  }, [loaded])

  const viewer = file?.name ? chooseViewer(file.name) : null

  return (
    <Dialog open={target !== null} onOpenChange={(o) => !o && onClose()}>
      <DialogContent
        ref={content}
        // Focus the dialog itself, not its first button: Space closes a
        // Quick Look, it must not press "Open".
        onOpenAutoFocus={(e) => {
          e.preventDefault()
          content.current?.focus()
        }}
        className="flex h-[90dvh] max-h-none max-w-[min(94vw,80rem)] flex-col gap-0 overflow-hidden p-0"
        onKeyDown={(e) => {
          if (e.key === 'ArrowLeft' && onStep) {
            e.preventDefault()
            onStep(-1)
          } else if (e.key === 'ArrowRight' && onStep) {
            e.preventDefault()
            onStep(1)
          } else if (e.key === ' ' && !(e.target as HTMLElement).closest('button, a, video, audio')) {
            e.preventDefault()
            onClose()
          }
        }}
      >
        {target && file ? (
          <>
            <header className="flex min-h-14 shrink-0 items-center gap-3 border-b border-border py-2 pl-4 pr-12">
              <KindIcon kind={file.kind} className="size-6" />
              <div className="min-w-0 flex-1">
                <DialogTitle className="truncate text-sm font-medium">{file.name}</DialogTitle>
                <DialogDescription className="truncate text-xs text-muted-foreground">
                  {formatBytes(file.size, i18n.language)} · {formatInstant(file.updatedAt, i18n.language)}
                </DialogDescription>
              </div>
              {target.folder.source !== 'remote' ? (
                <Button size="sm" variant="outline" onClick={() => onOpen(target)}>
                  <ExternalLink />
                  <span className="hidden sm:inline">{t('drive.actions.open')}</span>
                </Button>
              ) : null}
              <Button size="sm" variant="outline" onClick={() => onDownload(target)}>
                <Download />
                <span className="hidden sm:inline">{t('drive.actions.download')}</span>
              </Button>
            </header>
            <div className="relative min-h-0 flex-1 bg-muted/40">
              {loaded === null ? (
                <div className="flex h-full items-center justify-center">
                  <LoadingPanel label={t('quickLook.loading')} />
                </div>
              ) : loaded.kind === 'viewer' && viewer ? (
                <viewer.Component filename={file.name ?? ''} blobUrl={loaded.url} mimeType={loaded.mimeType} />
              ) : loaded.kind === 'picture' ? (
                <div className="flex h-full flex-col items-center justify-center gap-3 p-4">
                  <img src={loaded.url} alt={file.name ?? ''} className="min-h-0 max-w-full flex-1 object-contain shadow-sm" draggable={false} />
                  <p className="text-xs text-muted-foreground">{t(`quickLook.picture.${loaded.reason}`)}</p>
                </div>
              ) : loaded.kind === 'text' ? (
                <div className="flex h-full flex-col">
                  {loaded.markdown ? (
                    <Suspense fallback={<LoadingPanel label={t('quickLook.loading')} />}>
                      <MarkdownPreview source={loaded.text} className="mx-auto h-full w-full max-w-3xl bg-card" />
                    </Suspense>
                  ) : (
                    <pre className="h-full overflow-auto bg-card p-4 font-mono text-xs leading-relaxed">{loaded.text}</pre>
                  )}
                  {loaded.cut ? (
                    <p className="shrink-0 border-t border-border bg-card px-4 py-2 text-xs text-muted-foreground">
                      {t('quickLook.cut')}
                    </p>
                  ) : null}
                </div>
              ) : (
                <div className="flex h-full flex-col items-center justify-center gap-4 p-6 text-center">
                  <KindIcon kind={file.kind} className="size-24" />
                  <p className="max-w-sm text-sm text-muted-foreground">
                    {loaded.kind === 'none' ? t(`quickLook.none.${loaded.reason}`) : null}
                  </p>
                  {target.folder.source !== 'remote' && loaded.kind === 'none' && loaded.reason === 'type' && editorKindFor(file.name ?? '') ? (
                    <Button onClick={() => onOpen(target)}>
                      <ExternalLink />
                      {t('quickLook.openInEditor')}
                    </Button>
                  ) : null}
                </div>
              )}
              {onStep ? (
                <>
                  <Button
                    variant="outline"
                    size="icon"
                    className="absolute left-3 top-1/2 -translate-y-1/2 rounded-full bg-background/90 shadow-sm"
                    aria-label={t('quickLook.previous')}
                    onClick={() => onStep(-1)}
                  >
                    <ChevronLeft />
                  </Button>
                  <Button
                    variant="outline"
                    size="icon"
                    className="absolute right-3 top-1/2 -translate-y-1/2 rounded-full bg-background/90 shadow-sm"
                    aria-label={t('quickLook.next')}
                    onClick={() => onStep(1)}
                  >
                    <ChevronRight />
                  </Button>
                </>
              ) : null}
            </div>
          </>
        ) : null}
      </DialogContent>
    </Dialog>
  )
}
