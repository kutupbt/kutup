import { ArrowDownAZ, Clock, Plus, Search } from 'lucide-react'
import { useEffect, useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import type { DriveFile } from '@kutup/drive-core/model'
import { DOCUMENT_KINDS, type DocumentKind } from '@kutup/drive-core/documents'
import { thumbnailUrl } from '@kutup/drive-core/thumbnails'
import { KindIcon } from '@kutup/drive-ui/KindIcon'
import { appUrl } from '@kutup/session/apps'
import { Alert } from '@kutup/ui/components/alert'
import { Button } from '@kutup/ui/components/button'
import { Input } from '@kutup/ui/components/input'
import { PageBody } from '@kutup/ui/components/page'
import { EmptyState, LoadingPanel, Spinner } from '@kutup/ui/components/states'
import { filterDocuments, sortDocuments, useCreateDocument, useDocuments, type DocumentEntry, type DocumentOrder } from './documents'

/** The picture the editor drew of the document the last time it was saved. */
function Preview({ file, kind }: { file: DriveFile; kind: DocumentKind }) {
  const [url, setUrl] = useState<string | null>(null)
  const stamp = file.thumbnails.lg ?? file.thumbnails.sm
  useEffect(() => {
    let alive = true
    setUrl(null)
    void thumbnailUrl(file, file.thumbnails.lg ? 'lg' : 'sm').then((u) => alive && setUrl(u))
    return () => {
      alive = false
    }
    // The stamp changes when a new picture is stored.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [file.id, stamp])
  if (url) return <img src={url} alt="" className="size-full object-cover object-top" draggable={false} />
  return <KindIcon kind={kind} className="size-14" />
}

function DocumentCard({ entry, when }: { entry: DocumentEntry; when: string }) {
  const { t } = useTranslation()
  const name = entry.file.name ?? t('home.unnamed')
  return (
    <li>
      <a
        href={entry.href}
        data-testid="office-document"
        className="group flex h-full flex-col overflow-hidden rounded-lg border border-border bg-card transition-colors hover:border-primary/50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
      >
        <span className="flex aspect-[4/3] items-center justify-center overflow-hidden border-b border-border bg-muted/40">
          <Preview file={entry.file} kind={entry.kind} />
        </span>
        <span className="flex min-w-0 flex-col gap-1 p-3">
          <span className="truncate text-sm font-medium" title={name}>
            {name}
          </span>
          <span className="flex min-w-0 items-center gap-1.5 text-xs text-muted-foreground">
            <KindIcon kind={entry.kind} className="size-4" />
            <span className="truncate">
              {entry.owner ? t('home.changedBy', { when, owner: entry.owner }) : t('home.changed', { when })}
            </span>
          </span>
        </span>
      </a>
    </li>
  )
}

/** Start a new document, and every one you can open, most recently changed first. */
export function HomePage({ kind = null }: { kind?: DocumentKind | null }) {
  const { t, i18n } = useTranslation()
  const { root, documents, loading, error } = useDocuments()
  const createDocument = useCreateDocument()
  const [creating, setCreating] = useState<DocumentKind | null>(null)
  const [order, setOrder] = useState<DocumentOrder>('recent')
  const [query, setQuery] = useState('')
  const shown = useMemo(
    () => sortDocuments(filterDocuments(documents, kind, query, i18n.language), order, i18n.language),
    [documents, kind, query, order, i18n.language],
  )
  const date = useMemo(() => new Intl.DateTimeFormat(i18n.language, { dateStyle: 'medium' }), [i18n.language])
  const canCreate = Boolean(root?.key && root.canUpload)

  async function create(type: DocumentKind) {
    if (!root) return
    setCreating(type)
    try {
      window.location.assign(await createDocument(root, type, t(`home.untitled.${type}`)))
    } catch {
      toast.error(t('home.createFailed'))
      setCreating(null)
    }
  }

  return (
    <PageBody>
      <section aria-labelledby="office-new" className="mb-8">
        <h2 id="office-new" className="mb-3 font-display text-lg font-semibold">
          {t('home.startNew')}
        </h2>
        <ul className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-3">
          {(kind ? [kind] : DOCUMENT_KINDS).map((type) => (
            <li key={type}>
              <button
                type="button"
                disabled={!canCreate || creating !== null}
                onClick={() => void create(type)}
                data-testid={`office-new-${type}`}
                className="flex w-full items-center gap-3 rounded-lg border border-border bg-card p-4 text-left transition-colors hover:border-primary/50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring disabled:cursor-not-allowed disabled:opacity-60"
              >
                {creating === type ? (
                  <span className="flex size-11 shrink-0 items-center justify-center">
                    <Spinner label={t('home.creating')} />
                  </span>
                ) : (
                  <KindIcon kind={type} className="size-11" />
                )}
                <span className="min-w-0">
                  <span className="flex items-center gap-1 text-sm font-medium">
                    <Plus className="size-3.5 shrink-0" aria-hidden />
                    {t(`home.blank.${type}`)}
                  </span>
                  <span className="mt-0.5 block text-xs text-muted-foreground">{t('home.savedTo')}</span>
                </span>
              </button>
            </li>
          ))}
        </ul>
      </section>

      <section aria-labelledby="office-recent">
        <div className="mb-3 flex flex-wrap items-center gap-3">
          <h2 id="office-recent" className="mr-auto font-display text-lg font-semibold">
            {t(`home.recent.${kind ?? 'all'}`)}
          </h2>
          <div className="relative w-full sm:w-64">
            <Search className="pointer-events-none absolute left-2.5 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" aria-hidden />
            <Input
              type="search"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder={t('home.search')}
              aria-label={t('home.search')}
              className="pl-8"
            />
          </div>
          <Button
            variant="outline"
            size="sm"
            onClick={() => setOrder(order === 'recent' ? 'name' : 'recent')}
            data-testid="office-order"
          >
            {order === 'recent' ? <Clock /> : <ArrowDownAZ />}
            {t(`home.order.${order}`)}
          </Button>
        </div>

        {error ? (
          <Alert variant="error" title={t('home.loadFailedTitle')}>
            {t('home.loadFailed')}
          </Alert>
        ) : loading && documents.length === 0 ? (
          <LoadingPanel label={t('home.loading')} />
        ) : shown.length === 0 ? (
          <EmptyState
            title={query.trim() ? t('home.noMatchTitle') : t('home.emptyTitle')}
            description={query.trim() ? t('home.noMatch') : t('home.empty')}
            action={
              query.trim() ? undefined : (
                <Button variant="outline" asChild>
                  <a href={appUrl('drive')}>{t('home.openDrive')}</a>
                </Button>
              )
            }
          />
        ) : (
          <ul className="grid grid-cols-2 gap-4 md:grid-cols-3 xl:grid-cols-5" data-testid="office-documents">
            {shown.map((entry) => (
              <DocumentCard key={entry.file.id} entry={entry} when={date.format(new Date(entry.file.updatedAt))} />
            ))}
          </ul>
        )}
      </section>
    </PageBody>
  )
}
