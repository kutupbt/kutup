import { Download, ExternalLink, FolderOpen, Info } from 'lucide-react'
import { BlobDownloadTooLarge } from '@kutup/files/download/streamDownload'
import { useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { toast } from 'sonner'
import { EmptyState, LoadingPanel } from '@kutup/ui/components/states'
import { folderHex } from '../drive/colors'
import { downloadFile, downloadFolderZip, FsaRequiredError } from '@kutup/editors/files/downloads'
import type { FolderIndex } from '@kutup/drive-core/folders'
import type { DriveFile, Folder } from '@kutup/drive-core/model'
import { folderPath, openFile } from '@kutup/editors/paths'
import { Explorer, type ExplorerAction } from '../explorer/Explorer'
import { useExplorerPrefs } from '../explorer/prefs'
import { filterItems, itemKey, sortItems, type ExplorerItem } from '../explorer/sort'
import { Toolbar } from '../explorer/Toolbar'
import { FileThumbnail } from '../thumbnails/FileThumbnail'
import { matches, terms } from '@kutup/editors/search'
import { useDriveIndex } from '@kutup/editors/driveIndex'
import { sharedByMeRowOf, useSharedByMeRows } from '@kutup/drive-core/sharedByMe'
import { useRequiredSession } from '@kutup/session/store'
import { DetailsDialog } from '../details/DetailsDialog'
import { FilterBar } from './FilterBar'
import { activeFilters, filtersFromParams, passesFilters, withFilters, type FilterSubject } from './filters'

type Hit = { folder: Folder; file?: undefined } | { folder: Folder; file: DriveFile }

/** "My files › Projects › 2024", or the shared folder's name for shared items. */
function trail(index: FolderIndex, folder: Folder, myFiles: string): string {
  if (folder.source !== 'owned') return folder.name ?? ''
  const names: string[] = []
  let at: Folder | undefined = folder
  while (at && !at.isRoot) {
    names.unshift(at.name ?? '…')
    at = at.parentId ? index.byId.get(at.parentId) : undefined
  }
  return [myFiles, ...names].join(' › ')
}

/**
 * Search results: every folder and file whose name has all the words of the
 * query, from all of My files and everything shared with you, in the
 * toolbar's order. Each says where it lives.
 */
export function SearchPage() {
  const { t, i18n } = useTranslation()
  const navigate = useNavigate()
  const [params, setParams] = useSearchParams()
  const query = params.get('q') ?? ''
  const filters = useMemo(() => filtersFromParams(params), [params])
  const filtering = activeFilters(filters) > 0
  const session = useRequiredSession()
  const me = session.accountId
  const { index, files, loading } = useDriveIndex(true)
  // What this account shares, for the "Shared by me" filter.
  const sharing = useSharedByMeRows()
  const [prefs, updatePrefs] = useExplorerPrefs()
  const [selection, setSelection] = useState<Set<string>>(new Set())
  const [details, setDetails] = useState<Hit | null>(null)

  const { items, hits } = useMemo(() => {
    const hits = new Map<string, Hit>()
    const items: ExplorerItem[] = []
    if (!index) return { items, hits }
    const now = new Date()
    const rows = sharing.data
    // A folder's creator is its owner; a file's, its uploader (on this server: another server's ids are its own).
    const folderSubject = (folder: Folder): FilterSubject => ({
      modifiedAt: folder.updatedAt,
      owned: folder.source === 'owned',
      createdByMe: folder.source !== 'remote' && folder.ownerAccountId === me,
      sharedByMe: folder.source === 'owned' && Boolean(sharedByMeRowOf(rows, folder.id)),
    })
    const fileSubject = (folder: Folder, file: DriveFile): FilterSubject => ({
      modifiedAt: file.updatedAt,
      owned: folder.source === 'owned',
      createdByMe: folder.source !== 'remote' && file.uploaderAccountId === me,
      sharedByMe: folder.source === 'owned' && Boolean(sharedByMeRowOf(rows, folder.id, file.id)),
    })
    const q = terms(query)
    for (const folder of index.all) {
      if (folder.isRoot || !folder.name || !matches(folder.name, q)) continue
      if (!passesFilters(folderSubject(folder), filters, now)) continue
      const item: ExplorerItem = {
        type: 'folder',
        id: folder.remoteShareId ?? folder.id,
        name: folder.name,
        kind: 'folder',
        size: null,
        modifiedAt: folder.updatedAt,
        color: folderHex(folder.color),
      }
      items.push(item)
      hits.set(itemKey(item), { folder })
    }
    for (const { folder, file } of files) {
      if (!matches(file.name!, q)) continue
      if (!passesFilters(fileSubject(folder, file), filters, now)) continue
      const item: ExplorerItem = {
        type: 'file',
        id: file.id,
        name: file.name!,
        kind: file.kind,
        size: file.size,
        modifiedAt: file.updatedAt,
      }
      items.push(item)
      hits.set(itemKey(item), { folder, file })
    }
    return { items, hits }
  }, [index, files, query, filters, sharing.data, me])

  const shown = useMemo(
    () => sortItems(filterItems(items, prefs.kinds), prefs.sort, i18n.language),
    [items, prefs.kinds, prefs.sort, i18n.language],
  )

  const containerOf = (hit: Hit): Folder | undefined =>
    hit.file ? hit.folder : hit.folder.parentId ? index?.byId.get(hit.folder.parentId) : undefined

  const open = (item: ExplorerItem) => {
    const hit = hits.get(itemKey(item))
    if (!hit) return
    if (!hit.file) {
      if (hit.folder.key) void navigate(folderPath(hit.folder))
    } else if (hit.folder.source === 'remote') {
      void save(hit)
    } else {
      openFile(navigate, hit.folder, hit.file)
    }
  }

  async function save(hit: Hit) {
    try {
      if (hit.file) await downloadFile(hit.folder, hit.file)
      else if ((await downloadFolderZip(hit.folder, () => {})) === 'empty') toast.info(t('drive.zipEmpty'))
    } catch (error) {
      if (error instanceof DOMException && error.name === 'AbortError') return
      toast.error(
          error instanceof FsaRequiredError
            ? t('drive.zipTooLarge')
            : error instanceof BlobDownloadTooLarge
              ? t('drive.fileTooLargeForBrowser')
              : t('drive.downloadFailed'),
        )
    }
  }

  const actionsFor = (item: ExplorerItem): ExplorerAction[] => {
    const hit = hits.get(itemKey(item))
    if (!hit) return []
    const actions: ExplorerAction[] = [
      { id: 'open', label: t('drive.actions.open'), icon: <ExternalLink />, onSelect: () => open(item) },
    ]
    const container = containerOf(hit)
    if (container) {
      actions.push({
        id: 'show',
        label: t('search.showInFolder'),
        icon: <FolderOpen />,
        onSelect: () => void navigate(folderPath(container)),
      })
    }
    actions.push({
      id: 'download',
      label: hit.file ? t('drive.actions.download') : t('drive.actions.downloadZip'),
      icon: <Download />,
      onSelect: () => void save(hit),
    })
    actions.push({ id: 'details', label: t('drive.actions.details'), icon: <Info />, onSelect: () => setDetails(hit), separated: true })
    return actions
  }

  return (
    <div className="relative flex min-h-[calc(100svh-3.5rem)] flex-col">
      <div className="sticky top-14 z-20 flex min-h-12 flex-wrap items-center gap-2 border-b border-border bg-background/95 px-3 py-1.5 backdrop-blur-sm md:px-6">
        <h1 className="min-w-0 flex-1 truncate text-sm font-medium" aria-live="polite">
          {loading ? t('search.searching', { query }) : t('search.results', { count: shown.length, query })}
        </h1>
        <Toolbar prefs={prefs} update={updatePrefs} />
      </div>
      <FilterBar
        filters={filters}
        onChange={(next) => setParams(withFilters(params, next), { replace: true })}
      />
      {shown.length === 0 ? (
        loading || (filters.sharedByMe && sharing.isPending) ? (
          <LoadingPanel label={t('search.searching', { query })} />
        ) : (
          <EmptyState title={t('search.noneTitle')} description={filtering ? t('search.noneFiltered', { query }) : t('search.none', { query })} />
        )
      ) : (
        <Explorer
          items={shown}
          view={prefs.view}
          sort={prefs.sort}
          onSortField={(field) =>
            updatePrefs(
              field === prefs.sort.field
                ? { dir: prefs.sort.dir === 'asc' ? 'desc' : 'asc' }
                : { field, dir: field === 'name' || field === 'type' ? 'asc' : 'desc' },
            )
          }
          selection={selection}
          onSelectionChange={setSelection}
          onOpen={open}
          actionsFor={actionsFor}
          renderPreview={
            prefs.showPreviews
              ? (item) => {
                  const hit = hits.get(itemKey(item))
                  return hit?.file ? <FileThumbnail folder={hit.folder} file={hit.file} /> : null
                }
              : undefined
          }
          subtitleFor={(item) => {
            const hit = hits.get(itemKey(item))
            const where = hit && index ? containerOf(hit) : undefined
            return where && index ? trail(index, where, t('nav.myFiles')) : null
          }}
        />
      )}
      {index ? <DetailsDialog targets={details ? [details] : null} index={index} onClose={() => setDetails(null)} /> : null}
    </div>
  )
}
