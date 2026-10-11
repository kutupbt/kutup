import { Download, ExternalLink, FolderOpen } from 'lucide-react'
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
  const [params] = useSearchParams()
  const query = params.get('q') ?? ''
  const { index, files, loading } = useDriveIndex(true)
  const [prefs, updatePrefs] = useExplorerPrefs()
  const [selection, setSelection] = useState<Set<string>>(new Set())

  const { items, hits } = useMemo(() => {
    const hits = new Map<string, Hit>()
    const items: ExplorerItem[] = []
    if (!index) return { items, hits }
    const q = terms(query)
    for (const folder of index.all) {
      if (folder.isRoot || !folder.name || !matches(folder.name, q)) continue
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
  }, [index, files, query])

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
      toast.error(error instanceof FsaRequiredError ? t('drive.zipTooLarge') : t('drive.downloadFailed'))
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
      {shown.length === 0 ? (
        loading ? (
          <LoadingPanel label={t('search.searching', { query })} />
        ) : (
          <EmptyState title={t('search.noneTitle')} description={t('search.none', { query })} />
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
    </div>
  )
}
