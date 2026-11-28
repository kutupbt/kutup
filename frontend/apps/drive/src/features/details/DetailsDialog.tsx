import { ChevronDown, Info } from 'lucide-react'
import { useState, type ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import { useDriveSource } from '@kutup/drive-source/context'
import type { FileView, FolderTree, FolderView, PersonLookup, SharingSummary } from '@kutup/drive-source/source'
import { holdsYjsState } from '@kutup/editors/history'
import { useRequiredSession } from '@kutup/session/store'
import { Button } from '@kutup/ui/components/button'
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle } from '@kutup/ui/components/dialog'
import { Tooltip } from '@kutup/ui/components/tooltip'
import { cn } from '@kutup/ui/lib/cn'
import { formatBytes } from '@kutup/ui/lib/format'

/** A folder, or a file with the folder it is in. */
export type DetailsTarget = { folder: FolderView; file?: undefined } | { folder: FolderView; file: FileView }

/**
 * An item's details (Proton Drive's `DetailsModal`): for a file its name,
 * location, who created and last uploaded it, when, its type, sizes,
 * versions, whether its owner shares it, and whether the signature on what
 * it holds now checks out; for a folder the same where they apply; for
 * several items their number and size (Proton's `FilesDetailsModal`).
 *
 * Everything comes from what this browser decrypted or the server already
 * says (sizes, dates, ids, who uploaded); nothing is shown that Kutup
 * cannot vouch for.
 */
export function DetailsDialog({
  targets,
  index,
  onClose,
}: {
  targets: DetailsTarget[] | null
  index: FolderTree
  onClose: () => void
}) {
  const { t } = useTranslation()
  const only = targets?.length === 1 ? targets[0] : undefined
  const title = !only ? t('details.titleItems') : only.file ? t('details.titleFile') : t('details.titleFolder')
  return (
    <Dialog open={targets !== null} onOpenChange={(open) => !open && onClose()}>
      <DialogContent className="flex max-h-[85dvh] max-w-lg flex-col gap-4" data-testid="details">
        <DialogHeader>
          <DialogTitle>{title}</DialogTitle>
        </DialogHeader>
        <div className="-mx-6 min-h-0 flex-1 overflow-y-auto px-6">
          {only?.file ? (
            <FileDetails folder={only.folder} file={only.file} index={index} />
          ) : only ? (
            <FolderDetails folder={only.folder} index={index} />
          ) : targets ? (
            <SelectionDetails targets={targets} />
          ) : null}
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>
            {t('common.close')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

function Rows({ children }: { children: ReactNode }) {
  return <dl className="grid grid-cols-[minmax(7rem,auto)_1fr] gap-x-4 gap-y-2 text-sm">{children}</dl>
}

function Row({ id, label, hint, children }: { id: string; label: string; hint?: string; children: ReactNode }) {
  return (
    <>
      <dt className="flex items-center gap-1 text-muted-foreground">
        {label}
        {hint ? (
          <Tooltip label={hint}>
            <button type="button" className="text-muted-foreground hover:text-foreground" aria-label={hint}>
              <Info className="size-3.5" aria-hidden />
            </button>
          </Tooltip>
        ) : null}
      </dt>
      <dd className="min-w-0 break-words font-medium" data-testid={`details-${id}`}>
        {children}
      </dd>
    </>
  )
}

function When({ at }: { at: string }) {
  const { i18n } = useTranslation()
  const date = new Date(at)
  return (
    <time dateTime={at} title={date.toLocaleString(i18n.language)}>
      {new Intl.DateTimeFormat(i18n.language, { dateStyle: 'medium', timeStyle: 'short' }).format(date)}
    </time>
  )
}

/** "My files › Projects", "Shared with me › Their folder": where `folder` is, itself included. */
function locationTrail(index: FolderTree, folder: FolderView, labels: { myFiles: string; sharedWithMe: string; encrypted: string }): string {
  const names: string[] = []
  let at: FolderView | undefined = folder
  const owned = folder.source === 'owned'
  while (at && !at.isRoot) {
    names.unshift(at.name ?? labels.encrypted)
    // Someone else's folder is reached by itself: its parents are theirs.
    if (at.source !== 'owned') break
    at = at.parentId ? index.byId.get(at.parentId) : undefined
  }
  return [owned ? labels.myFiles : labels.sharedWithMe, ...names].join(' › ')
}

/** Where an item is: a file in its folder; a folder in its parent. */
function useWhere(index: FolderTree, target: DetailsTarget): string {
  const { t } = useTranslation()
  const labels = { myFiles: t('nav.myFiles'), sharedWithMe: t('nav.shared'), encrypted: t('drive.encrypted') }
  if (target.file) return locationTrail(index, target.folder, labels)
  const { folder } = target
  if (folder.source !== 'owned') return labels.sharedWithMe
  const parent = folder.parentId ? index.byId.get(folder.parentId) : undefined
  return parent ? locationTrail(index, parent, labels) : labels.myFiles
}

/** Someone as the source names them: a name, with the address as its tooltip. */
function Person({ who }: { who: PersonLookup }) {
  const { t } = useTranslation()
  if (who === 'pending') return <span className="text-muted-foreground">…</span>
  if (who === 'unknown') return <span className="text-muted-foreground">{t('details.unknownPerson')}</span>
  return <span title={who.address}>{who.name}</span>
}

/** What the owner shares an item with, as the server counts it. */
function SharingText({ row }: { row: SharingSummary | null }) {
  const { t } = useTranslation()
  if (!row) return <>{t('details.notShared')}</>
  const parts: string[] = []
  if (row.people > 0) parts.push(t('details.sharedPeople', { count: row.people }))
  if (row.links > 0) parts.push(t('details.sharedLinks', { count: row.links }))
  return <>{parts.length > 0 ? parts.join(' · ') : t('details.notShared')}</>
}

function Advanced({ children }: { children: ReactNode }) {
  const { t } = useTranslation()
  const [open, setOpen] = useState(false)
  return (
    <div className="mt-4 border-t border-border pt-3">
      <button
        type="button"
        className="flex w-full items-center justify-between text-sm font-medium"
        aria-expanded={open}
        onClick={() => setOpen(!open)}
        data-testid="details-advanced"
      >
        {t('details.advanced')}
        <ChevronDown className={cn('size-4 transition-transform', open && 'rotate-180')} aria-hidden />
      </button>
      {open ? <div className="mt-3">{children}</div> : null}
    </div>
  )
}

function FolderDetails({ folder, index }: { folder: FolderView; index: FolderTree }) {
  const { t } = useTranslation()
  const source = useDriveSource()
  const location = useWhere(index, { folder })
  const creator = source.useFolderCreator(folder)
  const sharing = source.useSharingSummary(folder)
  const owned = folder.source === 'owned'
  const name = folder.isRoot ? t('nav.myFiles') : (folder.name ?? t('drive.encrypted'))
  return (
    <>
      <Rows>
        <Row id="name" label={t('details.name')}>
          {name}
        </Row>
        {!folder.isRoot ? (
          <Row id="location" label={t('details.location')}>
            {location}
          </Row>
        ) : null}
        <Row id="created-by" label={t('details.createdBy')}>
          <Person who={creator} />
        </Row>
        {folder.source === 'remote' ? (
          // A share from another server says when it was shared, not when the folder was made.
          <Row id="shared-at" label={t('details.sharedWithYou')}>
            <When at={folder.createdAt} />
          </Row>
        ) : (
          <>
            <Row id="created" label={t('details.created')}>
              <When at={folder.createdAt} />
            </Row>
            <Row id="modified" label={t('details.modified')}>
              <When at={folder.updatedAt} />
            </Row>
          </>
        )}
        <Row id="type" label={t('details.type')}>
          {t('details.kinds.folder')}
        </Row>
        {folder.canManage && !folder.isRoot ? (
          <Row id="shared" label={t('details.shared')}>
            {sharing === undefined ? '…' : <SharingText row={sharing} />}
          </Row>
        ) : null}
        {!owned ? (
          <Row id="access" label={t('details.access')}>
            {folder.canDelete ? t('details.accessDelete') : folder.canUpload ? t('details.accessEdit') : t('details.accessView')}
          </Row>
        ) : null}
      </Rows>
      <Advanced>
        <Rows>
          <Row id="id" label={t('details.id')}>
            <span className="font-mono text-xs">{folder.id}</span>
          </Row>
        </Rows>
      </Advanced>
    </>
  )
}

function FileDetails({ folder, file, index }: { folder: FolderView; file: FileView; index: FolderTree }) {
  const { t, i18n } = useTranslation()
  const session = useRequiredSession()
  const source = useDriveSource()
  const location = useWhere(index, { folder, file })
  const details = source.useFileDetails(folder, file)
  const sharing = source.useSharingSummary(folder, file)
  const Banner = source.DetailsBanner
  const yjs = holdsYjsState(file.name)
  const { storedSize, sha256 } = details
  const owner = folder.ownerAccountId === session.accountId && folder.source === 'owned'
  const bytes = (n: number) => new Intl.NumberFormat(i18n.language).format(n)

  return (
    <>
      {Banner ? <Banner folder={folder} file={file} /> : null}
      <Rows>
        <Row id="name" label={t('details.name')}>
          {file.name ?? t('drive.encrypted')}
        </Row>
        <Row id="location" label={t('details.location')}>
          {location}
        </Row>
        {details.createdBy ? (
          <Row id="created-by" label={t('details.createdBy')}>
            <Person who={details.createdBy} />
          </Row>
        ) : null}
        {details.lastUploadedBy ? (
          <Row id="last-uploaded-by" label={t('details.lastUploadedBy')}>
            <Person who={details.lastUploadedBy} />
          </Row>
        ) : null}
        <Row id="uploaded" label={t('details.uploaded')}>
          <When at={file.createdAt} />
        </Row>
        <Row id="modified" label={t('details.modified')}>
          <When at={file.updatedAt} />
        </Row>
        <Row id="type" label={t('details.type')}>
          {t(`details.kinds.${file.kind}`)}
        </Row>
        {file.mimeType ? (
          <Row id="media-type" label={t('details.mediaType')}>
            <span className="font-mono text-xs">{file.mimeType}</span>
          </Row>
        ) : null}
        {storedSize !== null ? (
          <Row id="size" label={t('details.size')} hint={t('details.sizeHint')}>
            {formatBytes(storedSize, i18n.language)}
          </Row>
        ) : null}
        {!yjs && file.name ? (
          <Row id="original-size" label={t('details.originalSize')}>
            {formatBytes(file.size, i18n.language)}
          </Row>
        ) : null}
        {details.versions !== null ? (
          <Row id="versions" label={t('details.versions')}>
            {details.versions}
          </Row>
        ) : null}
        {owner ? (
          <Row id="shared" label={t('details.shared')}>
            {sharing === undefined ? (
              '…'
            ) : (
              <>
                <SharingText row={sharing} />
                {sharing?.folderShared ? <span className="block text-xs font-normal text-muted-foreground">{t('details.folderShared')}</span> : null}
              </>
            )}
          </Row>
        ) : null}
      </Rows>
      <Advanced>
        <Rows>
          {storedSize !== null ? (
            <Row id="size-bytes" label={t('details.sizeBytes')}>
              {bytes(storedSize)}
            </Row>
          ) : null}
          {!yjs && file.name ? (
            <Row id="original-size-bytes" label={t('details.originalSizeBytes')}>
              {bytes(file.size)}
            </Row>
          ) : null}
          {sha256 ? (
            <Row id="sha256" label={t('details.sha256')}>
              <span className="break-all font-mono text-xs">{sha256}</span>
            </Row>
          ) : null}
          <Row id="id" label={t('details.id')}>
            <span className="font-mono text-xs">{file.id}</span>
          </Row>
        </Rows>
      </Advanced>
    </>
  )
}

function SelectionDetails({ targets }: { targets: DetailsTarget[] }) {
  const { t, i18n } = useTranslation()
  const files = targets.flatMap((target) => (target.file ? [target.file] : []))
  const folders = targets.length - files.length
  // A note's metadata keeps its upload's size, not its text's now: it is left out, as folders are.
  const size = files.reduce((sum, file) => sum + (file.name && !holdsYjsState(file.name) ? file.size : 0), 0)
  return (
    <Rows>
      <Row id="count" label={t('details.count')}>
        {targets.length}
        <span className="block text-xs font-normal text-muted-foreground">
          {t('details.countFiles', { count: files.length })} · {t('details.countFolders', { count: folders })}
        </span>
      </Row>
      <Row id="total-size" label={t('details.totalSize')} hint={t('details.totalSizeHint')}>
        {formatBytes(size, i18n.language)}
      </Row>
    </Rows>
  )
}
