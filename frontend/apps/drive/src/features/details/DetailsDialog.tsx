import { useQuery } from '@tanstack/react-query'
import { ChevronDown, Info, Loader2, ShieldAlert, ShieldCheck, ShieldQuestion } from 'lucide-react'
import { useState, type ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import type { AccountRef } from '@kutup/crypto/accountRef'
import { useAccountName } from '@kutup/drive-core/accountName'
import type { FolderIndex } from '@kutup/drive-core/folders'
import { useDriveIdentity } from '@kutup/drive-core/identity'
import type { ManifestSignerVerdict } from '@kutup/drive-core/manifestSigners'
import { fileLocation, type DriveFile, type Folder } from '@kutup/drive-core/model'
import { personOf, personOfAccount, usePeople } from '@kutup/drive-core/people'
import type { ClaimedAuthor } from '@kutup/drive-core/revisionAuthors'
import { sharedByMeRowOf, useSharedByMeRows, type SharedByMeRow } from '@kutup/drive-core/sharedByMe'
import { currentContentSignature } from '@kutup/editors/files/signature'
import { fileHistory, holdsYjsState, listVersions, ORIGINAL, type HistoryEntry } from '@kutup/editors/history'
import { useRequiredSession } from '@kutup/session/store'
import { Button } from '@kutup/ui/components/button'
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle } from '@kutup/ui/components/dialog'
import { Tooltip } from '@kutup/ui/components/tooltip'
import { cn } from '@kutup/ui/lib/cn'
import { formatBytes } from '@kutup/ui/lib/format'

/** A folder, or a file with the folder it is in. */
export type DetailsTarget = { folder: Folder; file?: undefined } | { folder: Folder; file: DriveFile }

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
  index: FolderIndex
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
function locationTrail(index: FolderIndex, folder: Folder, labels: { myFiles: string; sharedWithMe: string; encrypted: string }): string {
  const names: string[] = []
  let at: Folder | undefined = folder
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
function useWhere(index: FolderIndex, target: DetailsTarget): string {
  const { t } = useTranslation()
  const labels = { myFiles: t('nav.myFiles'), sharedWithMe: t('nav.shared'), encrypted: t('drive.encrypted') }
  if (target.file) return locationTrail(index, target.folder, labels)
  const { folder } = target
  if (folder.source !== 'owned') return labels.sharedWithMe
  const parent = folder.parentId ? index.byId.get(folder.parentId) : undefined
  return parent ? locationTrail(index, parent, labels) : labels.myFiles
}

/** Someone named by their permanent id: their profile name once they gave it, else their address. */
function AccountName({ account }: { account: AccountRef }) {
  const { t } = useTranslation()
  const address = useAccountName(account)
  const people = usePeople()
  if (address.isPending) return <span className="text-muted-foreground">…</span>
  if (!address.data) return <span className="text-muted-foreground">{t('details.unknownPerson')}</span>
  const { name } = personOfAccount(people.data, account, address.data)
  return <span title={address.data}>{name}</span>
}

/** Someone named by their address (the owner of a folder shared with you). */
function AddressName({ address }: { address: string }) {
  const people = usePeople()
  return <span title={address}>{personOf(people.data, address).name}</span>
}

/** What the owner shares an item with, as the server counts it. */
function SharingText({ row }: { row: SharedByMeRow | undefined }) {
  const { t } = useTranslation()
  if (!row) return <>{t('details.notShared')}</>
  const parts: string[] = []
  const people = row.people + row.otherServers
  if (people > 0) parts.push(t('details.sharedPeople', { count: people }))
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

function FolderDetails({ folder, index }: { folder: Folder; index: FolderIndex }) {
  const { t } = useTranslation()
  const location = useWhere(index, { folder })
  const identity = useDriveIdentity()
  const sharing = useSharedByMeRows()
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
          {owned ? (identity.data?.account ?? '…') : folder.ownerAccount ? <AddressName address={folder.ownerAccount} /> : t('details.unknownPerson')}
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
            {sharing.isPending ? '…' : <SharingText row={sharedByMeRowOf(sharing.data, folder.id)} />}
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

/** A digest as the metadata keeps it (base64), as `sha256sum` prints it; null when it is not one. */
function hexOfBase64(value: string): string | null {
  try {
    return Array.from(atob(value), (c) => c.charCodeAt(0).toString(16).padStart(2, '0')).join('')
  } catch {
    return null
  }
}

/** The revision a history entry is (the original upload's is named by the metadata). */
function revisionOf(file: DriveFile, entry: HistoryEntry): string | null {
  return entry.id === ORIGINAL ? file.originalRevisionId : entry.id
}

/** Who the history says saved an entry, as the signature must agree. */
function claimOf(file: DriveFile, entry: HistoryEntry | undefined): ClaimedAuthor | null {
  if (!entry) return null
  if (entry.id === ORIGINAL) return file.uploaderAccountId ? { accountId: file.uploaderAccountId } : null
  // Someone on another server is named by their server's id there, which the pins can't compare: no claim.
  if (entry.remoteAuthor) return null
  return entry.authorAccountId ? { accountId: entry.authorAccountId } : null
}

function FileDetails({ folder, file, index }: { folder: Folder; file: DriveFile; index: FolderIndex }) {
  const { t, i18n } = useTranslation()
  const session = useRequiredSession()
  const location = useWhere(index, { folder, file })
  const identity = useDriveIdentity()
  const server = identity.data?.accountRef.server
  const sharing = useSharedByMeRows()
  // The history is this server's: a file on another server has none here.
  const local = fileLocation(folder).kind === 'local'
  // Asked again on every open: a replace or an editor's save adds versions without telling this query.
  const versions = useQuery({
    queryKey: ['versions', file.id],
    queryFn: () => listVersions(file.id),
    enabled: local && Boolean(file.fileKey),
    refetchOnMount: 'always',
  })
  const history = versions.data ? fileHistory(file, versions.data) : null
  const current = history?.find((e) => e.current)
  const yjs = holdsYjsState(file.name)
  const checkable = Boolean(file.fileKey && file.content) && !yjs && (!local || (versions.isSuccess && !versions.isFetching) || versions.isError)
  const signature = useQuery({
    queryKey: ['details-signature', file.id, file.content?.revisionId, file.contentKeyGeneration, current?.id ?? null],
    enabled: checkable,
    retry: false,
    staleTime: 60_000,
    queryFn: () =>
      currentContentSignature(folder, file, (revisionId) => {
        if (history) return claimOf(file, history.find((e) => revisionOf(file, e) === revisionId))
        // No history here: the original upload is the uploader's.
        return revisionId === file.originalRevisionId && file.uploaderAccountId ? { accountId: file.uploaderAccountId } : null
      }),
  })

  // People on this server are named by id; on another server only the owner is known by address.
  const accountRef = (accountId: string | null): AccountRef | null =>
    accountId && server && folder.source !== 'remote' ? { server, accountId } : null
  const creator = accountRef(file.uploaderAccountId)
  const remoteOwnerUploaded = folder.source === 'remote' && file.uploaderAccountId === folder.ownerAccountId && folder.ownerAccount
  const lastAuthor: AccountRef | null = current
    ? (current.remoteAuthor ?? accountRef(current.id === ORIGINAL ? file.uploaderAccountId : current.authorAccountId))
    : null
  const lastIsCreator =
    !lastAuthor || (current?.remoteAuthor === null && lastAuthor.accountId === file.uploaderAccountId)
  // What the current content takes on the server, sealed (Proton's "Size"). A
  // note's size in its metadata stays the upload's, so it shows only this one.
  const storedSize = current && current.sizeBytes > 0 ? current.sizeBytes : null
  const owner = folder.ownerAccountId === session.accountId && folder.source === 'owned'
  const fileRow = sharedByMeRowOf(sharing.data, folder.id, file.id)
  const folderRow = sharedByMeRowOf(sharing.data, folder.id)
  // The upload's hash says what the content is only while the server's content hash stands.
  const sha256 = !yjs && file.sha256 && file.contentHash ? hexOfBase64(file.sha256) : null
  const bytes = (n: number) => new Intl.NumberFormat(i18n.language).format(n)

  return (
    <>
      {checkable ? <SignatureBanner pending={signature.isPending} failed={signature.isError} verdict={signature.data?.verdict ?? null} claimed={Boolean(signature.data?.claimed)} hidden={signature.isSuccess && signature.data === null} /> : null}
      <Rows>
        <Row id="name" label={t('details.name')}>
          {file.name ?? t('drive.encrypted')}
        </Row>
        <Row id="location" label={t('details.location')}>
          {location}
        </Row>
        {creator ? (
          <Row id="created-by" label={t('details.createdBy')}>
            <AccountName account={creator} />
          </Row>
        ) : remoteOwnerUploaded ? (
          <Row id="created-by" label={t('details.createdBy')}>
            <AddressName address={folder.ownerAccount!} />
          </Row>
        ) : null}
        {lastAuthor && !lastIsCreator ? (
          <Row id="last-uploaded-by" label={t('details.lastUploadedBy')}>
            <AccountName account={lastAuthor} />
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
        {history ? (
          <Row id="versions" label={t('details.versions')}>
            {history.length}
          </Row>
        ) : null}
        {owner ? (
          <Row id="shared" label={t('details.shared')}>
            {sharing.isPending ? (
              '…'
            ) : (
              <>
                <SharingText row={fileRow} />
                {folderRow && !folder.isRoot ? <span className="block text-xs font-normal text-muted-foreground">{t('details.folderShared')}</span> : null}
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

/**
 * Proton's signature banner: the signature on what the file holds now,
 * checked against the people you know (docs/plans/drive-identity-pins.md).
 */
function SignatureBanner({
  pending,
  failed,
  verdict,
  claimed,
  hidden,
}: {
  pending: boolean
  failed: boolean
  verdict: ManifestSignerVerdict | null
  /** The history names who saved the content, so a good signature is theirs. */
  claimed: boolean
  hidden: boolean
}) {
  const { t } = useTranslation()
  if (hidden) return null
  let tone: 'ok' | 'bad' | 'muted' = 'muted'
  let text: string
  let Icon = ShieldQuestion
  if (pending) {
    text = t('details.signature.checking')
    Icon = Loader2
  } else if (failed || !verdict) {
    text = t('details.signature.failed')
  } else {
    switch (verdict.kind) {
      case 'verified':
        tone = 'ok'
        Icon = ShieldCheck
        text = claimed ? t('details.signature.verified') : t('details.signature.verifiedKey')
        break
      case 'unknown':
        text = t('details.signature.unknown')
        break
      case 'forged':
        tone = 'bad'
        Icon = ShieldAlert
        text = verdict.name ? t('identityCheck.content.forged', { name: verdict.name }) : t('identityCheck.content.forgedUnnamed')
        break
      case 'changed':
        tone = 'bad'
        Icon = ShieldAlert
        text = verdict.name ? t('identityCheck.content.changed', { name: verdict.name }) : t('identityCheck.content.changedUnnamed')
        break
      case 'authorMismatch':
        tone = 'bad'
        Icon = ShieldAlert
        text =
          verdict.name && verdict.claimed
            ? t('identityCheck.content.authorMismatch', { name: verdict.name, claimed: verdict.claimed })
            : verdict.name
              ? t('identityCheck.content.authorMismatchSigner', { name: verdict.name })
              : t('identityCheck.content.authorMismatchUnnamed')
        break
    }
  }
  return (
    <div
      className={cn(
        'mb-4 flex items-start gap-2 rounded-md border px-3 py-2 text-sm',
        tone === 'ok' && 'border-status-ok/40 bg-status-ok/10',
        tone === 'bad' && 'border-destructive/40 bg-destructive/10 text-destructive',
        tone === 'muted' && 'border-border bg-muted text-muted-foreground',
      )}
      role={tone === 'bad' ? 'alert' : undefined}
      data-testid="details-signature"
      data-verdict={pending ? 'pending' : failed || !verdict ? 'failed' : verdict.kind}
    >
      <Icon className={cn('mt-0.5 size-4 shrink-0', pending && 'animate-spin', tone === 'ok' && 'text-status-ok')} aria-hidden />
      <span>{text}</span>
    </div>
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
