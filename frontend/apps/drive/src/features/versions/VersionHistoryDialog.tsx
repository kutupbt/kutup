import { useQuery, useQueryClient } from '@tanstack/react-query'
import { Download, Eye, ExternalLink, Loader2, MoreVertical, Pin, PinOff, RotateCcw, Trash2 } from 'lucide-react'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Link } from 'react-router-dom'
import { toast } from 'sonner'
import { useAccountName } from '@kutup/drive-core/accountName'
import { editorKindFor } from '@kutup/drive-core/editorKind'
import { useDriveIdentity } from '@kutup/drive-core/identity'
import type { DriveFile, Folder } from '@kutup/drive-core/model'
import { personOfAccount, usePeople } from '@kutup/drive-core/people'
import { readRevision } from '@kutup/editors/content'
import { downloadRevision } from '@kutup/editors/files/downloads'
import {
  deleteVersion,
  fileHistory,
  groupHistory,
  holdsYjsState,
  listVersions,
  mayDeleteEntry,
  ORIGINAL,
  patchVersion,
  type HistoryEntry,
  type HistoryGroup,
} from '@kutup/editors/history'
import { chooseViewer } from '@kutup/editors/viewers/dispatch'
import { BlobDownloadTooLarge } from '@kutup/files/download/streamDownload'
import api from '@kutup/session/client'
import { useRequiredSession } from '@kutup/session/store'
import {
  AlertDialog,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '@kutup/ui/components/alert-dialog'
import { Alert } from '@kutup/ui/components/alert'
import { Button } from '@kutup/ui/components/button'
import { ConfirmDestructive } from '@kutup/ui/components/confirm-destructive'
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from '@kutup/ui/components/dialog'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@kutup/ui/components/dropdown-menu'
import { formatBytes } from '@kutup/ui/lib/format'
import { apiErrorMessage } from '@kutup/ui/lib/apiError'
import { canReplace, replaceContent } from '../../source/kutup/uploads/replace'
import { thumbnailAfterUpload } from '../../source/kutup/thumbnails/schedule'
import type { QuickLookTarget } from '../quicklook/QuickLook'

/** The periods with a name of their own (as Drive → Settings names them). */
const NAMED_RETENTION_DAYS: ReadonlySet<number> = new Set([7, 30, 90, 180, 365, 3650])

export interface VersionHistoryTarget {
  folder: Folder
  file: DriveFile
}

/** The query of a file's version rows. */
const versionsKey = (fileId: string) => ['versions', fileId] as const

/**
 * A file's version history (Proton Drive's "Version history"): the current
 * version, then the earlier ones by day, week, month and year, each with
 * preview, restore, download and delete; and, for the owner, how long
 * earlier versions are kept.
 *
 * Restoring seals the chosen revision again as the file's newest version
 * (its content records are bound to their own revision), so every other
 * version stays in the history. A note's saved state is restored in its
 * editor, which merges it into the live document.
 */
export function VersionHistoryDialog({
  target,
  onClose,
  onPreview,
  onOpen,
}: {
  target: VersionHistoryTarget | null
  onClose: () => void
  onPreview: (target: QuickLookTarget) => void
  onOpen: (target: VersionHistoryTarget) => void
}) {
  const { t } = useTranslation()
  const file = target?.file
  return (
    <Dialog open={target !== null} onOpenChange={(open) => !open && onClose()}>
      <DialogContent className="flex max-h-[85dvh] max-w-xl flex-col gap-4" data-testid="version-history">
        <DialogHeader>
          <DialogTitle>{t('versions.title')}</DialogTitle>
          <DialogDescription className="truncate">{file?.name}</DialogDescription>
        </DialogHeader>
        {target ? <HistoryBody target={target} onPreview={onPreview} onOpen={onOpen} /> : null}
      </DialogContent>
    </Dialog>
  )
}

function HistoryBody({
  target,
  onPreview,
  onOpen,
}: {
  target: VersionHistoryTarget
  onPreview: (target: QuickLookTarget) => void
  onOpen: (target: VersionHistoryTarget) => void
}) {
  const { t, i18n } = useTranslation()
  const session = useRequiredSession()
  const queryClient = useQueryClient()
  const { folder, file } = target
  const versions = useQuery({ queryKey: versionsKey(file.id), queryFn: () => listVersions(file.id) })
  const owner = folder.ownerAccountId === session.accountId
  const [restoring, setRestoring] = useState<HistoryEntry | null>(null)
  const [restorePending, setRestorePending] = useState(false)
  const [deleting, setDeleting] = useState<HistoryEntry | null>(null)
  const [deletePending, setDeletePending] = useState(false)
  const [deleteError, setDeleteError] = useState<unknown>(null)

  if (versions.isPending) {
    return (
      <div className="flex items-center justify-center gap-2 p-8 text-sm text-muted-foreground">
        <Loader2 className="size-4 animate-spin" aria-hidden />
        {t('versions.loading')}
      </div>
    )
  }
  if (versions.isError) return <Alert variant="error">{apiErrorMessage(versions.error, t('versions.loadFailed'))}</Alert>

  const history = fileHistory(file, versions.data)
  const current = history.find((e) => e.current)
  const earlier = history.filter((e) => !e.current)
  const yjs = holdsYjsState(file.name)
  const previewable = Boolean(file.name && (chooseViewer(file.name) || editorKindFor(file.name) === 'text'))
  const mayRestore = !yjs && canReplace(folder, file)

  const refresh = () =>
    Promise.all([
      queryClient.invalidateQueries({ queryKey: versionsKey(file.id) }),
      queryClient.invalidateQueries({ queryKey: ['files'] }),
    ])

  const when = (entry: HistoryEntry) =>
    new Intl.DateTimeFormat(i18n.language, { dateStyle: 'long', timeStyle: 'short' }).format(new Date(entry.createdAt))

  const actions: RowActions = {
    preview: previewable
      ? (entry) =>
          onPreview({
            folder,
            file,
            revision: entry.current ? undefined : { ...entry, authorAccountId: entry.authorAccountId },
          })
      : undefined,
    download: async (entry) => {
      try {
        await downloadRevision(file, entry)
      } catch (error) {
        if (error instanceof DOMException && error.name === 'AbortError') return
        toast.error(error instanceof BlobDownloadTooLarge ? t('drive.fileTooLargeForBrowser') : t('versions.downloadFailed'))
      }
    },
    restore: mayRestore ? setRestoring : undefined,
    openInEditor: yjs && folder.canUpload ? () => onOpen(target) : undefined,
    keep: folder.canUpload
      ? async (entry) => {
          try {
            await patchVersion(file.id, entry.id, { keepForever: !entry.keepForever })
            await queryClient.invalidateQueries({ queryKey: versionsKey(file.id) })
          } catch (error) {
            toast.error(apiErrorMessage(error, t('versions.updateFailed')))
          }
        }
      : undefined,
    remove: (entry) => (mayDeleteEntry(entry, history, session.accountId, folder.ownerAccountId) ? () => setDeleting(entry) : undefined),
  }

  async function restore(entry: HistoryEntry) {
    if (!file.name) return
    setRestorePending(true)
    const id = toast.loading(t('versions.restoring'))
    try {
      const blob = await readRevision(file, entry)
      const restored = new File([blob], file.name, { type: file.mimeType })
      const outcome = await replaceContent(folder, file, restored, { signal: new AbortController().signal })
      if ('done' in outcome) {
        thumbnailAfterUpload(outcome.done, restored)
        toast.success(t('versions.restored'), { id })
        setRestoring(null)
        await refresh()
      } else {
        toast.error(t(`versions.restoreProblem.${outcome.problem}`), { id })
      }
    } catch (error) {
      toast.error(apiErrorMessage(error, t('versions.restoreFailed')), { id })
    } finally {
      setRestorePending(false)
    }
  }

  async function remove(entry: HistoryEntry) {
    setDeletePending(true)
    setDeleteError(null)
    try {
      await deleteVersion(file.id, entry.id)
      setDeleting(null)
      toast.success(t('versions.deleted'))
      await refresh()
    } catch (error) {
      setDeleteError(error)
    } finally {
      setDeletePending(false)
    }
  }

  return (
    <>
      {owner ? <RetentionBanner /> : null}
      <div className="-mx-6 min-h-0 flex-1 overflow-y-auto px-6">
        {current ? (
          <section data-testid="version-current">
            <h3 className="text-sm font-semibold">{t('versions.current')}</h3>
            <ul className="mt-2">
              <VersionItem entry={current} format="auto" actions={actions} />
            </ul>
          </section>
        ) : null}
        {earlier.length > 0 ? (
          groupHistory(earlier).map((group) => (
            <section key={group.key} className="mt-4" data-testid="version-group">
              <h3 className="text-sm font-semibold text-muted-foreground">{groupTitle(group, t, i18n.language)}</h3>
              <ul className="mt-2">
                {group.entries.map((entry) => (
                  <VersionItem
                    key={entry.id}
                    entry={entry}
                    format={group.kind === 'today' || group.kind === 'yesterday' ? 'time' : 'date'}
                    actions={actions}
                  />
                ))}
              </ul>
            </section>
          ))
        ) : (
          <p className="mt-4 text-sm text-muted-foreground">{t('versions.none')}</p>
        )}
      </div>

      <AlertDialog open={restoring !== null} onOpenChange={(open) => !open && !restorePending && setRestoring(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{t('versions.restoreTitle')}</AlertDialogTitle>
            <AlertDialogDescription>
              {restoring ? t('versions.restoreDescription', { name: file.name, date: when(restoring) }) : null}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={restorePending}>{t('common.cancel')}</AlertDialogCancel>
            <Button disabled={restorePending} onClick={() => restoring && void restore(restoring)} data-testid="version-restore-confirm">
              {restorePending ? <Loader2 className="animate-spin" aria-hidden /> : <RotateCcw />}
              {t('versions.restoreSubmit')}
            </Button>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
      <ConfirmDestructive
        open={deleting !== null}
        onOpenChange={(open) => {
          if (!open) {
            setDeleting(null)
            setDeleteError(null)
          }
        }}
        title={t('versions.deleteTitle')}
        description={deleting ? t('versions.deleteDescription', { name: file.name, date: when(deleting) }) : ''}
        warning={deleting?.keepForever ? t('versions.deleteKept') : t('versions.deleteWarning')}
        submit={t('versions.deleteSubmit')}
        pending={deletePending}
        error={deleteError}
        errorFallback={t('versions.deleteFailed')}
        onConfirm={() => deleting && void remove(deleting)}
      />
    </>
  )
}

interface RowActions {
  preview?: (entry: HistoryEntry) => void
  download: (entry: HistoryEntry) => Promise<void>
  restore?: (entry: HistoryEntry) => void
  openInEditor?: () => void
  keep?: (entry: HistoryEntry) => Promise<void>
  /** The delete action for `entry`, when this account may delete it. */
  remove: (entry: HistoryEntry) => (() => void) | undefined
}

function groupTitle(group: HistoryGroup, t: (key: string) => string, locale: string): string {
  switch (group.kind) {
    case 'today':
      return t('versions.groups.today')
    case 'yesterday':
      return t('versions.groups.yesterday')
    case 'lastWeek':
      return t('versions.groups.lastWeek')
    case 'weekday':
      return new Intl.DateTimeFormat(locale, { weekday: 'long' }).format(group.date)
    case 'month':
      return new Intl.DateTimeFormat(locale, { month: 'long' }).format(group.date)
    case 'year':
      return new Intl.DateTimeFormat(locale, { year: 'numeric' }).format(group.date)
  }
}

function VersionItem({ entry, format, actions }: { entry: HistoryEntry; format: 'auto' | 'time' | 'date'; actions: RowActions }) {
  const { t, i18n } = useTranslation()
  const at = new Date(entry.createdAt)
  const sameDay = at.toDateString() === new Date().toDateString()
  const options: Intl.DateTimeFormatOptions =
    format === 'time' || (format === 'auto' && sameDay)
      ? { hour: 'numeric', minute: 'numeric' }
      : { month: 'short', day: 'numeric', year: at.getFullYear() === new Date().getFullYear() ? undefined : 'numeric' }
  const remove = actions.remove(entry)
  return (
    <li
      className="flex items-center gap-3 rounded-md px-2 py-2 hover:bg-accent/40"
      data-testid="version-row"
      data-version={entry.id}
      data-current={entry.current ? 'true' : undefined}
    >
      <div className="min-w-0 flex-1">
        <div className="flex flex-wrap items-center gap-2 text-sm">
          <time dateTime={entry.createdAt} title={at.toLocaleString(i18n.language)} className="font-medium">
            {new Intl.DateTimeFormat(i18n.language, options).format(at)}
          </time>
          {entry.label ? <span className="truncate text-muted-foreground">{entry.label}</span> : null}
          {entry.id === ORIGINAL ? (
            <span className="rounded-full bg-muted px-2 py-0.5 text-[10px] font-medium text-muted-foreground">{t('versions.original')}</span>
          ) : null}
          {entry.keepForever ? (
            <span className="inline-flex items-center gap-1 rounded-full bg-primary/15 px-2 py-0.5 text-[10px] font-medium text-primary">
              <Pin className="size-2.5" aria-hidden /> {t('versions.kept')}
            </span>
          ) : null}
        </div>
        <div className="mt-0.5 flex min-w-0 items-center gap-1 text-xs text-muted-foreground">
          <AuthorName entry={entry} />
          {entry.sizeBytes > 0 ? <span className="shrink-0">· {formatBytes(entry.sizeBytes, i18n.language)}</span> : null}
        </div>
      </div>
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Button variant="ghost" size="icon" aria-label={t('versions.more')} data-testid="version-menu">
            <MoreVertical />
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end">
          {actions.preview ? (
            <DropdownMenuItem onSelect={() => actions.preview?.(entry)} data-testid="version-preview">
              <Eye /> {t('versions.preview')}
            </DropdownMenuItem>
          ) : null}
          {!entry.current && actions.restore ? (
            <DropdownMenuItem onSelect={() => actions.restore?.(entry)} data-testid="version-restore">
              <RotateCcw /> {t('versions.restore')}
            </DropdownMenuItem>
          ) : null}
          {!entry.current && actions.openInEditor ? (
            <DropdownMenuItem onSelect={() => actions.openInEditor?.()} data-testid="version-open-editor">
              <ExternalLink /> {t('versions.restoreInEditor')}
            </DropdownMenuItem>
          ) : null}
          <DropdownMenuItem onSelect={() => void actions.download(entry)} data-testid="version-download">
            <Download /> {t('versions.download')}
          </DropdownMenuItem>
          {actions.keep && entry.id !== ORIGINAL ? (
            <DropdownMenuItem onSelect={() => void actions.keep?.(entry)} data-testid="version-keep">
              {entry.keepForever ? <PinOff /> : <Pin />} {entry.keepForever ? t('versions.unkeep') : t('versions.keep')}
            </DropdownMenuItem>
          ) : null}
          {remove ? (
            <>
              <DropdownMenuSeparator />
              <DropdownMenuItem destructive onSelect={remove} data-testid="version-delete">
                <Trash2 /> {t('versions.delete')}
              </DropdownMenuItem>
            </>
          ) : null}
        </DropdownMenuContent>
      </DropdownMenu>
    </li>
  )
}

/** Who saved a revision: their profile name once they gave it, else their address. */
function AuthorName({ entry }: { entry: HistoryEntry }) {
  const { t } = useTranslation()
  const identity = useDriveIdentity()
  const server = identity.data?.accountRef.server
  const account =
    entry.remoteAuthor ?? (entry.authorAccountId && server ? { server, accountId: entry.authorAccountId } : null)
  const address = useAccountName(account)
  const people = usePeople()
  const name = account && address.data ? personOfAccount(people.data, account, address.data).name : null
  return <span className="truncate">{name ?? t('versions.unknownAuthor')}</span>
}

/** How long the owner's earlier versions are kept, with a way to change it (Proton's `RevisionsSettingsBanner`). */
function RetentionBanner() {
  const { t } = useTranslation()
  const me = useQuery({
    queryKey: ['me'],
    queryFn: async () =>
      (await api.get<{ versionRetentionDays: number; versionRetentionChoices: number[] }>('/account')).data,
  })
  if (!me.data) return null
  const days = me.data.versionRetentionDays
  const period = NAMED_RETENTION_DAYS.has(days) ? t(`settings.versions.retention.d${days}`) : t('settings.versions.retention.days', { count: days })
  return (
    <div className="flex items-center justify-between gap-3 rounded-md bg-muted/60 px-3 py-2" data-testid="version-retention">
      <p className="text-xs text-muted-foreground">{t('versions.retention', { period })}</p>
      <Button asChild size="sm" variant="outline">
        <Link to="/settings">{t('versions.change')}</Link>
      </Button>
    </div>
  )
}
