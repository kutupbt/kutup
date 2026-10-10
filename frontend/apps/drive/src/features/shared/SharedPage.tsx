import { Download, ExternalLink, LogOut, Pencil, Plus, UserPlus } from 'lucide-react'
import { useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useNavigate } from 'react-router-dom'
import { toast } from 'sonner'
import { Alert } from '@kutup/ui/components/alert'
import { Button } from '@kutup/ui/components/button'
import { ConfirmDestructive } from '@kutup/ui/components/confirm-destructive'
import { EmptyState, LoadingPanel } from '@kutup/ui/components/states'
import { apiErrorMessage } from '@kutup/ui/lib/apiError'
import { downloadFile, downloadFolderZip } from '@kutup/editors/files/downloads'
import { useLeaveRemoteFileShare, useSharedFiles, type SharedFile } from '@kutup/drive-core/fileShares'
import { useRenameFile } from '@kutup/drive-core/mutations'
import { FileShareDialog } from '@kutup/drive-ui/FileShareDialog'
import { NameDialog } from '@kutup/drive-ui/NameDialog'
import { useFolders } from '@kutup/drive-core/folders'
import type { Folder } from '@kutup/drive-core/model'
import { useLeaveRemoteShare } from '@kutup/drive-core/mutations'
import { folderPath, openFile } from '@kutup/editors/paths'
import { personOf, usePeople } from '@kutup/drive-core/people'
import { PersonLabel } from '../people/PersonLabel'
import { Explorer } from '../explorer/Explorer'
import { useExplorerPrefs } from '../explorer/prefs'
import { filterItems, sortItems, type ExplorerItem } from '../explorer/sort'
import { Toolbar } from '../explorer/Toolbar'
import { AcceptInviteDialog } from './AcceptInviteDialog'

/**
 * What other people shared with you: folders, here or from other Kutup
 * servers, and single files (docs/plans/drive-file-sharing.md).
 */
export function SharedPage() {
  const { t, i18n } = useTranslation()
  const navigate = useNavigate()
  const folders = useFolders()
  const sharedFiles = useSharedFiles()
  const [prefs, updatePrefs] = useExplorerPrefs()
  const [selection, setSelection] = useState<Set<string>>(new Set())
  const [inviting, setInviting] = useState(false)
  const [leaving, setLeaving] = useState<Folder | null>(null)
  const leave = useLeaveRemoteShare()
  const rename = useRenameFile()
  const leaveFile = useLeaveRemoteFileShare()
  const [leavingFile, setLeavingFile] = useState<SharedFile | null>(null)
  // By id: the file's key and name refresh while a dialog is open.
  const [sharing, setSharing] = useState<string | null>(null)
  const [renaming, setRenaming] = useState<string | null>(null)
  const people = usePeople()

  const byId = useMemo(() => new Map((folders.data?.sharedWithMe ?? []).map((f) => [f.remoteShareId ?? f.id, f])), [folders.data])
  const filesById = useMemo(() => new Map((sharedFiles.data ?? []).map((s) => [s.file.id, s])), [sharedFiles.data])
  const items: ExplorerItem[] = useMemo(
    () => [
      ...(folders.data?.sharedWithMe ?? []).map((f) => ({
        type: 'folder' as const,
        id: f.remoteShareId ?? f.id,
        name: f.name ?? t('drive.encrypted'),
        kind: 'folder' as const,
        size: null,
        modifiedAt: f.updatedAt,
      })),
      ...(sharedFiles.data ?? []).map((s) => ({
        type: 'file' as const,
        id: s.file.id,
        name: s.file.name ?? (s.state === 'waiting' ? t('shared.waitingName') : s.state === 'gone' ? t('shared.goneName') : t('drive.encrypted')),
        kind: s.file.kind,
        size: s.file.name ? s.file.size : null,
        modifiedAt: s.file.updatedAt,
      })),
    ],
    [folders.data, sharedFiles.data, t],
  )
  const shown = sortItems(filterItems(items, prefs.kinds), prefs.sort, i18n.language)

  function downloadShared(s: SharedFile) {
    return downloadFile(s.container, s.file).catch(
      (e: unknown) => !(e instanceof DOMException && e.name === 'AbortError') && toast.error(t('drive.downloadFailed')),
    )
  }

  if (folders.isPending || sharedFiles.isPending) return <LoadingPanel label={t('common.loading')} />

  return (
    <div className="flex min-h-[calc(100svh-3.5rem)] flex-col">
      <div className="sticky top-14 z-20 flex min-h-12 flex-wrap items-center gap-2 border-b border-border bg-background/95 px-3 py-1.5 backdrop-blur-sm md:px-6">
        <h1 className="min-w-0 flex-1 font-display text-lg font-semibold">{t('nav.shared')}</h1>
        <Button variant="outline" size="sm" onClick={() => setInviting(true)}>
          <Plus />
          {t('shared.addInvite')}
        </Button>
        <Toolbar prefs={prefs} update={updatePrefs} />
      </div>
      {folders.isError || sharedFiles.isError ? (
        <div className="p-4"><Alert variant="error">{apiErrorMessage(folders.error ?? sharedFiles.error, t('drive.loadFailed'))}</Alert></div>
      ) : null}
      {shown.length === 0 ? (
        <EmptyState title={t('shared.emptyTitle')} description={t('shared.emptyDescription')} />
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
          subtitleFor={(item) => {
            if (item.type === 'file') {
              const s = filesById.get(item.id)
              if (!s) return null
              const from = <PersonLabel account={s.ownerAccount} format={(name) => t('shared.from', { account: name })} />
              return s.state === 'gone' ? (
                <>{from} · {t('shared.gone')}</>
              ) : s.state === 'waiting' ? (
                <>{from} · {t('shared.waiting')}</>
              ) : s.state === 'editsWait' && s.canEdit ? (
                <>{from} · {t('shared.editsWait')}</>
              ) : (
                from
              )
            }
            const f = byId.get(item.id)
            return f?.ownerAccount ? (
              <PersonLabel account={f.ownerAccount} format={(name) => t('shared.from', { account: name })} />
            ) : null
          }}
          onOpen={(item) => {
            if (item.type === 'file') {
              const s = filesById.get(item.id)
              if (s?.file.fileKey) openFile(navigate, s.container, s.file)
              else if (s?.state === 'waiting') toast.info(t('shared.waitingHint'))
              return
            }
            const f = byId.get(item.id)
            if (f?.key) void navigate(folderPath(f))
          }}
          actionsFor={(item) => {
            if (item.type === 'file') {
              const s = filesById.get(item.id)
              const leave = s?.remoteShareId
                ? [{ id: 'leave', label: t('shared.remove'), icon: <LogOut />, onSelect: () => setLeavingFile(s), destructive: true, separated: true }]
                : []
              if (!s?.file.fileKey) return leave
              return [
                { id: 'open', label: t('drive.actions.open'), icon: <ExternalLink />, onSelect: () => openFile(navigate, s.container, s.file) },
                {
                  id: 'download',
                  label: t('drive.actions.download'),
                  icon: <Download />,
                  onSelect: () => void downloadShared(s),
                },
                ...leave,
                // An editor renames, and shares on when the owner lets them.
                ...(s.canEdit && s.state === 'ready'
                  ? [{ id: 'rename', label: t('drive.actions.rename'), icon: <Pencil />, onSelect: () => setRenaming(s.file.id), separated: true }]
                  : []),
                ...(s.canShare ? [{ id: 'share', label: t('drive.actions.share'), icon: <UserPlus />, onSelect: () => setSharing(s.file.id) }] : []),
              ]
            }
            const f = byId.get(item.id)
            if (!f?.key) return []
            return [
              { id: 'open', label: t('drive.actions.open'), icon: <ExternalLink />, onSelect: () => void navigate(folderPath(f)) },
              {
                id: 'download',
                label: t('drive.actions.downloadZip'),
                icon: <Download />,
                onSelect: () =>
                  void downloadFolderZip(f, () => {}).then(
                    (r) => r === 'empty' && toast.info(t('drive.zipEmpty')),
                    (e: unknown) => !(e instanceof DOMException && e.name === 'AbortError') && toast.error(t('drive.downloadFailed')),
                  ),
              },
              ...(f.source === 'remote'
                ? [{ id: 'leave', label: t('shared.leave'), icon: <LogOut />, onSelect: () => setLeaving(f), destructive: true, separated: true }]
                : []),
            ]
          }}
        />
      )}
      <AcceptInviteDialog open={inviting} onClose={() => setInviting(false)} />
      <ConfirmDestructive
        open={leavingFile !== null}
        onOpenChange={(o) => !o && (setLeavingFile(null), leaveFile.reset())}
        title={t('shared.removeFileTitle')}
        description={t('shared.removeFileDescription', { name: leavingFile?.file.name ?? t('shared.goneName') })}
        submit={t('shared.remove')}
        pending={leaveFile.isPending}
        error={leaveFile.error}
        errorFallback={t('shared.leaveFailed')}
        onConfirm={() => leavingFile && leaveFile.mutate(leavingFile, { onSuccess: () => setLeavingFile(null) })}
      />
      <FileShareDialog
        target={(() => {
          const s: SharedFile | undefined = sharing ? filesById.get(sharing) : undefined
          return s?.canShare ? { folder: s.container, file: s.file, role: 'editor' as const } : null
        })()}
        onClose={() => setSharing(null)}
      />
      {(() => {
        const s = renaming ? filesById.get(renaming) : undefined
        return (
          <NameDialog
            open={s !== undefined}
            title={t('dialogs.rename.title')}
            initial={s?.file.name ?? ''}
            submit={t('dialogs.rename.submit')}
            pending={rename.isPending}
            error={rename.error}
            onClose={() => (setRenaming(null), rename.reset())}
            onSubmit={(name) => s && rename.mutate({ folder: s.container, file: s.file, name }, { onSuccess: () => setRenaming(null) })}
          />
        )
      })()}
      <ConfirmDestructive
        open={leaving !== null}
        onOpenChange={(o) => !o && (setLeaving(null), leave.reset())}
        title={t('shared.leaveTitle')}
        description={t('shared.leaveDescription', { name: leaving?.name ?? '', account: leaving?.ownerAccount ? personOf(people.data, leaving.ownerAccount).name : '' })}
        submit={t('shared.leave')}
        pending={leave.isPending}
        error={leave.error}
        errorFallback={t('shared.leaveFailed')}
        onConfirm={() => leaving && leave.mutate(leaving, { onSuccess: () => setLeaving(null) })}
      />
    </div>
  )
}
