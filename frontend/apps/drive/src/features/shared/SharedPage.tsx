import { Download, ExternalLink, LogOut, Plus } from 'lucide-react'
import { useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useNavigate } from 'react-router-dom'
import { toast } from 'sonner'
import { Alert } from '@kutup/ui/components/alert'
import { Button } from '@kutup/ui/components/button'
import { ConfirmDestructive } from '@kutup/ui/components/confirm-destructive'
import { EmptyState, LoadingPanel } from '@kutup/ui/components/states'
import { apiErrorMessage } from '@kutup/ui/lib/apiError'
import { downloadFile, downloadFolderZip } from '../drive/downloads'
import { useSharedFiles } from '@kutup/drive-core/fileShares'
import { useFolders } from '@kutup/drive-core/folders'
import type { Folder } from '@kutup/drive-core/model'
import { useLeaveRemoteShare } from '@kutup/drive-core/mutations'
import { filePath, folderPath } from '../drive/paths'
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
        name: s.file.name ?? (s.state === 'waiting' ? t('shared.waitingName') : t('drive.encrypted')),
        kind: s.file.kind,
        size: s.file.name ? s.file.size : null,
        modifiedAt: s.file.updatedAt,
      })),
    ],
    [folders.data, sharedFiles.data, t],
  )
  const shown = sortItems(filterItems(items, prefs.kinds), prefs.sort, i18n.language)

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
              return s.state === 'waiting' ? (
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
              if (s?.file.fileKey) void navigate(filePath(s.container, s.file.id))
              else if (s?.state === 'waiting') toast.info(t('shared.waitingHint'))
              return
            }
            const f = byId.get(item.id)
            if (f?.key) void navigate(folderPath(f))
          }}
          actionsFor={(item) => {
            if (item.type === 'file') {
              const s = filesById.get(item.id)
              if (!s?.file.fileKey) return []
              return [
                { id: 'open', label: t('drive.actions.open'), icon: <ExternalLink />, onSelect: () => void navigate(filePath(s.container, s.file.id)) },
                {
                  id: 'download',
                  label: t('drive.actions.download'),
                  icon: <Download />,
                  onSelect: () =>
                    void downloadFile(s.container, s.file).catch(
                      (e: unknown) => !(e instanceof DOMException && e.name === 'AbortError') && toast.error(t('drive.downloadFailed')),
                    ),
                },
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
