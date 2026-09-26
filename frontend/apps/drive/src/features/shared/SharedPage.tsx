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
import { downloadFolderZip } from '../drive/downloads'
import { useFolders } from '../drive/folders'
import type { Folder } from '../drive/model'
import { useLeaveRemoteShare } from '../drive/mutations'
import { folderPath } from '../drive/paths'
import { personOf, usePeople } from '../people/people'
import { PersonLabel } from '../people/PersonLabel'
import { Explorer } from '../explorer/Explorer'
import { useExplorerPrefs } from '../explorer/prefs'
import { filterItems, sortItems, type ExplorerItem } from '../explorer/sort'
import { Toolbar } from '../explorer/Toolbar'
import { AcceptInviteDialog } from './AcceptInviteDialog'

/** Folders other people shared with you, here or from other Kutup servers. */
export function SharedPage() {
  const { t, i18n } = useTranslation()
  const navigate = useNavigate()
  const folders = useFolders()
  const [prefs, updatePrefs] = useExplorerPrefs()
  const [selection, setSelection] = useState<Set<string>>(new Set())
  const [inviting, setInviting] = useState(false)
  const [leaving, setLeaving] = useState<Folder | null>(null)
  const leave = useLeaveRemoteShare()
  const people = usePeople()

  const byId = useMemo(() => new Map((folders.data?.sharedWithMe ?? []).map((f) => [f.remoteShareId ?? f.id, f])), [folders.data])
  const items: ExplorerItem[] = useMemo(
    () =>
      (folders.data?.sharedWithMe ?? []).map((f) => ({
        type: 'folder' as const,
        id: f.remoteShareId ?? f.id,
        name: f.name ?? t('drive.encrypted'),
        kind: 'folder' as const,
        size: null,
        modifiedAt: f.updatedAt,
      })),
    [folders.data, t],
  )
  const shown = sortItems(filterItems(items, prefs.kinds), prefs.sort, i18n.language)

  if (folders.isPending) return <LoadingPanel label={t('common.loading')} />

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
      {folders.isError ? (
        <div className="p-4"><Alert variant="error">{apiErrorMessage(folders.error, t('drive.loadFailed'))}</Alert></div>
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
            const f = byId.get(item.id)
            return f?.ownerAccount ? (
              <PersonLabel account={f.ownerAccount} format={(name) => t('shared.from', { account: name })} />
            ) : null
          }}
          onOpen={(item) => {
            const f = byId.get(item.id)
            if (f?.key) void navigate(folderPath(f))
          }}
          actionsFor={(item) => {
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
