import { ArrowLeft, FileUp, Folder, FolderPlus, KeyRound, Lock, MoreHorizontal, Pencil, Plus, Search, ShieldCheck, Trash, Trash2, Vault } from 'lucide-react'
import { useEffect, useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useNavigate, useParams, useSearchParams } from 'react-router-dom'
import { toast } from 'sonner'
import { Alert } from '@kutup/ui/components/alert'
import { Badge } from '@kutup/ui/components/badge'
import { Button } from '@kutup/ui/components/button'
import { ConfirmDestructive } from '@kutup/ui/components/confirm-destructive'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@kutup/ui/components/dropdown-menu'
import { Input } from '@kutup/ui/components/input'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@kutup/ui/components/select'
import { EmptyState, LoadingPanel } from '@kutup/ui/components/states'
import { cn } from '@kutup/ui/lib/cn'
import { asNameTaken } from '@kutup/drive-core/names'
import { useRenameFile } from '@kutup/drive-core/mutations'
import { useForgetVaultKey, useVaultSecrets } from '../drive/secrets'
import { refreshVaultFile, useVaultFiles, vaultTitle, type VaultFile } from '../drive/vaults'
import { lockVault, useSessionState, useVaultSession } from '../sync/openVaults'
import type { VaultSession } from '../sync/vaultSession'
import { fieldValue, type EntryInput, type EntryView, type GroupView, type MergeReport } from '../vault/types'
import { EntryDetail } from './EntryDetail'
import { EntryEditor } from './EntryEditor'
import { GroupDialog } from './GroupDialog'
import { ImportDialog } from './ImportDialog'
import { SecurityPanel } from './SecurityPanel'
import { SiteIcon } from './SiteIcon'
import { SyncBadge } from './SyncBadge'
import { TheirsKeyDialog } from './TheirsKeyDialog'
import { UnlockVault } from './UnlockVault'

/** How often an open vault looks for another device's save while the tab is visible. */
const REFRESH_MS = 60_000
/** The group picker's choice for every entry (Radix items need a value). */
const ALL_GROUPS = 'all'

/** A vault: unlocked, or the way to unlock it. */
export function VaultPage() {
  const { t } = useTranslation()
  const { fileId } = useParams()
  const { vaults, loading } = useVaultFiles()
  const session = useVaultSession(fileId)
  const vault = vaults.find((v) => v.file.id === fileId)
  if (session) return <OpenVault session={session} vault={vault} />
  if (loading) return <LoadingPanel label={t('vaults.loading')} />
  if (!vault) return <EmptyState title={t('vaults.notFoundTitle')} description={t('vaults.notFoundDescription')} />
  return <UnlockVault key={vault.file.id} vault={vault} />
}

function matches(entry: EntryView, needle: string): boolean {
  if (!needle) return true
  const hay = [fieldValue(entry, 'Title'), fieldValue(entry, 'UserName'), fieldValue(entry, 'URL'), fieldValue(entry, 'Notes'), ...entry.tags]
    .join('\n')
    .toLocaleLowerCase()
  return hay.includes(needle)
}

function MergeNotice({ report, onDismiss }: { report: MergeReport; onDismiss: () => void }) {
  const { t } = useTranslation()
  const toReview = report.conflicts.length + report.groupConflicts.length
  return (
    <Alert variant="warn" title={t('merge.title')} className="m-3">
      <p>
        {toReview > 0 ? t('merge.review', { count: toReview }) : null}
        {report.restored.length > 0 ? ` ${t('merge.restored', { count: report.restored.length })}` : null}
        {report.metadataConflicts.length > 0 ? ` ${t('merge.settings')}` : null}
      </p>
      <Button size="sm" variant="outline" className="mt-2" onClick={onDismiss}>
        {t('merge.dismiss')}
      </Button>
    </Alert>
  )
}

function OpenVault({ session, vault }: { session: VaultSession; vault: VaultFile | undefined }) {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const { fileId, entryId } = useParams()
  const [params] = useSearchParams()
  const state = useSessionState(session)!
  const { view, status, merge } = state
  const secrets = useVaultSecrets()
  const forgetKey = useForgetVaultKey()
  const renameFile = useRenameFile()
  const [query, setQuery] = useState('')
  const [editing, setEditing] = useState<EntryView | 'new' | null>(null)
  const [groupDialog, setGroupDialog] = useState<{ kind: 'new'; parent: string } | { kind: 'rename'; group: GroupView } | null>(null)
  const [deletingGroup, setDeletingGroup] = useState<GroupView | null>(null)
  const [emptyingBin, setEmptyingBin] = useState(false)
  const [renamingVault, setRenamingVault] = useState(false)
  const [importing, setImporting] = useState(false)

  // Another device's save is taken in when the tab comes back, and now and then.
  useEffect(() => {
    const refresh = () => {
      if (document.visibilityState === 'visible') void session.refresh()
    }
    const timer = setInterval(refresh, REFRESH_MS)
    document.addEventListener('visibilitychange', refresh)
    return () => {
      clearInterval(timer)
      document.removeEventListener('visibilitychange', refresh)
    }
  }, [session])

  const groupId = params.get('g') ?? null
  const showingReport = params.get('view') === 'security'
  const bin = view.recycleBinId
  const viewingBin = Boolean(bin && groupId === bin)
  const selectedGroup = groupId ? view.groups.find((g) => g.id === groupId) : undefined
  const needle = query.trim().toLocaleLowerCase()
  const shown = useMemo(() => {
    const inGroup = (entry: EntryView) => {
      if (!groupId) return !entry.inRecycleBin
      if (viewingBin) return entry.inRecycleBin
      return entry.groupId === groupId
    }
    return view.entries
      .filter((e) => inGroup(e) && matches(e, needle))
      .sort((a, b) => fieldValue(a, 'Title').localeCompare(fieldValue(b, 'Title'), undefined, { sensitivity: 'base', numeric: true }))
  }, [view.entries, groupId, viewingBin, needle])
  const entry = entryId ? view.entries.find((e) => e.id === entryId) : undefined
  const kept = secrets.data?.some((s) => s.fileId === fileId) ?? false
  const groups = view.groups.filter((g) => !g.inRecycleBin)
  const toReview = view.entries.filter((e) => e.review.length > 0 && !e.inRecycleBin).length

  const selectGroup = (id: string | null) => {
    const next = new URLSearchParams(params)
    if (id) next.set('g', id)
    else next.delete('g')
    void navigate({ pathname: `/v/${fileId}`, search: next.toString() })
  }
  const openEntry = (id: string) => {
    const next = new URLSearchParams(params)
    next.delete('view')
    void navigate({ pathname: `/v/${fileId}/e/${id}`, search: next.toString() })
  }
  const toggleReport = () => {
    const next = new URLSearchParams(params)
    if (showingReport) next.delete('view')
    else next.set('view', 'security')
    void navigate({ pathname: `/v/${fileId}`, search: next.toString() })
  }

  const saveEntry = async (input: EntryInput) => {
    if (editing === 'new') {
      const target = groupId && !viewingBin ? groupId : view.rootGroupId
      const applied = await session.apply({ op: 'createEntry', groupId: target, entry: input })
      toast.success(t('entry.created'))
      if (applied.id) openEntry(applied.id)
    } else if (editing) {
      await session.apply({ op: 'updateEntry', id: editing.id, entry: input })
      toast.success(t('entry.saved'))
    }
  }

  // The vault's name is its file's name, as Drive shows it; the name inside
  // the KeePass file follows it when renamed here.
  const title = vaultTitle(vault?.file.name) || view.name
  return (
    <div className="flex h-full min-h-0 flex-col">
      <header className="flex flex-wrap items-center gap-3 border-b border-border px-4 py-3">
        <Vault className="size-5 text-primary" aria-hidden />
        <h1 className="min-w-0 truncate font-display text-lg font-semibold tracking-tight">{title}</h1>
        <SyncBadge status={status} />
        {!session.canEdit ? <Badge variant="neutral">{t('vaults.readOnly')}</Badge> : null}
        {state.fromOutbox ? <Badge variant="warn">{t('sync.fromOutbox')}</Badge> : null}
        <div className="ml-auto flex items-center gap-2">
          <Button size="sm" variant={showingReport ? 'secondary' : 'outline'} onClick={toggleReport} aria-pressed={showingReport}>
            <ShieldCheck />
            {t('report.open')}
          </Button>
          {session.canEdit ? (
            <Button size="sm" onClick={() => setEditing('new')} disabled={viewingBin}>
              <Plus />
              {t('entry.new')}
            </Button>
          ) : null}
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="ghost" size="icon" aria-label={t('vault.menu')}>
                <MoreHorizontal />
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end">
              {session.canEdit ? (
                <DropdownMenuItem onSelect={() => setRenamingVault(true)}>
                  <Pencil />
                  {t('vault.rename')}
                </DropdownMenuItem>
              ) : null}
              {session.canEdit ? (
                <DropdownMenuItem onSelect={() => setImporting(true)}>
                  <FileUp />
                  {t('import.open')}
                </DropdownMenuItem>
              ) : null}
              {kept ? (
                <DropdownMenuItem
                  onSelect={() =>
                    void forgetKey(fileId!).then(
                      () => toast.success(t('vault.keyForgotten')),
                      () => toast.error(t('vault.forgetFailed')),
                    )
                  }
                >
                  <KeyRound />
                  {t('vault.forgetKey')}
                </DropdownMenuItem>
              ) : null}
              <DropdownMenuSeparator />
              <DropdownMenuItem
                onSelect={() => {
                  void lockVault(fileId!).then(() => navigate('/'))
                }}
              >
                <Lock />
                {t('vault.lock')}
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        </div>
      </header>
      {status === 'quota' ? (
        <Alert variant="error" className="m-3">
          {t('sync.quotaDescription')}
        </Alert>
      ) : null}
      {status === 'offline' ? (
        <Alert variant="info" className="m-3">
          {t('sync.offlineDescription')}
        </Alert>
      ) : null}
      {merge ? <MergeNotice report={merge} onDismiss={() => session.dismissMerge()} /> : null}
      <div className="flex min-h-0 flex-1">
        <nav aria-label={t('groups.label')} className={cn('w-56 shrink-0 overflow-y-auto border-r border-border p-2', 'hidden md:block')}>
          <ul className="space-y-0.5 text-sm">
            <li>
              <button
                type="button"
                onClick={() => selectGroup(null)}
                className={cn('flex w-full items-center gap-2 rounded-md px-2 py-1.5 text-left hover:bg-accent/60', !groupId && 'bg-accent font-medium')}
              >
                <KeyRound className="size-4 shrink-0" aria-hidden />
                <span className="flex-1 truncate">{t('groups.all')}</span>
                {toReview > 0 ? <Badge variant="warn">{toReview}</Badge> : null}
              </button>
            </li>
            {groups.map((g) => (
              <li key={g.id} className="group/row flex items-center">
                <button
                  type="button"
                  onClick={() => selectGroup(g.id)}
                  className={cn('flex min-w-0 flex-1 items-center gap-2 rounded-md px-2 py-1.5 text-left hover:bg-accent/60', groupId === g.id && 'bg-accent font-medium')}
                  style={{ paddingInlineStart: `${0.5 + g.depth * 0.75}rem` }}
                >
                  <Folder className="size-4 shrink-0" aria-hidden />
                  <span className="truncate">{g.name}</span>
                </button>
                {session.canEdit ? (
                  <DropdownMenu>
                    <DropdownMenuTrigger asChild>
                      <Button variant="ghost" size="icon" className="size-7 opacity-0 group-hover/row:opacity-100 focus-visible:opacity-100" aria-label={t('groups.actions', { name: g.name })}>
                        <MoreHorizontal />
                      </Button>
                    </DropdownMenuTrigger>
                    <DropdownMenuContent align="end">
                      <DropdownMenuItem onSelect={() => setGroupDialog({ kind: 'new', parent: g.id })}>
                        <FolderPlus />
                        {t('groups.newInside')}
                      </DropdownMenuItem>
                      {g.id !== view.rootGroupId ? (
                        <>
                          <DropdownMenuItem onSelect={() => setGroupDialog({ kind: 'rename', group: g })}>
                            <Pencil />
                            {t('groups.rename')}
                          </DropdownMenuItem>
                          <DropdownMenuItem onSelect={() => setDeletingGroup(g)}>
                            <Trash2 />
                            {t('groups.delete')}
                          </DropdownMenuItem>
                        </>
                      ) : null}
                    </DropdownMenuContent>
                  </DropdownMenu>
                ) : null}
              </li>
            ))}
            {bin ? (
              <li className="flex items-center pt-2">
                <button
                  type="button"
                  onClick={() => selectGroup(bin)}
                  className={cn('flex min-w-0 flex-1 items-center gap-2 rounded-md px-2 py-1.5 text-left hover:bg-accent/60', viewingBin && 'bg-accent font-medium')}
                >
                  <Trash className="size-4 shrink-0" aria-hidden />
                  <span className="truncate">{t('groups.recycleBin')}</span>
                </button>
              </li>
            ) : null}
          </ul>
        </nav>
        {showingReport ? (
          <section className="min-w-0 flex-1" aria-label={t('report.title')}>
            <SecurityPanel view={view} onOpen={openEntry} />
          </section>
        ) : null}
        <section aria-label={t('entries.label')} className={cn('flex w-full min-w-0 flex-col border-r border-border md:w-80 md:shrink-0', (entry || showingReport) && 'hidden', entry && !showingReport && 'md:flex')}>
          <div className="space-y-2 border-b border-border p-2">
            <label className="relative block">
              <span className="sr-only">{t('entries.search')}</span>
              <Search className="pointer-events-none absolute left-2.5 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" aria-hidden />
              <Input value={query} onChange={(e) => setQuery(e.target.value)} placeholder={t('entries.search')} className="pl-8" type="search" />
            </label>
            {viewingBin && shown.length > 0 && session.canEdit ? (
              <Button variant="outline" size="sm" className="w-full" onClick={() => setEmptyingBin(true)}>
                <Trash2 />
                {t('groups.emptyBin')}
              </Button>
            ) : null}
            <div className="md:hidden">
              <Select value={groupId ?? ALL_GROUPS} onValueChange={(value) => selectGroup(value === ALL_GROUPS ? null : value)}>
                <SelectTrigger aria-label={t('groups.label')}>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value={ALL_GROUPS}>{t('groups.all')}</SelectItem>
                  {groups.map((g) => (
                    <SelectItem key={g.id} value={g.id}>
                      <span style={{ paddingInlineStart: `${g.depth * 0.75}rem` }}>{g.name}</span>
                    </SelectItem>
                  ))}
                  {bin ? <SelectItem value={bin}>{t('groups.recycleBin')}</SelectItem> : null}
                </SelectContent>
              </Select>
            </div>
          </div>
          {shown.length === 0 ? (
            <p className="p-4 text-sm text-muted-foreground">
              {needle ? t('entries.noMatch') : viewingBin ? t('entries.binEmpty') : t('entries.empty', { group: selectedGroup?.name ?? title })}
            </p>
          ) : (
            <ul className="flex-1 overflow-y-auto" aria-label={t('entries.label')}>
              {shown.map((e) => (
                <li key={e.id}>
                  <button
                    type="button"
                    onClick={() => openEntry(e.id)}
                    aria-current={e.id === entryId ? 'true' : undefined}
                    className={cn('flex w-full items-center gap-3 border-b border-border px-3 py-2.5 text-left hover:bg-accent/50', e.id === entryId && 'bg-accent')}
                  >
                    <SiteIcon title={fieldValue(e, 'Title')} address={fieldValue(e, 'URL')} />
                    <span className="min-w-0 flex-1">
                      <span className="block truncate text-sm font-medium">{fieldValue(e, 'Title') || t('entry.untitled')}</span>
                      <span className="block truncate text-xs text-muted-foreground">{fieldValue(e, 'UserName') || fieldValue(e, 'URL')}</span>
                    </span>
                    {e.review.length > 0 ? <Badge variant="warn">{t('review.badge')}</Badge> : null}
                  </button>
                </li>
              ))}
            </ul>
          )}
        </section>
        <section className={cn('min-w-0 flex-1', showingReport ? 'hidden' : !entry && 'hidden md:block')}>
          {entry ? (
            <div className="flex h-full flex-col">
              <Button variant="ghost" size="sm" className="m-2 self-start md:hidden" onClick={() => void navigate({ pathname: `/v/${fileId}`, search: params.toString() })}>
                <ArrowLeft />
                {t('common.back')}
              </Button>
              <EntryDetail
                key={entry.id}
                session={session}
                entry={entry}
                view={view}
                onEdit={() => setEditing(entry)}
                onGone={() => void navigate({ pathname: `/v/${fileId}`, search: params.toString() })}
              />
            </div>
          ) : (
            <div className="grid h-full place-items-center p-6">
              <p className="text-sm text-muted-foreground">{t('entries.pick')}</p>
            </div>
          )}
        </section>
      </div>
      <EntryEditor
        open={editing !== null}
        onOpenChange={(open) => !open && setEditing(null)}
        entry={editing === 'new' ? null : editing}
        defaultUserName={view.defaultUserName}
        onSave={saveEntry}
      />
      <GroupDialog
        open={groupDialog !== null}
        onOpenChange={(open) => !open && setGroupDialog(null)}
        title={groupDialog?.kind === 'rename' ? t('groups.renameTitle') : t('groups.newTitle')}
        initial={groupDialog?.kind === 'rename' ? groupDialog.group.name : ''}
        onSubmit={async (name) => {
          if (groupDialog?.kind === 'rename') {
            await session.apply({ op: 'updateGroup', id: groupDialog.group.id, name, notes: groupDialog.group.notes })
          } else if (groupDialog) {
            const applied = await session.apply({ op: 'createGroup', parentId: groupDialog.parent, name })
            if (applied.id) selectGroup(applied.id)
          }
        }}
      />
      <GroupDialog
        open={renamingVault}
        onOpenChange={setRenamingVault}
        title={t('vault.renameTitle')}
        label={t('vaults.name')}
        initial={title}
        describeError={(failure) => (asNameTaken(failure) ? t('vault.nameTaken') : null)}
        onSubmit={async (name) => {
          if (!vault) return
          // The file, as its folder lists it now (the vault's own saves move it on).
          const file = await refreshVaultFile(vault.folder, vault.file)
          await renameFile.mutateAsync({ folder: vault.folder, file, name: `${name}.kdbx` })
          await session.apply({ op: 'updateVault', name, description: view.description, defaultUserName: view.defaultUserName })
        }}
      />
      <ConfirmDestructive
        open={deletingGroup !== null}
        onOpenChange={(open) => !open && setDeletingGroup(null)}
        title={t('groups.deleteTitle')}
        description={t(view.recycleBinEnabled ? 'groups.deleteDescription' : 'groups.deleteForGoodDescription', { name: deletingGroup?.name ?? '' })}
        submit={t('groups.delete')}
        errorFallback={t('entry.saveFailed')}
        onConfirm={() => {
          const group = deletingGroup
          setDeletingGroup(null)
          if (!group) return
          void session.apply({ op: 'deleteGroup', id: group.id }).then(
            () => {
              toast.success(t('groups.deleted'))
              if (groupId === group.id) selectGroup(null)
            },
            () => toast.error(t('entry.saveFailed')),
          )
        }}
      />
      <ConfirmDestructive
        open={emptyingBin}
        onOpenChange={setEmptyingBin}
        title={t('groups.emptyBinTitle')}
        description={t('groups.emptyBinDescription')}
        submit={t('groups.emptyBin')}
        errorFallback={t('entry.saveFailed')}
        onConfirm={() => {
          setEmptyingBin(false)
          void session.apply({ op: 'emptyRecycleBin' }).then(
            () => toast.success(t('groups.binEmptied')),
            () => toast.error(t('entry.saveFailed')),
          )
        }}
      />
      <TheirsKeyDialog session={session} open={status === 'needsKey'} />
      <ImportDialog session={session} open={importing} onOpenChange={setImporting} onImported={(id) => selectGroup(id)} />
    </div>
  )
}
