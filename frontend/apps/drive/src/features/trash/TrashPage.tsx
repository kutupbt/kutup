import { RotateCcw, Trash2 } from 'lucide-react'
import { useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { Alert } from '@kutup/ui/components/alert'
import { Button } from '@kutup/ui/components/button'
import { ConfirmDestructive } from '@kutup/ui/components/confirm-destructive'
import { EmptyState, LoadingPanel } from '@kutup/ui/components/states'
import { apiErrorCode, apiErrorMessage } from '@kutup/ui/lib/apiError'
import { Explorer } from '../explorer/Explorer'
import { useExplorerPrefs } from '../explorer/prefs'
import { filterItems, itemKey, sortItems, type ExplorerItem } from '../explorer/sort'
import { Toolbar } from '../explorer/Toolbar'
import { useEmptyTrash, usePurge, useRestore, useTrash, type TrashEntry } from './api'

/**
 * Trash, as the same mixed list (sorted by when things were deleted unless
 * the toolbar says otherwise). A folder is one entry holding everything that
 * was inside it.
 */
export function TrashPage() {
  const { t, i18n } = useTranslation()
  const trash = useTrash()
  const restore = useRestore()
  const purge = usePurge()
  const empty = useEmptyTrash()
  const [prefs, updatePrefs] = useExplorerPrefs()
  const [selection, setSelection] = useState<Set<string>>(new Set())
  const [purging, setPurging] = useState<TrashEntry | null>(null)
  const [emptying, setEmptying] = useState(false)

  const entries = useMemo(() => new Map((trash.data ?? []).map((e) => [itemKey(e), e])), [trash.data])
  const items: ExplorerItem[] = useMemo(
    () =>
      (trash.data ?? []).map((e) => ({
        type: e.type,
        id: e.id,
        name: e.name ?? t('drive.encrypted'),
        kind: e.kind,
        size: e.size,
        modifiedAt: e.deletedAt,
      })),
    [trash.data, t],
  )
  const shown = sortItems(filterItems(items, prefs.kinds), prefs.sort, i18n.language)

  const doRestore = (entry: TrashEntry) =>
    restore.mutate(entry.id, {
      onSuccess: () => toast.success(t('trash.restored', { name: entry.name ?? t('drive.encrypted') })),
      onError: (error) =>
        toast.error(apiErrorCode(error) === 'conflict' ? t('trash.restoreParentFirst') : apiErrorMessage(error, t('trash.restoreFailed'))),
    })

  if (trash.isPending) return <LoadingPanel label={t('common.loading')} />

  return (
    <div className="flex min-h-[calc(100svh-3.5rem)] flex-col">
      <div className="sticky top-14 z-20 flex min-h-12 flex-wrap items-center gap-2 border-b border-border bg-background/95 px-3 py-1.5 backdrop-blur-sm md:px-6">
        <h1 className="min-w-0 flex-1 font-display text-lg font-semibold">{t('nav.trash')}</h1>
        {items.length > 0 ? (
          <Button variant="outline" size="sm" onClick={() => setEmptying(true)}>
            <Trash2 />
            {t('trash.empty')}
          </Button>
        ) : null}
        <Toolbar prefs={prefs} update={updatePrefs} />
      </div>
      {trash.isError ? <div className="p-4"><Alert variant="error">{apiErrorMessage(trash.error, t('drive.loadFailed'))}</Alert></div> : null}
      {items.length > 0 ? <p className="px-4 pt-3 text-xs text-muted-foreground md:px-6">{t('trash.retention')}</p> : null}
      {shown.length === 0 ? (
        <EmptyState title={t('trash.emptyTitle')} description={t('trash.emptyDescription')} />
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
            const e = entries.get(itemKey(item))
            return e?.type === 'folder' && e.files ? t('trash.withFiles', { count: e.files }) : null
          }}
          onOpen={() => {}}
          actionsFor={(item) => {
            const entry = entries.get(itemKey(item))
            if (!entry) return []
            return [
              { id: 'restore', label: t('trash.restore'), icon: <RotateCcw />, onSelect: () => doRestore(entry) },
              { id: 'purge', label: t('trash.deleteForever'), icon: <Trash2 />, onSelect: () => setPurging(entry), destructive: true, separated: true },
            ]
          }}
        />
      )}
      <ConfirmDestructive
        open={purging !== null}
        onOpenChange={(o) => !o && (setPurging(null), purge.reset())}
        title={t('trash.deleteForeverTitle')}
        description={t('trash.deleteForeverDescription', { name: purging?.name ?? t('drive.encrypted') })}
        warning={t('trash.cannotUndo')}
        submit={t('trash.deleteForever')}
        pending={purge.isPending}
        error={purge.error}
        errorFallback={t('trash.deleteFailed')}
        onConfirm={() => purging && purge.mutate(purging.id, { onSuccess: () => setPurging(null) })}
      />
      <ConfirmDestructive
        open={emptying}
        onOpenChange={(o) => !o && (setEmptying(false), empty.reset())}
        title={t('trash.emptyConfirmTitle')}
        description={t('trash.emptyConfirmDescription', { count: items.length })}
        warning={t('trash.cannotUndo')}
        submit={t('trash.empty')}
        pending={empty.isPending}
        error={empty.error}
        errorFallback={t('trash.deleteFailed')}
        onConfirm={() => empty.mutate(undefined, { onSuccess: () => setEmptying(false) })}
      />
    </div>
  )
}
