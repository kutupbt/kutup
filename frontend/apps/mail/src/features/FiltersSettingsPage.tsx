import { Filter, GripVertical, ListChecks, Pencil, Plus, Trash2 } from 'lucide-react'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { useApplyFilters, useDeleteFilter, useFilterRun, useFilters, useOrderFilters, useUpdateFilter, type MailFilter } from '@kutup/mail-core/filters'
import { usePlaces } from '@kutup/mail-core/places'
import { Alert } from '@kutup/ui/components/alert'
import { Button } from '@kutup/ui/components/button'
import { Checkbox } from '@kutup/ui/components/checkbox'
import { ConfirmDestructive } from '@kutup/ui/components/confirm-destructive'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@kutup/ui/components/dialog'
import { PageBody, PageHeader } from '@kutup/ui/components/page'
import { EmptyState, LoadingPanel } from '@kutup/ui/components/states'
import { Tooltip } from '@kutup/ui/components/tooltip'
import { apiErrorMessage } from '@kutup/ui/lib/apiError'
import { cn } from '@kutup/ui/lib/cn'
import { FilterDialog } from './FilterDialog'
import { describeFilter } from './filterText'

/**
 * Settings → Filters (Proton's `FiltersSection`): the filters in the order
 * they run (drag to reorder), each switched on or off, edited, applied to
 * the mail already there, or deleted.
 */
export function FiltersSettingsPage() {
  const { t } = useTranslation()
  const filters = useFilters()
  const places = usePlaces()
  const update = useUpdateFilter()
  const remove = useDeleteFilter()
  const order = useOrderFilters()
  const apply = useApplyFilters()
  const [editing, setEditing] = useState<MailFilter | 'new' | null>(null)
  const [deleting, setDeleting] = useState<MailFilter | null>(null)
  const [applying, setApplying] = useState<MailFilter | null>(null)
  const [runId, setRunId] = useState<string | null>(null)
  const run = useFilterRun(runId)
  const [dragging, setDragging] = useState<string | null>(null)
  const [over, setOver] = useState<{ id: string; after: boolean } | null>(null)

  if (filters.isPending) return <LoadingPanel label={t('common.loading')} />
  if (filters.isError) return <Alert variant="error">{apiErrorMessage(filters.error, t('common.tryAgain'))}</Alert>
  const list = filters.data

  function drop(target: MailFilter, after: boolean) {
    if (!dragging || dragging === target.id) return
    const ids = list.map((f) => f.id).filter((id) => id !== dragging)
    ids.splice(ids.indexOf(target.id) + (after ? 1 : 0), 0, dragging)
    order.mutate(ids, { onError: (e) => toast.error(apiErrorMessage(e, t('common.tryAgain'))) })
  }

  return (
    <PageBody>
      <PageHeader
        title={t('filters.title')}
        description={t('filters.description')}
        actions={
          <Button onClick={() => setEditing('new')}>
            <Plus />
            {t('filters.add')}
          </Button>
        }
      />
      {run.data && !run.data.finished ? (
        <Alert variant="info" title={t('filters.applying')}>
          {t('filters.progress', { done: run.data.done, total: run.data.total })}
        </Alert>
      ) : run.data?.finished ? (
        <Alert variant={run.data.failed ? 'error' : 'info'}>
          {run.data.failed ? t('filters.applyFailed') : t('filters.applied', { count: run.data.changed })}
        </Alert>
      ) : null}
      {list.length === 0 ? (
        <EmptyState title={t('filters.empty')} description={t('filters.emptyHint')} />
      ) : (
        <>
          <p className="text-sm text-muted-foreground">{t('filters.orderHint')}</p>
          <ul className="rounded-lg border border-border">
            {list.map((filter) => (
              <li
                key={filter.id}
                draggable
                onDragStart={(e) => {
                  e.dataTransfer.effectAllowed = 'move'
                  e.dataTransfer.setData('text/plain', filter.id)
                  setDragging(filter.id)
                }}
                onDragEnd={() => {
                  setDragging(null)
                  setOver(null)
                }}
                onDragOver={(e) => {
                  if (!dragging || dragging === filter.id) return
                  e.preventDefault()
                  const box = e.currentTarget.getBoundingClientRect()
                  setOver({ id: filter.id, after: e.clientY > box.top + box.height / 2 })
                }}
                onDrop={(e) => {
                  e.preventDefault()
                  const after = over?.id === filter.id ? over.after : true
                  setOver(null)
                  drop(filter, after)
                }}
                className={cn(
                  'flex items-start gap-3 border-b border-border px-3 py-3 last:border-b-0',
                  over?.id === filter.id && (over.after ? 'shadow-[inset_0_-2px_0_var(--primary)]' : 'shadow-[inset_0_2px_0_var(--primary)]'),
                  !filter.enabled && 'opacity-70',
                )}
              >
                <GripVertical className="mt-0.5 size-4 shrink-0 cursor-grab text-muted-foreground" aria-hidden />
                <Filter className="mt-0.5 size-4 shrink-0 text-muted-foreground" aria-hidden />
                <div className="min-w-0 flex-1">
                  <p className="truncate text-sm font-medium">{filter.name}</p>
                  <p className="text-xs text-muted-foreground">{describeFilter(filter, places.data, t)}</p>
                </div>
                <label className="flex shrink-0 items-center gap-2 text-xs text-muted-foreground">
                  <Checkbox
                    checked={filter.enabled}
                    aria-label={t('filters.enabledFor', { name: filter.name })}
                    onCheckedChange={(on) =>
                      update.mutate({ id: filter.id, enabled: on === true }, { onError: (e) => toast.error(apiErrorMessage(e, t('common.tryAgain'))) })
                    }
                  />
                  {t('filters.enabled')}
                </label>
                <Tooltip label={t('filters.applyExistingShort')}>
                  <Button variant="ghost" size="icon" className="size-8" aria-label={t('filters.applyExistingShort')} disabled={!filter.enabled} onClick={() => setApplying(filter)}>
                    <ListChecks />
                  </Button>
                </Tooltip>
                <Tooltip label={t('filters.edit')}>
                  <Button variant="ghost" size="icon" className="size-8" aria-label={t('filters.edit')} onClick={() => setEditing(filter)}>
                    <Pencil />
                  </Button>
                </Tooltip>
                <Tooltip label={t('filters.delete')}>
                  <Button variant="ghost" size="icon" className="size-8" aria-label={t('filters.delete')} onClick={() => setDeleting(filter)}>
                    <Trash2 />
                  </Button>
                </Tooltip>
              </li>
            ))}
          </ul>
        </>
      )}
      {editing ? <FilterDialog filter={editing === 'new' ? undefined : editing} onClose={() => setEditing(null)} /> : null}
      <Dialog open={applying !== null} onOpenChange={(open) => !open && setApplying(null)}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>{t('filters.applyTitle')}</DialogTitle>
            <DialogDescription>{t('filters.applyDescription')}</DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setApplying(null)}>
              {t('common.cancel')}
            </Button>
            <Button
              disabled={apply.isPending}
              onClick={() => {
                const target = applying
                setApplying(null)
                if (!target) return
                apply.mutate([target.id], {
                  onSuccess: (started) => {
                    setRunId(started.id)
                    toast(t('filters.applying'))
                  },
                  onError: (e) => toast.error(apiErrorMessage(e, t('common.tryAgain'))),
                })
              }}
            >
              {t('filters.apply')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
      <ConfirmDestructive
        open={deleting !== null}
        onOpenChange={(open) => !open && setDeleting(null)}
        title={t('filters.deleteTitle')}
        description={t('filters.deleteDescription', { name: deleting?.name ?? '' })}
        submit={t('filters.delete')}
        pending={remove.isPending}
        error={remove.error}
        errorFallback={t('common.tryAgain')}
        onConfirm={() => {
          const target = deleting
          if (!target) return
          remove.mutate(target.id, {
            onSuccess: () => {
              toast.success(t('filters.removed', { name: target.name }))
              setDeleting(null)
            },
          })
        }}
      />
    </PageBody>
  )
}
