import { Check, RotateCcw, Trash2, X } from 'lucide-react'
import { useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import type { DriveFile } from '@kutup/drive-core/model'
import { usePurge, useRestore, useTrash, type TrashEntry } from '@kutup/drive-core/trash'
import { appUrl } from '@kutup/session/apps'
import { Alert } from '@kutup/ui/components/alert'
import { Button } from '@kutup/ui/components/button'
import { ConfirmDestructive } from '@kutup/ui/components/confirm-destructive'
import { PageBody, PageHeader } from '@kutup/ui/components/page'
import { EmptyState, LoadingPanel } from '@kutup/ui/components/states'
import { cn } from '@kutup/ui/lib/cn'
import { formatInstant } from '@kutup/ui/lib/format'
import { useThumbnail } from '../timeline/useThumbnail'

type TrashedPhoto = TrashEntry & { file: DriveFile }

function TrashTile({ entry, selected, onToggle }: { entry: TrashedPhoto; selected: boolean; onToggle: () => void }) {
  const { t, i18n } = useTranslation()
  const url = useThumbnail(entry.file)
  return (
    <button
      type="button"
      role="checkbox"
      aria-checked={selected}
      aria-label={t('trash.select', { name: entry.name ?? '', when: formatInstant(entry.deletedAt, i18n.language) })}
      onClick={onToggle}
      className="group relative aspect-square overflow-hidden bg-muted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-ring"
    >
      {url ? <img src={url} alt="" className={cn('size-full object-cover transition-transform', selected && 'scale-[0.88] rounded-md')} draggable={false} /> : null}
      <span
        className={cn(
          'absolute left-1.5 top-1.5 flex size-6 items-center justify-center rounded-full border-2',
          selected ? 'border-primary bg-primary text-primary-foreground' : 'border-white/90 bg-black/20 text-transparent opacity-0 group-hover:opacity-100',
        )}
      >
        <Check className="size-3.5" strokeWidth={3} aria-hidden />
      </span>
    </button>
  )
}

/**
 * Photos and videos in the trash of your folders (Drive's trash: restoring
 * puts one back where it was, in Drive and here). Folders in the trash, and
 * everything else, are in Drive's trash.
 */
export function TrashPage() {
  const { t } = useTranslation()
  const trash = useTrash()
  const restore = useRestore()
  const purge = usePurge()
  const [selected, setSelected] = useState<Set<string>>(() => new Set())
  const [confirming, setConfirming] = useState(false)
  const photos = useMemo(
    () =>
      (trash.data ?? []).filter(
        (e): e is TrashedPhoto => e.type === 'file' && Boolean(e.file) && (e.kind === 'image' || e.kind === 'video'),
      ),
    [trash.data],
  )
  const chosen = photos.filter((p) => selected.has(p.id))

  async function each(run: (id: string) => Promise<void>, done: string, failed: string) {
    let failures = 0
    for (const entry of chosen) {
      try {
        await run(entry.id)
      } catch {
        failures++
      }
    }
    setSelected(new Set())
    if (failures) toast.error(t(failed, { count: failures }))
    else toast.success(t(done, { count: chosen.length }))
  }

  if (trash.isPending) return <LoadingPanel label={t('trash.loading')} />
  return (
    <PageBody className="px-4 py-6 md:px-8 md:py-8">
      <PageHeader title={t('trash.title')} description={t('trash.description')} />
      {trash.isError ? (
        <Alert variant="error" title={t('trash.failed')}>
          {t('timeline.failedDescription')}
        </Alert>
      ) : null}
      {chosen.length > 0 ? (
        <div className="sticky top-14 z-20 -mx-4 mb-3 flex items-center gap-2 border-b border-border bg-background/95 px-4 py-2 backdrop-blur-sm md:-mx-8 md:px-8">
          <Button variant="ghost" size="icon" aria-label={t('selection.clear')} onClick={() => setSelected(new Set())}>
            <X />
          </Button>
          <p className="min-w-0 flex-1 text-sm font-medium">{t('selection.count', { count: chosen.length })}</p>
          <Button
            variant="outline"
            size="sm"
            disabled={restore.isPending}
            onClick={() => void each((id) => restore.mutateAsync(id), 'trash.restored', 'trash.restoreFailed')}
          >
            <RotateCcw /> {t('trash.restore')}
          </Button>
          <Button variant="outline" size="sm" onClick={() => setConfirming(true)}>
            <Trash2 /> <span className="hidden sm:inline">{t('trash.deleteForever')}</span>
          </Button>
        </div>
      ) : null}
      {photos.length === 0 ? (
        <EmptyState
          title={t('trash.emptyTitle')}
          description={t('trash.emptyDescription')}
          action={
            <Button asChild variant="outline">
              <a href={appUrl('drive', '/trash')}>{t('trash.openDrive')}</a>
            </Button>
          }
        />
      ) : (
        <div className="grid grid-cols-3 gap-0.5 sm:grid-cols-5 lg:grid-cols-7">
          {photos.map((entry) => (
            <TrashTile
              key={entry.id}
              entry={entry}
              selected={selected.has(entry.id)}
              onToggle={() =>
                setSelected((current) => {
                  const next = new Set(current)
                  if (next.has(entry.id)) next.delete(entry.id)
                  else next.add(entry.id)
                  return next
                })
              }
            />
          ))}
        </div>
      )}
      <ConfirmDestructive
        open={confirming}
        onOpenChange={setConfirming}
        title={t('trash.deleteTitle', { count: chosen.length })}
        description={t('trash.deleteDescription', { count: chosen.length })}
        warning={t('trash.deleteWarning')}
        submit={t('trash.deleteForever')}
        pending={purge.isPending}
        errorFallback={t('trash.deleteFailed', { count: chosen.length })}
        onConfirm={() => {
          void each((id) => purge.mutateAsync(id), 'trash.deleted', 'trash.deleteFailed').then(() => setConfirming(false))
        }}
      />
    </PageBody>
  )
}
