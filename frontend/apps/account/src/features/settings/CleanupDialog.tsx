import { useState, type ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { useTrashFile } from '@kutup/drive-core/mutations'
import { useQueryClient } from '@tanstack/react-query'
import {
  largeFiles,
  LARGE_FILE_BYTES,
  pruneVersions,
  storageKey,
  useVersionAges,
  versionsOlderThan,
  type OwnFile,
  type StorageUsage,
  type useOwnFiles,
} from '@kutup/drive-core/storage'
import { useEmptyTrash } from '@kutup/drive-core/trash'
import { KindIcon } from '@kutup/drive-ui/KindIcon'
import { appUrl } from '@kutup/session/apps'
import { Alert } from '@kutup/ui/components/alert'
import { Button } from '@kutup/ui/components/button'
import { Checkbox } from '@kutup/ui/components/checkbox'
import { ConfirmDestructive } from '@kutup/ui/components/confirm-destructive'
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from '@kutup/ui/components/dialog'
import { Skeleton } from '@kutup/ui/components/skeleton'
import { apiErrorMessage } from '@kutup/ui/lib/apiError'
import { formatBytes } from '@kutup/ui/lib/format'
import { useMe } from './api'

/**
 * Ways to free space, each with what it would free: emptying the trash,
 * trashing large files, and pointers to what is managed elsewhere (Chat's
 * stored media) or goes on its own (earlier versions).
 */
export function CleanupDialog({
  open,
  onOpenChange,
  usage,
  own,
}: {
  open: boolean
  onOpenChange: (open: boolean) => void
  usage: StorageUsage
  own: ReturnType<typeof useOwnFiles>
}) {
  const { t, i18n } = useTranslation()
  const bytes = (value: number) => formatBytes(value, i18n.language)
  const me = useMe()

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-2xl">
        <DialogHeader>
          <DialogTitle>{t('settings.storage.cleanup.title')}</DialogTitle>
          <DialogDescription>{t('settings.storage.cleanup.description')}</DialogDescription>
        </DialogHeader>
        <div className="mt-4 space-y-3">
          <EmptyTrash usage={usage} />
          <LargeFiles own={own} />
          <OldVersions open={open} retentionDays={me.data?.versionRetentionDays ?? null} />
          <Suggestion
            title={t('settings.storage.cleanup.chat')}
            size={bytes(usage.chat.mediaBytes + usage.chat.historyMediaBytes)}
            description={t('settings.storage.cleanup.chatHint')}
            action={
              <Button asChild variant="outline" size="sm">
                <a href={appUrl('chat', '/settings/storage')}>{t('settings.storage.cleanup.openChat')}</a>
              </Button>
            }
          />
        </div>
      </DialogContent>
    </Dialog>
  )
}

function Suggestion({ title, size, description, action, children }: { title: string; size: string; description: ReactNode; action?: ReactNode; children?: ReactNode }) {
  return (
    <section className="rounded-lg border border-border p-4">
      <div className="flex flex-wrap items-start gap-3">
        <div className="min-w-0 flex-1 space-y-1">
          <h3 className="text-sm font-medium">
            {title} <span className="font-normal tabular-nums text-muted-foreground">· {size}</span>
          </h3>
          <p className="text-sm text-muted-foreground">{description}</p>
        </div>
        {action}
      </div>
      {children}
    </section>
  )
}

function EmptyTrash({ usage }: { usage: StorageUsage }) {
  const { t, i18n } = useTranslation()
  const empty = useEmptyTrash()
  const [confirming, setConfirming] = useState(false)
  const { trashBytes, trashCount } = usage.drive
  return (
    <>
      <Suggestion
        title={t('settings.storage.cleanup.trash')}
        size={formatBytes(trashBytes, i18n.language)}
        description={
          trashCount > 0 ? t('settings.storage.cleanup.trashHint', { count: trashCount }) : t('settings.storage.cleanup.trashEmpty')
        }
        action={
          <Button variant="outline" size="sm" disabled={trashCount === 0} onClick={() => setConfirming(true)}>
            {t('settings.storage.cleanup.emptyTrash')}
          </Button>
        }
      />
      <ConfirmDestructive
        open={confirming}
        onOpenChange={setConfirming}
        title={t('settings.storage.cleanup.emptyTrashTitle')}
        description={t('settings.storage.cleanup.emptyTrashDescription', {
          count: trashCount,
          size: formatBytes(trashBytes, i18n.language),
        })}
        warning={t('settings.storage.cleanup.cannotUndo')}
        submit={t('settings.storage.cleanup.emptyTrash')}
        pending={empty.isPending}
        error={empty.error}
        errorFallback={t('settings.storage.cleanup.failed')}
        onConfirm={() =>
          empty.mutate(undefined, {
            onSuccess: () => {
              setConfirming(false)
              toast.success(t('settings.storage.cleanup.trashEmptied'))
            },
          })
        }
      />
    </>
  )
}

function LargeFiles({ own }: { own: ReturnType<typeof useOwnFiles> }) {
  const { t, i18n } = useTranslation()
  const lang = i18n.language
  const trash = useTrashFile()
  const [selected, setSelected] = useState<Set<string>>(new Set())
  const [busy, setBusy] = useState(false)
  const files = own.loading ? [] : largeFiles(own.files)
  const chosen = files.filter(({ file }) => selected.has(file.id))
  const chosenBytes = chosen.reduce((total, { file }) => total + file.size, 0)

  function toggle(id: string, on: boolean) {
    setSelected((current) => {
      const next = new Set(current)
      if (on) next.add(id)
      else next.delete(id)
      return next
    })
  }

  async function moveToTrash(items: OwnFile[]) {
    setBusy(true)
    let moved = 0
    try {
      for (const item of items) {
        await trash.mutateAsync(item)
        moved += 1
      }
      toast.success(t('settings.storage.cleanup.moved', { count: moved }))
      setSelected(new Set())
    } catch (error) {
      toast.error(apiErrorMessage(error, t('settings.storage.cleanup.failed')))
    } finally {
      setBusy(false)
    }
  }

  return (
    <Suggestion
      title={t('settings.storage.cleanup.large')}
      size={formatBytes(files.reduce((total, { file }) => total + file.size, 0), lang)}
      description={t('settings.storage.cleanup.largeHint', { size: formatBytes(LARGE_FILE_BYTES, lang) })}
      action={
        <Button variant="outline" size="sm" disabled={chosen.length === 0 || busy} loading={busy} onClick={() => void moveToTrash(chosen)}>
          {chosen.length > 0
            ? t('settings.storage.cleanup.moveSelected', { count: chosen.length, size: formatBytes(chosenBytes, lang) })
            : t('settings.storage.cleanup.moveToTrash')}
        </Button>
      }
    >
      {own.failed ? <Alert variant="error" className="mt-3">{t('settings.storage.byKindPartial')}</Alert> : null}
      {own.loading ? (
        <Skeleton className="mt-3 h-24 w-full" />
      ) : files.length === 0 ? (
        <p className="mt-3 text-sm text-muted-foreground">{t('settings.storage.cleanup.noLarge')}</p>
      ) : (
        <ul className="mt-3 max-h-72 divide-y divide-border overflow-y-auto rounded-md border border-border" aria-label={t('settings.storage.cleanup.large')}>
          {files.map(({ folder, file }) => (
            <li key={file.id}>
              <label className="flex cursor-pointer items-center gap-3 px-3 py-2 text-sm hover:bg-muted/60">
                <Checkbox
                  checked={selected.has(file.id)}
                  onCheckedChange={(on) => toggle(file.id, on === true)}
                  disabled={busy}
                  aria-label={t('settings.storage.cleanup.select', { name: file.name })}
                />
                <KindIcon kind={file.kind} className="size-5" />
                <span className="min-w-0 flex-1">
                  <span className="block truncate">{file.name}</span>
                  <span className="block truncate text-xs text-muted-foreground">{folder.isRoot ? t('settings.storage.cleanup.myFiles') : (folder.name ?? t('settings.storage.cleanup.unnamedFolder'))}</span>
                </span>
                <span className="shrink-0 tabular-nums text-muted-foreground">{formatBytes(file.size, lang)}</span>
              </label>
            </li>
          ))}
        </ul>
      )}
      {chosen.length > 0 ? <p className="mt-2 text-xs text-muted-foreground">{t('settings.storage.cleanup.trashStillCounts')}</p> : null}
    </Suggestion>
  )
}

/**
 * Earlier versions you saved, deleted in bulk by age with a slider: what the
 * chosen age would free is shown before anything goes. Each file's newest
 * version always stays (it is the file's current content), and versions
 * marked Keep forever only go when included.
 */
function OldVersions({ open, retentionDays }: { open: boolean; retentionDays: number | null }) {
  const { t, i18n } = useTranslation()
  const lang = i18n.language
  const queryClient = useQueryClient()
  const ages = useVersionAges(open)
  const oldest = Math.max(0, ...(ages.data ?? []).map((a) => a.ageDays))
  const [chosen, setChosen] = useState<number | null>(null)
  const days = Math.min(chosen ?? Math.min(30, oldest), oldest)
  const [includeKept, setIncludeKept] = useState(false)
  const [confirming, setConfirming] = useState(false)
  const [pending, setPending] = useState(false)
  const [error, setError] = useState<unknown>(null)
  const all = versionsOlderThan(ages.data ?? [], 0, true)
  const kept = (ages.data ?? []).filter((a) => a.keepForever).reduce((n, a) => n + a.count, 0)
  const selected = versionsOlderThan(ages.data ?? [], days, includeKept)

  async function remove() {
    setPending(true)
    setError(null)
    try {
      const done = await pruneVersions(days, includeKept)
      setConfirming(false)
      toast.success(t('settings.storage.cleanup.versionsDeleted', { count: done.deletedCount, size: formatBytes(done.freedBytes, lang) }))
      await queryClient.invalidateQueries({ queryKey: storageKey })
    } catch (e) {
      setError(e)
    } finally {
      setPending(false)
    }
  }

  return (
    <Suggestion
      title={t('settings.storage.cleanup.versions')}
      size={formatBytes(all.bytes, lang)}
      description={
        retentionDays !== null
          ? t('settings.storage.cleanup.versionsHint', { count: retentionDays })
          : t('settings.storage.cleanup.versionsHintUnknown')
      }
      action={
        <Button asChild variant="outline" size="sm">
          <a href={appUrl('drive', '/settings')}>{t('settings.storage.cleanup.versionSettings')}</a>
        </Button>
      }
    >
      {ages.isPending ? (
        <Skeleton className="mt-3 h-20 w-full" />
      ) : ages.isError ? (
        <Alert variant="error" className="mt-3">{apiErrorMessage(ages.error, t('common.tryAgain'))}</Alert>
      ) : all.count === 0 ? (
        <p className="mt-3 text-sm text-muted-foreground">{t('settings.storage.cleanup.noVersions')}</p>
      ) : (
        <div className="mt-3 space-y-3 rounded-md border border-border p-3">
          <label className="block space-y-2 text-sm">
            <span className="flex justify-between gap-2">
              <span>{days === 0 ? t('settings.storage.cleanup.anyAge') : t('settings.storage.cleanup.olderThan', { count: days })}</span>
              <span className="tabular-nums text-muted-foreground">
                {t('settings.storage.cleanup.wouldFree', { count: selected.count, size: formatBytes(selected.bytes, lang) })}
              </span>
            </span>
            <input
              type="range"
              min={0}
              max={oldest}
              step={1}
              value={days}
              onChange={(e) => setChosen(Number(e.target.value))}
              disabled={pending || oldest === 0}
              className="w-full accent-primary"
              aria-label={t('settings.storage.cleanup.olderThanLabel')}
              aria-valuetext={days === 0 ? t('settings.storage.cleanup.anyAge') : t('settings.storage.cleanup.olderThan', { count: days })}
            />
          </label>
          {kept > 0 ? (
            <label className="flex items-center gap-2 text-sm">
              <Checkbox checked={includeKept} onCheckedChange={(on) => setIncludeKept(on === true)} disabled={pending} />
              {t('settings.storage.cleanup.includeKept', { count: kept })}
            </label>
          ) : null}
          <p className="text-xs text-muted-foreground">{t('settings.storage.cleanup.newestStays')}</p>
          <div className="flex justify-end">
            <Button variant="outline" size="sm" disabled={selected.count === 0 || pending} onClick={() => setConfirming(true)}>
              {t('settings.storage.cleanup.deleteVersions', { count: selected.count })}
            </Button>
          </div>
        </div>
      )}
      <ConfirmDestructive
        open={confirming}
        onOpenChange={(next) => {
          setConfirming(next)
          if (!next) setError(null)
        }}
        title={t('settings.storage.cleanup.deleteVersionsTitle')}
        description={
          days === 0
            ? t('settings.storage.cleanup.deleteAllVersionsDescription', { count: selected.count, size: formatBytes(selected.bytes, lang) })
            : t('settings.storage.cleanup.deleteVersionsDescription', { count: selected.count, days, size: formatBytes(selected.bytes, lang) })
        }
        warning={includeKept ? t('settings.storage.cleanup.deleteVersionsKept') : t('settings.storage.cleanup.cannotUndo')}
        submit={t('settings.storage.cleanup.deletePermanently')}
        pending={pending}
        error={error}
        errorFallback={t('settings.storage.cleanup.failed')}
        onConfirm={() => void remove()}
      />
    </Suggestion>
  )
}
