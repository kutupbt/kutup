import { useState, type ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { useTrashFile } from '@kutup/drive-core/mutations'
import { largeFiles, LARGE_FILE_BYTES, type OwnFile, type StorageUsage, type useOwnFiles } from '@kutup/drive-core/storage'
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
          <Suggestion
            title={t('settings.storage.cleanup.versions')}
            size={bytes(usage.drive.versionsBytes)}
            description={
              me.data
                ? t('settings.storage.cleanup.versionsHint', { count: me.data.versionRetentionDays })
                : t('settings.storage.cleanup.versionsHintUnknown')
            }
          />
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
