import { useQueries } from '@tanstack/react-query'
import type { ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import { folderFilesKey, loadFolderFiles } from '@kutup/drive-core/files'
import { useFolders } from '@kutup/drive-core/folders'
import { FILE_KINDS, type FileKind } from '@kutup/drive-core/kinds'
import { KindIcon } from '@kutup/drive-ui/KindIcon'
import { useRequiredSession } from '@kutup/session/store'
import { Alert } from '@kutup/ui/components/alert'
import { Card, CardContent } from '@kutup/ui/components/card'
import { PageBody, PageHeader, Section } from '@kutup/ui/components/page'
import { Skeleton } from '@kutup/ui/components/skeleton'
import { apiErrorMessage } from '@kutup/ui/lib/apiError'
import { cn } from '@kutup/ui/lib/cn'
import { formatBytes } from '@kutup/ui/lib/format'
import { useStorageUsage, type StorageUsage } from './api'

/**
 * The account's one storage pool (docs/api.md, `GET /api/user/storage`):
 * how full it is, what each app stores in it, and what kinds of files take
 * the room. The server knows only sizes; the kinds come from the names this
 * browser decrypts.
 */
export function StoragePage() {
  const { t } = useTranslation()
  const usage = useStorageUsage()

  return (
    <PageBody width="prose">
      <PageHeader title={t('settings.storage.title')} description={t('settings.storage.description')} />
      {usage.isPending ? (
        <Skeleton className="h-40 w-full" />
      ) : usage.isError ? (
        <Alert variant="error">{apiErrorMessage(usage.error, t('common.tryAgain'))}</Alert>
      ) : (
        <>
          <Overview usage={usage.data} />
          <ByApp usage={usage.data} />
          <ByKind />
        </>
      )}
    </PageBody>
  )
}

function Overview({ usage }: { usage: StorageUsage }) {
  const { t, i18n } = useTranslation()
  const lang = i18n.language
  const drive = driveTotal(usage)
  const chat = chatTotal(usage)
  const quota = Math.max(usage.quotaBytes, 1)
  const share = (bytes: number) => `${Math.min(100, (Math.max(bytes, 0) / quota) * 100)}%`
  const free = usage.quotaBytes - usage.usedBytes - usage.reservedBytes
  return (
    <Card>
      <CardContent className="space-y-4 p-5">
        <p className="text-sm">
          <span className="text-2xl font-semibold tabular-nums">{formatBytes(usage.usedBytes, lang)}</span>{' '}
          <span className="text-muted-foreground">
            {t('settings.storage.ofQuota', { total: formatBytes(usage.quotaBytes, lang) })}
          </span>
        </p>
        <div
          className="flex h-2.5 overflow-hidden rounded-full bg-muted"
          role="meter"
          aria-valuemin={0}
          aria-valuemax={usage.quotaBytes}
          aria-valuenow={usage.usedBytes}
          aria-label={t('settings.storage.title')}
        >
          <div className="h-full bg-primary" style={{ width: share(drive) }} />
          <div className="h-full bg-status-ok" style={{ width: share(chat) }} />
          <div className="h-full bg-status-neutral" style={{ width: share(usage.reservedBytes) }} />
        </div>
        <ul className="flex flex-wrap gap-x-5 gap-y-2 text-sm text-muted-foreground">
          <Legend swatch="bg-primary" label={t('settings.storage.apps.drive')} value={formatBytes(drive, lang)} />
          <Legend swatch="bg-status-ok" label={t('settings.storage.apps.chat')} value={formatBytes(chat, lang)} />
          {usage.reservedBytes > 0 ? (
            <Legend swatch="bg-status-neutral" label={t('settings.storage.reserved')} value={formatBytes(usage.reservedBytes, lang)} />
          ) : null}
          <Legend swatch="bg-muted border border-border" label={t('settings.storage.free')} value={formatBytes(Math.max(free, 0), lang)} />
        </ul>
        {free <= 0 ? <Alert variant="error">{t('settings.storage.full')}</Alert> : null}
      </CardContent>
    </Card>
  )
}

function Legend({ swatch, label, value }: { swatch: string; label: string; value: string }) {
  return (
    <li className="flex items-center gap-2">
      <span aria-hidden className={cn('size-2.5 rounded-full', swatch)} />
      <span>
        {label} <span className="tabular-nums text-foreground">{value}</span>
      </span>
    </li>
  )
}

function ByApp({ usage }: { usage: StorageUsage }) {
  const { t, i18n } = useTranslation()
  const lang = i18n.language
  const { drive, chat } = usage
  return (
    <>
      <Section title={t('settings.storage.apps.drive')} description={t('settings.storage.driveHint')}>
        <Card>
          <CardContent className="divide-y divide-border p-0">
            <Row label={t('settings.storage.drive.files', { count: drive.filesCount })} bytes={drive.filesBytes} lang={lang} />
            <Row label={t('settings.storage.drive.trash', { count: drive.trashCount })} bytes={drive.trashBytes} lang={lang} />
            <Row label={t('settings.storage.drive.versions')} bytes={drive.versionsBytes} lang={lang} />
            <Row label={t('settings.storage.drive.thumbnails')} bytes={drive.thumbnailsBytes} lang={lang} />
            <Row label={t('settings.storage.drive.assets')} bytes={drive.assetsBytes} lang={lang} />
          </CardContent>
        </Card>
      </Section>
      <Section title={t('settings.storage.apps.chat')} description={t('settings.storage.chatHint')}>
        <Card>
          <CardContent className="divide-y divide-border p-0">
            <Row label={t('settings.storage.chat.media')} bytes={chat.mediaBytes} lang={lang} />
            <Row label={t('settings.storage.chat.history')} bytes={chat.historyBytes} lang={lang} />
            <Row label={t('settings.storage.chat.historyMedia')} bytes={chat.historyMediaBytes} lang={lang} />
          </CardContent>
        </Card>
      </Section>
    </>
  )
}

function Row({ label, bytes, lang, icon }: { label: string; bytes: number; lang: string; icon?: ReactNode }) {
  return (
    <div className="flex items-center justify-between gap-4 px-5 py-3 text-sm">
      <span className="flex min-w-0 items-center gap-3">
        {icon}
        <span className="truncate">{label}</span>
      </span>
      <span className="shrink-0 tabular-nums text-muted-foreground">{formatBytes(bytes, lang)}</span>
    </div>
  )
}

/**
 * Files this account uploaded and has not trashed, by kind, from every
 * folder it can read: what is charged to it, which includes what it put in
 * other people's folders. Sizes are of the files themselves, before
 * encryption.
 */
function ByKind() {
  const { t, i18n } = useTranslation()
  const session = useRequiredSession()
  const folders = useFolders()
  const readable = (folders.data?.all ?? []).filter((f) => f.key)
  const lists = useQueries({
    queries: readable.map((folder) => ({
      queryKey: folderFilesKey(folder),
      queryFn: () => loadFolderFiles(folder),
    })),
  })
  const loading = folders.isPending || lists.some((l) => l.isPending)
  const failed = folders.isError || lists.some((l) => l.isError)

  const totals = new Map<FileKind, { bytes: number; count: number }>()
  const seen = new Set<string>()
  for (const list of lists) {
    for (const file of list.data ?? []) {
      if (file.uploaderUserId !== session.userId || seen.has(file.id)) continue
      seen.add(file.id)
      const total = totals.get(file.kind) ?? { bytes: 0, count: 0 }
      total.bytes += file.size
      total.count += 1
      totals.set(file.kind, total)
    }
  }
  const rows = FILE_KINDS.flatMap((kind) => {
    const total = totals.get(kind)
    return total ? [{ kind, ...total }] : []
  }).sort((a, b) => b.bytes - a.bytes)

  return (
    <Section title={t('settings.storage.byKind')} description={t('settings.storage.byKindHint')}>
      {loading ? (
        <Skeleton className="h-32 w-full" />
      ) : (
        <>
          {failed ? <Alert variant="error">{t('settings.storage.byKindPartial')}</Alert> : null}
          {rows.length === 0 ? (
            <p className="text-sm text-muted-foreground">{t('settings.storage.noFiles')}</p>
          ) : (
            <Card>
              <CardContent className="divide-y divide-border p-0">
                {rows.map((row) => (
                  <Row
                    key={row.kind}
                    icon={<KindIcon kind={row.kind} className="size-5" />}
                    label={t('settings.storage.kindCount', { kind: t(`settings.storage.kinds.${row.kind}`), count: row.count })}
                    bytes={row.bytes}
                    lang={i18n.language}
                  />
                ))}
              </CardContent>
            </Card>
          )}
        </>
      )}
    </Section>
  )
}

function driveTotal(usage: StorageUsage) {
  const d = usage.drive
  return d.filesBytes + d.trashBytes + d.versionsBytes + d.thumbnailsBytes + d.assetsBytes
}

function chatTotal(usage: StorageUsage) {
  const c = usage.chat
  return c.mediaBytes + c.historyBytes + c.historyMediaBytes
}
