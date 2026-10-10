import { Sparkles } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { useSearchParams } from 'react-router-dom'
import {
  kindTotals,
  storageLevel,
  usageCategories,
  useOwnFiles,
  useStorageUsage,
  type StorageUsage,
  type UsageCategory,
} from '@kutup/drive-core/storage'
import { appUrl } from '@kutup/session/apps'
import { Alert } from '@kutup/ui/components/alert'
import { Button } from '@kutup/ui/components/button'
import { Card, CardContent } from '@kutup/ui/components/card'
import { Donut } from '@kutup/ui/components/donut'
import { PageBody, PageHeader } from '@kutup/ui/components/page'
import { Skeleton } from '@kutup/ui/components/skeleton'
import { apiErrorMessage } from '@kutup/ui/lib/apiError'
import { formatBytes } from '@kutup/ui/lib/format'
import { CleanupDialog } from './CleanupDialog'

/**
 * The account's one storage pool (docs/api.md, `GET /api/user/storage`):
 * a ring of what fills it, largest first, as Google One draws it, in
 * Proton's "X of Y" terms, and a way to free space. The server knows only
 * sizes; the file kinds come from the names this browser decrypts.
 */
export function StoragePage() {
  const { t } = useTranslation()
  const usage = useStorageUsage()
  const own = useOwnFiles()
  const [params, setParams] = useSearchParams()
  const cleaning = params.get('cleanup') === '1'
  const setCleaning = (open: boolean) =>
    setParams(
      (current) => {
        const next = new URLSearchParams(current)
        if (open) next.set('cleanup', '1')
        else next.delete('cleanup')
        return next
      },
      { replace: true },
    )

  const kinds = own.loading ? null : kindTotals(own.files)

  return (
    <PageBody width="prose">
      <PageHeader
        title={t('settings.storage.title')}
        description={t('settings.storage.description')}
        actions={
          <Button onClick={() => setCleaning(true)} disabled={!usage.data}>
            <Sparkles />
            {t('settings.storage.cleanup.open')}
          </Button>
        }
      />
      {usage.isPending ? (
        <Skeleton className="h-64 w-full" />
      ) : usage.isError ? (
        <Alert variant="error">{apiErrorMessage(usage.error, t('common.tryAgain'))}</Alert>
      ) : (
        <>
          <LevelAlert usage={usage.data} />
          <Overview usage={usage.data} categories={usageCategories(usage.data, kinds)} countingFiles={own.loading} />
          {own.failed ? <Alert variant="error">{t('settings.storage.byKindPartial')}</Alert> : null}
          <CleanupDialog open={cleaning} onOpenChange={setCleaning} usage={usage.data} own={own} />
        </>
      )}
    </PageBody>
  )
}

function LevelAlert({ usage }: { usage: StorageUsage }) {
  const { t } = useTranslation()
  const level = storageLevel(usage)
  if (level === 'ok') return null
  return (
    <Alert variant={level === 'danger' ? 'error' : 'warn'} title={t(`settings.storage.level.${level}`)}>
      {t(`settings.storage.level.${level}Hint`)}
    </Alert>
  )
}

function Overview({ usage, categories, countingFiles }: { usage: StorageUsage; categories: UsageCategory[]; countingFiles: boolean }) {
  const { t, i18n } = useTranslation()
  const lang = i18n.language
  const quota = Math.max(usage.quotaBytes, 1)
  const free = Math.max(0, usage.quotaBytes - usage.usedBytes - usage.reservedBytes)
  const percent = (bytes: number) => {
    const value = Math.round((bytes / quota) * 1000) / 10
    return bytes > 0 && value < 0.1 ? '<0.1' : String(value)
  }
  return (
    <Card>
      <CardContent className="grid items-center gap-6 p-5 sm:grid-cols-[auto_1fr] sm:gap-8">
        <Donut
          className="mx-auto size-48"
          gap={2}
          minPercent={1.5}
          segments={categories.map((c) => [(c.bytes / quota) * 100, c.color])}
        >
          <div>
            <p className="text-2xl font-semibold tabular-nums">{formatBytes(usage.usedBytes, lang)}</p>
            <p className="text-sm text-muted-foreground">{t('settings.storage.ofQuota', { total: formatBytes(usage.quotaBytes, lang) })}</p>
          </div>
        </Donut>
        <div className="min-w-0">
          <ul className="divide-y divide-border" aria-label={t('settings.storage.breakdown')}>
            {categories.map((c) => (
              <CategoryRow key={c.id} category={c} percent={percent(c.bytes)} />
            ))}
            <li className="flex items-center gap-3 py-2.5 text-sm">
              <span aria-hidden className="size-3 shrink-0 rounded-full border border-border bg-muted" />
              <span className="min-w-0 flex-1">{t('settings.storage.free')}</span>
              <span className="tabular-nums text-muted-foreground">{formatBytes(free, lang)}</span>
            </li>
          </ul>
          <p className="mt-2 text-xs text-muted-foreground">
            {countingFiles ? t('settings.storage.counting') : t('settings.storage.kindsNote')}
          </p>
        </div>
      </CardContent>
    </Card>
  )
}

/** Where a category can be acted on, when somewhere can. */
function categoryHref(id: UsageCategory['id']): string | null {
  if (id === 'trash') return appUrl('drive', '/trash')
  if (id === 'chatMedia' || id === 'chatHistory') return appUrl('chat', '/settings/storage')
  if (id === 'contacts') return appUrl('contacts')
  if (id === 'mail') return appUrl('mail')
  return null
}

function CategoryRow({ category, percent }: { category: UsageCategory; percent: string }) {
  const { t, i18n } = useTranslation()
  const href = categoryHref(category.id)
  const label = t(`storage.categories.${category.id}`)
  return (
    <li className="flex items-center gap-3 py-2.5 text-sm">
      <span aria-hidden className="size-3 shrink-0 rounded-full" style={{ background: category.color }} />
      <span className="min-w-0 flex-1 truncate">
        {href ? (
          <a href={href} className="hover:underline">
            {label}
          </a>
        ) : (
          label
        )}
        {category.count !== undefined ? (
          <span className="text-muted-foreground"> · {t('settings.storage.fileCount', { count: category.count })}</span>
        ) : null}
      </span>
      <span className="shrink-0 tabular-nums">{formatBytes(category.bytes, i18n.language)}</span>
      <span className="w-12 shrink-0 text-right tabular-nums text-muted-foreground">{percent}%</span>
    </li>
  )
}
