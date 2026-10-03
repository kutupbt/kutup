import { Download } from 'lucide-react'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Alert } from '@kutup/ui/components/alert'
import { Button } from '@kutup/ui/components/button'
import { Card } from '@kutup/ui/components/card'
import { Checkbox } from '@kutup/ui/components/checkbox'
import { Input } from '@kutup/ui/components/input'
import { Label } from '@kutup/ui/components/label'
import { Mono } from '@kutup/ui/components/mono'
import { PageBody, PageHeader } from '@kutup/ui/components/page'
import { EmptyState, LoadingPanel } from '@kutup/ui/components/states'
import { apiErrorMessage } from '@kutup/ui/lib/apiError'
import { formatInstant } from '@kutup/ui/lib/format'
import { exportActivityCsv, useAdminActivity, type ActivityFilter } from './api'
import { activitySentence } from './activityText'

export function ActivityPage() {
  const { t, i18n } = useTranslation()
  const [filter, setFilter] = useState<ActivityFilter>({ federationOnly: false, domain: '' })
  const [domainDraft, setDomainDraft] = useState('')
  const [exporting, setExporting] = useState(false)
  const [exportError, setExportError] = useState<unknown>(null)
  const activity = useAdminActivity(filter)
  const entries = activity.data?.pages.flatMap((p) => p.entries) ?? []

  async function download() {
    setExporting(true)
    setExportError(null)
    try {
      const blob = await exportActivityCsv(filter)
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = filter.federationOnly
        ? `kutup-federation-audit${filter.domain ? `-${filter.domain}` : ''}.csv`
        : 'kutup-audit.csv'
      a.click()
      window.setTimeout(() => URL.revokeObjectURL(url), 0)
    } catch (error) {
      setExportError(error)
    } finally {
      setExporting(false)
    }
  }

  return (
    <PageBody>
      <PageHeader
        title={t('admin.activity.title')}
        description={t('admin.activity.description')}
        actions={
          <Button variant="outline" onClick={() => void download()} loading={exporting}>
            <Download />
            {t('admin.activity.export')}
          </Button>
        }
      />
      {exportError ? <Alert variant="error">{apiErrorMessage(exportError, t('admin.activity.exportFailed'))}</Alert> : null}
      <Card className="p-0">
        <form
          className="flex flex-wrap items-center gap-4 border-b border-border p-3"
          onSubmit={(e) => {
            e.preventDefault()
            setFilter((f) => ({ ...f, domain: domainDraft }))
          }}
        >
          <div className="flex items-center gap-2">
            <Checkbox
              id="federation-only"
              checked={filter.federationOnly}
              onCheckedChange={(v) => setFilter((f) => ({ ...f, federationOnly: v === true }))}
            />
            <Label htmlFor="federation-only">{t('admin.activity.federationOnly')}</Label>
          </div>
          {filter.federationOnly ? (
            <Input
              value={domainDraft}
              onChange={(e) => setDomainDraft(e.target.value)}
              onBlur={() => setFilter((f) => ({ ...f, domain: domainDraft }))}
              placeholder={t('admin.activity.domain')}
              aria-label={t('admin.activity.domain')}
              className="max-w-xs"
            />
          ) : null}
        </form>
        {activity.isPending ? <LoadingPanel label={t('common.loading')} /> : null}
        {activity.isError ? (
          <div className="p-4"><Alert variant="error">{apiErrorMessage(activity.error, t('common.tryAgain'))}</Alert></div>
        ) : null}
        {activity.data && entries.length === 0 ? (
          <EmptyState title={t('admin.activity.emptyTitle')} description={t('admin.activity.emptyDescription')} />
        ) : null}
        <ol className="divide-y divide-border">
          {entries.map((e) => (
            <li key={e.id} className="flex flex-wrap items-baseline gap-x-4 gap-y-1 px-4 py-3">
              <p className="min-w-0 flex-1 text-sm">{activitySentence(e, t)}</p>
              <Mono className="text-xs text-muted-foreground">{formatInstant(e.occurredAt, i18n.language)}</Mono>
            </li>
          ))}
        </ol>
        {activity.hasNextPage ? (
          <div className="border-t border-border p-3 text-center">
            <Button variant="ghost" onClick={() => void activity.fetchNextPage()} loading={activity.isFetchingNextPage}>
              {t('admin.activity.older')}
            </Button>
          </div>
        ) : null}
      </Card>
    </PageBody>
  )
}
