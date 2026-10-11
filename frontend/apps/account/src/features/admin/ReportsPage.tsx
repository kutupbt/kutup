import { ExternalLink } from 'lucide-react'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Link } from 'react-router-dom'
import { toast } from 'sonner'
import { Alert } from '@kutup/ui/components/alert'
import { Badge } from '@kutup/ui/components/badge'
import { Button } from '@kutup/ui/components/button'
import { Card } from '@kutup/ui/components/card'
import { ConfirmDestructive } from '@kutup/ui/components/confirm-destructive'
import { PageBody, PageHeader } from '@kutup/ui/components/page'
import { EmptyState, LoadingPanel } from '@kutup/ui/components/states'
import { Tabs, TabsList, TabsTrigger } from '@kutup/ui/components/tabs'
import { apiErrorMessage } from '@kutup/ui/lib/apiError'
import { formatInstant } from '@kutup/ui/lib/format'
import { useDismissReport, useLinkReports, useRemoveReportedLink, useUpdateUser, type LinkReport } from './api'

type Pending = { kind: 'remove' | 'disable'; report: LinkReport }

/**
 * Reports on public links, from anyone who opened one (docs/architecture.md,
 * "File editor route"). The server cannot see what a link shows; a reporter
 * may have handed over the whole link so an administrator can look. Each
 * report is dismissed, or its link taken down, or its owner's account
 * disabled (which takes every link of theirs down).
 */
export function ReportsPage() {
  const { t } = useTranslation()
  const [status, setStatus] = useState<'open' | 'resolved'>('open')
  const reports = useLinkReports(status)
  const dismiss = useDismissReport()
  const remove = useRemoveReportedLink()
  const update = useUpdateUser()
  const [pending, setPending] = useState<Pending | null>(null)

  const close = () => {
    setPending(null)
    remove.reset()
    update.reset()
  }

  return (
    <PageBody>
      <PageHeader title={t('admin.reports.title')} description={t('admin.reports.description')} />
      <Tabs value={status} onValueChange={(v) => setStatus(v as 'open' | 'resolved')}>
        <TabsList>
          <TabsTrigger value="open">{t('admin.reports.open')}</TabsTrigger>
          <TabsTrigger value="resolved">{t('admin.reports.resolved')}</TabsTrigger>
        </TabsList>
      </Tabs>
      {reports.isPending ? <LoadingPanel label={t('common.loading')} /> : null}
      {reports.isError ? <Alert variant="error">{apiErrorMessage(reports.error, t('common.tryAgain'))}</Alert> : null}
      {reports.data && reports.data.length === 0 ? (
        <EmptyState
          title={t(status === 'open' ? 'admin.reports.emptyTitle' : 'admin.reports.noneResolvedTitle')}
          description={t(status === 'open' ? 'admin.reports.emptyDescription' : 'admin.reports.noneResolvedDescription')}
        />
      ) : null}
      <ul className="space-y-3">
        {reports.data?.map((report) => (
          <li key={report.id}>
            <ReportCard
              report={report}
              dismissing={dismiss.isPending && dismiss.variables === report.id}
              onDismiss={() =>
                dismiss.mutate(report.id, {
                  onSuccess: () => toast.success(t('admin.reports.dismissed')),
                  onError: (error) => toast.error(apiErrorMessage(error, t('admin.reports.actionFailed'))),
                })
              }
              onRemove={() => setPending({ kind: 'remove', report })}
              onDisable={() => setPending({ kind: 'disable', report })}
            />
          </li>
        ))}
      </ul>
      {pending?.kind === 'remove' ? (
        <ConfirmDestructive
          open
          onOpenChange={(o) => !o && close()}
          title={t('admin.reports.removeTitle')}
          description={t('admin.reports.removeDescription', { email: pending.report.ownerEmail })}
          submit={t('admin.reports.remove')}
          pending={remove.isPending}
          error={remove.error}
          errorFallback={t('admin.reports.actionFailed')}
          onConfirm={() =>
            remove.mutate(pending.report.id, {
              onSuccess: () => {
                toast.success(t('admin.reports.removed'))
                close()
              },
            })
          }
        />
      ) : null}
      {pending?.kind === 'disable' ? (
        <ConfirmDestructive
          open
          onOpenChange={(o) => !o && close()}
          title={t('admin.reports.disableTitle')}
          description={t('admin.reports.disableDescription', { email: pending.report.ownerEmail })}
          submit={t('admin.user.disable')}
          pending={update.isPending}
          error={update.error}
          errorFallback={t('admin.reports.actionFailed')}
          onConfirm={() =>
            update.mutate(
              { id: pending.report.ownerUserId, patch: { isActive: false } },
              {
                onSuccess: () => {
                  toast.success(t('admin.reports.disabled'))
                  close()
                },
              },
            )
          }
        />
      ) : null}
    </PageBody>
  )
}

function ReportCard({
  report,
  dismissing,
  onDismiss,
  onRemove,
  onDisable,
}: {
  report: LinkReport
  dismissing: boolean
  onDismiss: () => void
  onRemove: () => void
  onDisable: () => void
}) {
  const { t, i18n } = useTranslation()
  const open = report.resolvedAt === null
  return (
    <Card className="space-y-3 p-4" data-testid="link-report">
      <div className="flex flex-wrap items-center gap-2">
        <Badge variant="warn">{t(`reportLink.reasons.${report.reason}`)}</Badge>
        <span className="text-sm text-muted-foreground">{formatInstant(report.createdAt, i18n.language)}</span>
        {report.openReportsOnLink > 1 && open ? (
          <span className="text-sm text-muted-foreground">{t('admin.reports.more', { count: report.openReportsOnLink - 1 })}</span>
        ) : null}
        {report.resolution ? (
          <Badge variant="neutral" className="ml-auto">
            {t(`admin.reports.resolution.${report.resolution}`)}
          </Badge>
        ) : null}
      </div>
      {report.details ? <p className="whitespace-pre-wrap break-words text-sm">{report.details}</p> : null}
      <dl className="grid gap-x-4 gap-y-1 text-sm sm:grid-cols-[max-content_1fr]">
        <dt className="text-muted-foreground">{t('admin.reports.owner')}</dt>
        <dd className="flex min-w-0 flex-wrap items-center gap-2">
          <Link to={`/admin/users/${report.ownerUserId}`} className="truncate font-medium hover:underline">
            {report.ownerEmail}
          </Link>
          {report.ownerIsActive ? null : <Badge variant="neutral">{t('admin.users.disabled')}</Badge>}
        </dd>
        <dt className="text-muted-foreground">{t('admin.reports.link')}</dt>
        <dd>
          {t(report.shareType === 'file' ? 'admin.reports.fileLink' : 'admin.reports.folderLink', {
            date: formatInstant(report.shareCreatedAt, i18n.language),
          })}
          {report.shareRemovedAt ? ` · ${t('admin.reports.linkRemoved')}` : ''}
        </dd>
      </dl>
      {open ? (
        <div className="flex flex-wrap gap-2 border-t border-border pt-3">
          {report.link ? (
            <Button size="sm" variant="outline" asChild>
              {/* The reporter's link, checked by the server to be one of this server's public pages. */}
              <a href={report.link} target="_blank" rel="noopener noreferrer">
                <ExternalLink /> {t('admin.reports.openLink')}
              </a>
            </Button>
          ) : (
            <span className="self-center text-xs text-muted-foreground">{t('admin.reports.noLink')}</span>
          )}
          <div className="ml-auto flex flex-wrap gap-2">
            <Button size="sm" variant="ghost" loading={dismissing} onClick={onDismiss}>
              {t('admin.reports.dismiss')}
            </Button>
            {report.shareRemovedAt ? null : (
              <Button size="sm" variant="outline" onClick={onRemove}>
                {t('admin.reports.remove')}
              </Button>
            )}
            {report.ownerIsActive ? (
              <Button size="sm" variant="destructive" onClick={onDisable}>
                {t('admin.user.disable')}
              </Button>
            ) : null}
          </div>
        </div>
      ) : null}
    </Card>
  )
}
