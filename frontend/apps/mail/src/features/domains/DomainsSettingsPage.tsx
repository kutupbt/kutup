import { MoreHorizontal, Plus, RefreshCw } from 'lucide-react'
import { useState } from 'react'
import { Trans, useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { DOMAIN_STATE, useDeleteDomain, useDomains, useRefreshDomain, type MailDomain } from '@kutup/mail-core/domains'
import { Alert } from '@kutup/ui/components/alert'
import { Button } from '@kutup/ui/components/button'
import { ConfirmDestructive } from '@kutup/ui/components/confirm-destructive'
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from '@kutup/ui/components/dropdown-menu'
import { PageBody, PageHeader } from '@kutup/ui/components/page'
import { EmptyState, LoadingPanel } from '@kutup/ui/components/states'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@kutup/ui/components/table'
import { apiErrorMessage } from '@kutup/ui/lib/apiError'
import { formatInstant } from '@kutup/ui/lib/format'
import { CatchAllDialog } from './CatchAllDialog'
import { DomainWizard } from './DomainWizard'
import { DomainName, DomainStatus } from './DomainStatus'

/**
 * Settings → Domains (Proton's "Domain names"): the account's custom
 * domains with their seven badges, "Add domain" within the limit, "Refresh
 * status", and per domain Review (the wizard), Set catch-all and Delete.
 */
export function DomainsSettingsPage() {
  const { t, i18n } = useTranslation()
  const domains = useDomains()
  const refresh = useRefreshDomain()
  const remove = useDeleteDomain()
  const [wizard, setWizard] = useState<MailDomain | 'new' | null>(null)
  const [catchAll, setCatchAll] = useState<MailDomain | null>(null)
  const [deleting, setDeleting] = useState<MailDomain | null>(null)
  const [refreshing, setRefreshing] = useState(false)

  if (domains.isPending) return <LoadingPanel label={t('common.loading')} />
  if (domains.isError) return <Alert variant="error">{apiErrorMessage(domains.error, t('common.tryAgain'))}</Alert>
  const data = domains.data
  if (!data) {
    return (
      <PageBody>
        <PageHeader title={t('domains.title')} />
        <Alert>{t('domains.unavailable')}</Alert>
      </PageBody>
    )
  }
  const off = data.mode === 'off'
  const full = data.used >= data.max

  // Proton's "Refresh status": every domain checked now, together.
  async function refreshAll() {
    setRefreshing(true)
    const results = await Promise.allSettled(data!.domains.map((domain) => refresh.mutateAsync(domain.id)))
    setRefreshing(false)
    const failed = results.find((result): result is PromiseRejectedResult => result.status === 'rejected')
    if (failed) toast.error(apiErrorMessage(failed.reason, t('common.tryAgain')))
  }

  return (
    <PageBody>
      <PageHeader
        title={t('domains.title')}
        description={t('domains.description')}
        actions={
          <div className="flex gap-2">
            <Button onClick={() => setWizard('new')} disabled={off || full} data-testid="domain-add">
              <Plus />
              {t('domains.add')}
            </Button>
            {data.domains.length > 0 ? (
              <Button variant="outline" onClick={() => void refreshAll()} loading={refreshing} disabled={refreshing}>
                <RefreshCw />
                {t('domains.refresh')}
              </Button>
            ) : null}
          </div>
        }
      />
      {off ? <Alert variant="warn">{t('domains.off')}</Alert> : null}
      {data.mode === 'approve' ? <Alert>{t('domains.approveMode')}</Alert> : null}
      {data.domains.map((domain) =>
        domain.stopped ? (
          <Alert key={domain.id} variant="error" data-testid="domain-stopped">
            <Trans i18nKey="domains.stopped" values={{ domain: domain.name }} components={{ strong: <strong /> }} />
          </Alert>
        ) : domain.state === DOMAIN_STATE.warn ? (
          <Alert key={domain.id} variant="warn" data-testid="domain-warned">
            <Trans
              i18nKey="domains.warned"
              values={{ domain: domain.name, date: formatInstant(domain.warnedAt, i18n.language) ?? '' }}
              components={{ strong: <strong /> }}
            />
          </Alert>
        ) : null,
      )}
      {data.domains.length === 0 ? (
        <EmptyState title={t('domains.empty')} description={t('domains.emptyHint')} />
      ) : (
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>{t('domains.columns.domain')}</TableHead>
              <TableHead>{t('domains.columns.status')}</TableHead>
              <TableHead className="w-12">
                <span className="sr-only">{t('domains.columns.actions')}</span>
              </TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {data.domains.map((domain) => (
              <TableRow key={domain.id} data-testid="domain-row">
                <TableCell className="max-w-48">
                  <DomainName domain={domain} />
                </TableCell>
                <TableCell>
                  <DomainStatus domain={domain} />
                </TableCell>
                <TableCell>
                  <DropdownMenu>
                    <DropdownMenuTrigger asChild>
                      <Button variant="ghost" size="icon" aria-label={t('domains.actionsFor', { domain: domain.name })}>
                        <MoreHorizontal className="size-4" />
                      </Button>
                    </DropdownMenuTrigger>
                    <DropdownMenuContent align="end">
                      {!off ? <DropdownMenuItem onSelect={() => setWizard(domain)}>{t('domains.review')}</DropdownMenuItem> : null}
                      {!off && domain.addressCount > 0 ? (
                        <DropdownMenuItem onSelect={() => setCatchAll(domain)}>{t('domains.setCatchAll')}</DropdownMenuItem>
                      ) : null}
                      <DropdownMenuItem className="text-destructive" onSelect={() => setDeleting(domain)}>
                        {t('domains.delete')}
                      </DropdownMenuItem>
                    </DropdownMenuContent>
                  </DropdownMenu>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      )}
      {!off ? (
        <p className="text-sm text-muted-foreground" data-testid="domains-used">
          {t('domains.used', { used: data.used, count: data.max })}
        </p>
      ) : null}

      {wizard ? <DomainWizard initial={wizard === 'new' ? undefined : wizard} onClose={() => setWizard(null)} /> : null}
      {catchAll ? <CatchAllDialog domain={catchAll} onClose={() => setCatchAll(null)} /> : null}
      <ConfirmDestructive
        open={deleting !== null}
        onOpenChange={(open) => {
          // One domain's refusal never shows on the next one's dialog.
          if (open) return
          setDeleting(null)
          remove.reset()
        }}
        title={t('domains.deleteTitle')}
        description={<Trans i18nKey="domains.deleteBody" values={{ domain: deleting?.name ?? '' }} components={{ strong: <strong /> }} />}
        warning={t('domains.deleteSure')}
        submit={t('domains.delete')}
        pending={remove.isPending}
        error={remove.error}
        errorFallback={t('common.tryAgain')}
        onConfirm={() =>
          deleting &&
          remove.mutate(deleting.id, {
            onSuccess: () => {
              setDeleting(null)
              toast.success(t('domains.deleted'))
            },
          })
        }
      />
    </PageBody>
  )
}
