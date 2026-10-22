import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import api from '@kutup/session/client'
import { Alert } from '@kutup/ui/components/alert'
import { Badge } from '@kutup/ui/components/badge'
import { Button } from '@kutup/ui/components/button'
import { ConfirmDestructive } from '@kutup/ui/components/confirm-destructive'
import { Field } from '@kutup/ui/components/field'
import { Input } from '@kutup/ui/components/input'
import { PageBody, PageHeader } from '@kutup/ui/components/page'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@kutup/ui/components/select'
import { EmptyState, LoadingPanel } from '@kutup/ui/components/states'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@kutup/ui/components/table'
import { apiErrorMessage } from '@kutup/ui/lib/apiError'
import { formatInstant } from '@kutup/ui/lib/format'
import { adminKey } from './api'

// Mail → Domains for administrators (docs/plans/mail-custom-domains.md §7,
// §11): every custom domain with its owner and states, approving them in
// the `approve` mode, deactivating one (its name blocked until lifted), the
// blocked names, the DKIM keys' records to publish, and every
// `mail_domains.*` setting. Proton has no counterpart: its operators run
// this out of sight.

interface DkimKey {
  selector: string
  state: 'pending' | 'active' | 'retiring'
  host: string
  txt: string
  publishedSince: string | null
}

interface AdminDomain {
  id: string
  name: string
  owner: string
  state: number
  verifyState: number
  mxState: number
  spfState: number
  dkimState: number
  dmarcState: number
  approved: boolean
  stopped: boolean
  blocked: boolean
  createdAt: string
}

interface AdminDomains {
  stalwartDriftAt: string | null
  configured: boolean
  settings: Record<string, string>
  spf: DkimKey
  dkimKeys: DkimKey[]
  domains: AdminDomain[]
}

interface DomainBlock {
  name: string
  blockedAt: string
  blockedBy: string | null
}

/** The numeric settings, in the order the page shows them, with their ranges (the server's `KEYS`). */
const NUMBERS: [string, number, number][] = [
  ['mail_domains.per_account', 0, 100],
  ['mail_domains.addresses_per_account', 1, 1000],
  ['mail_domains.on_server', 0, 1_000_000],
  ['mail_domains.adds_per_day', 1, 1000],
  ['mail_domains.pending_days', 1, 365],
  ['mail_domains.catch_all_per_day', 0, 100_000],
  ['mail_domains.grace_warn_days', 1, 365],
  ['mail_domains.grace_stopped_hours', 1, 720],
  ['mail_domains.refreshes_at_once', 1, 1000],
  ['mail_domains.check_timeout_seconds', 10, 600],
]

const domainsAdminKey = [...adminKey, 'mail', 'domains'] as const
const blocksKey = [...domainsAdminKey, 'blocks'] as const

/** The settings' i18n key: `mail_domains.per_account` → `perAccount`. */
function settingKey(key: string): string {
  return key.replace('mail_domains.', '').replace(/_([a-z])/g, (_, c: string) => c.toUpperCase())
}

export function MailDomainsPage() {
  const { t, i18n } = useTranslation()
  const queryClient = useQueryClient()
  const view = useQuery({
    queryKey: domainsAdminKey,
    queryFn: async () => (await api.get<AdminDomains>('/admin/mail/domains')).data,
  })
  const blocks = useQuery({
    queryKey: blocksKey,
    queryFn: async () => (await api.get<DomainBlock[]>('/admin/mail/domains/blocks')).data,
  })
  const refresh = () => void queryClient.invalidateQueries({ queryKey: domainsAdminKey })
  const failed = (e: unknown) => toast.error(apiErrorMessage(e, t('common.tryAgain')))
  const approve = useMutation({
    mutationFn: async (id: string) => api.post(`/admin/mail/domains/${id}/approve`),
    onSuccess: () => toast.success(t('admin.mailDomains.approved')),
    onError: failed,
    onSettled: refresh,
  })
  const deactivate = useMutation({
    mutationFn: async (id: string) => api.post(`/admin/mail/domains/${id}/deactivate`),
    onSettled: refresh,
  })
  const unblock = useMutation({
    mutationFn: async (name: string) => api.delete(`/admin/mail/domains/blocks/${encodeURIComponent(name)}`),
    onSuccess: () => toast.success(t('admin.mailDomains.unblocked')),
    onError: failed,
    onSettled: () => void queryClient.invalidateQueries({ queryKey: blocksKey }),
  })
  const [ending, setEnding] = useState<AdminDomain | null>(null)

  if (view.isPending) return <LoadingPanel label={t('common.loading')} />
  if (view.isError) return <Alert variant="error">{apiErrorMessage(view.error, t('common.tryAgain'))}</Alert>
  const data = view.data
  const mode = data.settings['mail_domains.mode'] ?? 'everyone'

  return (
    <PageBody>
      <PageHeader title={t('admin.mailDomains.title')} description={t('admin.mailDomains.description')} />
      {!data.configured ? <Alert variant="warn">{t('admin.mailDomains.notConfigured')}</Alert> : null}
      {data.stalwartDriftAt ? (
        <Alert variant="warn">{t('admin.mailDomains.drift', { date: formatInstant(data.stalwartDriftAt, i18n.language) ?? '' })}</Alert>
      ) : null}

      <section className="space-y-3" aria-labelledby="mail-domains-records">
        <h2 id="mail-domains-records" className="text-base font-semibold">
          {t('admin.mailDomains.recordsTitle')}
        </h2>
        <p className="text-sm text-muted-foreground">{t('admin.mailDomains.recordsHint')}</p>
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>{t('admin.mailDomains.host')}</TableHead>
              <TableHead>{t('admin.mailDomains.value')}</TableHead>
              <TableHead>{t('admin.mailDomains.state')}</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {[data.spf, ...data.dkimKeys].map((key) => (
              <TableRow key={`${key.host}-${key.selector}`} data-testid="admin-dkim-key">
                <TableCell className="font-mono text-xs">{key.host}</TableCell>
                <TableCell className="max-w-96 truncate font-mono text-xs" title={key.txt}>
                  TXT {key.txt}
                </TableCell>
                <TableCell>
                  <Badge variant={key.state === 'active' ? 'ok' : key.state === 'pending' ? 'warn' : 'neutral'}>
                    {t(`admin.mailDomains.keyStates.${key.state}`)}
                  </Badge>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </section>

      <section className="space-y-3" aria-labelledby="mail-domains-list">
        <h2 id="mail-domains-list" className="text-base font-semibold">
          {t('admin.mailDomains.domainsTitle')}
        </h2>
        {data.domains.length === 0 ? (
          <EmptyState title={t('admin.mailDomains.empty')} description={t('admin.mailDomains.emptyHint')} />
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>{t('admin.mailDomains.domain')}</TableHead>
                <TableHead>{t('admin.mailDomains.owner')}</TableHead>
                <TableHead>{t('admin.mailDomains.state')}</TableHead>
                <TableHead>
                  <span className="sr-only">{t('admin.mailDomains.actions')}</span>
                </TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {data.domains.map((domain) => {
                const verified = domain.state === 1 || domain.state === 2
                return (
                  <TableRow key={domain.id} data-testid="admin-domain-row">
                    <TableCell className="font-medium">{domain.name}</TableCell>
                    <TableCell>{domain.owner}</TableCell>
                    <TableCell>
                      <span className="flex flex-wrap gap-1">
                        <Badge variant={domain.state === 1 ? 'ok' : domain.state === 2 ? 'warn' : 'neutral'}>
                          {t(`admin.mailDomains.states.${domain.state === 1 ? 'verified' : domain.state === 2 ? 'warn' : 'pending'}`)}
                        </Badge>
                        {verified && !domain.approved && mode === 'approve' ? <Badge variant="warn">{t('admin.mailDomains.awaiting')}</Badge> : null}
                        {domain.stopped ? <Badge variant="danger">{t('admin.mailDomains.stopped')}</Badge> : null}
                        {domain.blocked ? <Badge variant="danger">{t('admin.mailDomains.blocked')}</Badge> : null}
                      </span>
                    </TableCell>
                    <TableCell className="text-right">
                      <span className="flex justify-end gap-2">
                        {verified && !domain.approved && mode === 'approve' ? (
                          <Button size="sm" onClick={() => approve.mutate(domain.id)} loading={approve.isPending && approve.variables === domain.id}>
                            {t('admin.mailDomains.approve')}
                          </Button>
                        ) : null}
                        {!domain.blocked ? (
                          <Button size="sm" variant="ghost" className="text-destructive" onClick={() => setEnding(domain)}>
                            {t('admin.mailDomains.deactivate')}
                          </Button>
                        ) : null}
                      </span>
                    </TableCell>
                  </TableRow>
                )
              })}
            </TableBody>
          </Table>
        )}
      </section>

      <section className="space-y-3" aria-labelledby="mail-domains-blocks">
        <h2 id="mail-domains-blocks" className="text-base font-semibold">
          {t('admin.mailDomains.blocksTitle')}
        </h2>
        {(blocks.data ?? []).length === 0 ? (
          <p className="text-sm text-muted-foreground">{t('admin.mailDomains.noBlocks')}</p>
        ) : (
          <ul className="divide-y divide-border rounded-lg border border-border">
            {(blocks.data ?? []).map((block) => (
              <li key={block.name} className="flex items-center justify-between gap-3 px-3 py-2 text-sm" data-testid="admin-domain-block">
                <span>
                  <span className="font-medium">{block.name}</span>{' '}
                  <span className="text-muted-foreground">
                    {t('admin.mailDomains.blockedBy', {
                      date: formatInstant(block.blockedAt, i18n.language) ?? '',
                      by: block.blockedBy ?? t('admin.mailDomains.formerAdmin'),
                    })}
                  </span>
                </span>
                <Button size="sm" variant="outline" onClick={() => unblock.mutate(block.name)} loading={unblock.isPending && unblock.variables === block.name}>
                  {t('admin.mailDomains.unblock')}
                </Button>
              </li>
            ))}
          </ul>
        )}
      </section>

      <SettingsForm settings={data.settings} onSaved={refresh} />

      <ConfirmDestructive
        open={ending !== null}
        onOpenChange={(open) => !open && setEnding(null)}
        title={t('admin.mailDomains.deactivateTitle', { domain: ending?.name ?? '' })}
        description={t('admin.mailDomains.deactivateBody', { domain: ending?.name ?? '', owner: ending?.owner ?? '' })}
        warning={t('admin.mailDomains.deactivateWarning')}
        submit={t('admin.mailDomains.deactivate')}
        confirmPhrase={ending?.name}
        pending={deactivate.isPending}
        error={deactivate.error}
        errorFallback={t('common.tryAgain')}
        onConfirm={() =>
          ending &&
          deactivate.mutate(ending.id, {
            onSuccess: () => {
              setEnding(null)
              toast.success(t('admin.mailDomains.deactivated'))
              void queryClient.invalidateQueries({ queryKey: blocksKey })
            },
          })
        }
      />
    </PageBody>
  )
}

/** Every `mail_domains.*` setting, checked against its range, saved together. */
function SettingsForm({ settings, onSaved }: { settings: Record<string, string>; onSaved: () => void }) {
  const { t } = useTranslation()
  const [values, setValues] = useState(settings)
  useEffect(() => setValues(settings), [settings])
  const save = useMutation({
    mutationFn: async (changed: Record<string, string>) => api.put('/admin/mail/domains/settings', changed),
    onSuccess: () => {
      toast.success(t('admin.mailDomains.saved'))
      onSaved()
    },
    onError: (e) => toast.error(apiErrorMessage(e, t('common.tryAgain'))),
  })
  const changed = Object.fromEntries(Object.entries(values).filter(([key, value]) => settings[key] !== value))
  const wrong = NUMBERS.find(([key, min, max]) => {
    const value = Number(values[key])
    return !Number.isInteger(value) || value < min || value > max
  })
  return (
    <section className="max-w-2xl space-y-4" aria-labelledby="mail-domains-settings">
      <h2 id="mail-domains-settings" className="text-base font-semibold">
        {t('admin.mailDomains.settingsTitle')}
      </h2>
      <Field label={t('admin.mailDomains.settings.mode')} description={t('admin.mailDomains.settings.modeHint')}>
        {(props) => (
          <Select value={values['mail_domains.mode'] ?? 'everyone'} onValueChange={(mode) => setValues({ ...values, 'mail_domains.mode': mode })}>
            <SelectTrigger {...props} className="w-64">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {(['everyone', 'approve', 'off'] as const).map((mode) => (
                <SelectItem key={mode} value={mode}>
                  {t(`admin.mailDomains.modes.${mode}`)}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        )}
      </Field>
      <Field label={t('admin.mailDomains.settings.catchAll')}>
        {(props) => (
          <Select value={values['mail_domains.catch_all'] ?? '1'} onValueChange={(on) => setValues({ ...values, 'mail_domains.catch_all': on })}>
            <SelectTrigger {...props} className="w-64">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="1">{t('admin.mailDomains.on')}</SelectItem>
              <SelectItem value="0">{t('admin.mailDomains.off')}</SelectItem>
            </SelectContent>
          </Select>
        )}
      </Field>
      {NUMBERS.map(([key, min, max]) => (
        <Field key={key} label={t(`admin.mailDomains.settings.${settingKey(key)}`)} description={t('admin.mailDomains.range', { min, max })}>
          {(props) => (
            <Input
              {...props}
              type="number"
              min={min}
              max={max}
              className="w-40"
              value={values[key] ?? ''}
              onChange={(e) => setValues({ ...values, [key]: e.target.value })}
            />
          )}
        </Field>
      ))}
      {wrong ? <Alert variant="error">{t('admin.mailDomains.outOfRange', { setting: t(`admin.mailDomains.settings.${settingKey(wrong[0])}`), min: wrong[1], max: wrong[2] })}</Alert> : null}
      <Button onClick={() => save.mutate(changed)} disabled={Object.keys(changed).length === 0 || wrong !== undefined} loading={save.isPending}>
        {t('common.save')}
      </Button>
    </section>
  )
}
