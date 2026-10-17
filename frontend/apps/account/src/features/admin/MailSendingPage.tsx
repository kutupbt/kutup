import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Link } from 'react-router-dom'
import api from '@kutup/session/client'
import { Alert } from '@kutup/ui/components/alert'
import { Button } from '@kutup/ui/components/button'
import { Checkbox } from '@kutup/ui/components/checkbox'
import { PageBody, PageHeader } from '@kutup/ui/components/page'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@kutup/ui/components/select'
import { EmptyState, LoadingPanel } from '@kutup/ui/components/states'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@kutup/ui/components/table'
import { apiErrorMessage } from '@kutup/ui/lib/apiError'
import { toast } from 'sonner'
import { adminKey } from './api'
import { LimitsDialog, SendingState } from './MailSending'
import { sendersKey, useUpdateMailSending, type MailSender } from './mailSendingApi'

type Policy = 'off' | 'admins' | 'on'
const POLICIES: Policy[] = ['off', 'admins', 'on']
const policyKey = [...adminKey, 'mail-outside-sending'] as const

/**
 * Who may send mail to outside addresses: nobody, administrators, or
 * everyone. Stored by the server and applied at once; MAIL_OUTSIDE_SENDING
 * only gives its first value (docs/self-hosting.md).
 */
function OutsidePolicy() {
  const { t } = useTranslation()
  const queryClient = useQueryClient()
  const policy = useQuery({
    queryKey: policyKey,
    queryFn: async () => (await api.get<{ outsideSending: Policy }>('/admin/mail/outside-sending')).data.outsideSending,
  })
  const save = useMutation({
    mutationFn: async (outsideSending: Policy) => (await api.put<{ outsideSending: Policy }>('/admin/mail/outside-sending', { outsideSending })).data.outsideSending,
    onSuccess: async (value) => {
      queryClient.setQueryData(policyKey, value)
      toast.success(t('admin.mailSending.policySaved'))
      await queryClient.invalidateQueries({ queryKey: ['mail'] })
    },
    onError: (error) => toast.error(apiErrorMessage(error, t('common.tryAgain'))),
  })
  if (policy.isError) return <Alert variant="error">{apiErrorMessage(policy.error, t('common.tryAgain'))}</Alert>
  return (
    <section className="mb-6 flex flex-col gap-3 rounded-lg border border-border p-4 sm:flex-row sm:items-center sm:justify-between">
      <span>
        <label htmlFor="outside-sending" className="block text-sm font-medium">
          {t('admin.mailSending.policyLabel')}
        </label>
        <span className="block text-sm text-muted-foreground">{t('admin.mailSending.policyHint')}</span>
      </span>
      <Select value={policy.data ?? ''} disabled={policy.isPending || save.isPending} onValueChange={(value) => save.mutate(value as Policy)}>
        <SelectTrigger id="outside-sending" className="sm:w-56" aria-label={t('admin.mailSending.policyLabel')}>
          <SelectValue placeholder={t('common.loading')} />
        </SelectTrigger>
        <SelectContent>
          {POLICIES.map((value) => (
            <SelectItem key={value} value={value}>
              {t(`admin.mailSending.policy.${value}`)}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
    </section>
  )
}

/**
 * Who sends mail outside the server, and how it goes (docs/plans/mail.md,
 * sending safety): counts only, never content. Paused and flagged accounts
 * first; pause, resume, clear a flag, or set an account's own limits.
 */
export function MailSendingPage() {
  const { t } = useTranslation()
  const [attention, setAttention] = useState(false)
  const [editing, setEditing] = useState<MailSender | null>(null)
  const senders = useQuery({
    queryKey: [...sendersKey, attention],
    queryFn: async () => (await api.get<MailSender[]>('/admin/mail/senders', { params: { attention } })).data,
  })
  const update = useUpdateMailSending(() => setEditing(null))

  return (
    <PageBody>
      <PageHeader title={t('admin.mailSending.title')} description={t('admin.mailSending.description')} />
      <OutsidePolicy />
      <label className="mb-4 flex items-center gap-2 text-sm">
        <Checkbox checked={attention} onCheckedChange={(on) => setAttention(on === true)} />
        {t('admin.mailSending.attentionOnly')}
      </label>
      {senders.isPending ? (
        <LoadingPanel label={t('common.loading')} />
      ) : senders.isError ? (
        <Alert variant="error">{apiErrorMessage(senders.error, t('common.tryAgain'))}</Alert>
      ) : senders.data.length === 0 ? (
        <EmptyState title={t('admin.mailSending.emptyTitle')} description={t('admin.mailSending.emptyDescription')} />
      ) : (
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>{t('admin.mailSending.account')}</TableHead>
              <TableHead className="text-right">{t('admin.mailSending.sentDay')}</TableHead>
              <TableHead className="text-right">{t('admin.mailSending.sentWeek')}</TableHead>
              <TableHead className="text-right">{t('admin.mailSending.bounces')}</TableHead>
              <TableHead>{t('admin.mailSending.limits')}</TableHead>
              <TableHead>{t('admin.mailSending.state')}</TableHead>
              <TableHead />
            </TableRow>
          </TableHeader>
          <TableBody>
            {senders.data.map((sender) => (
              <TableRow key={sender.userId}>
                <TableCell>
                  <Link to={`/admin/users/${sender.userId}`} className="font-medium hover:underline">
                    {sender.username}
                  </Link>
                </TableCell>
                <TableCell className="text-right tabular-nums">{sender.sentDay}</TableCell>
                <TableCell className="text-right tabular-nums">{sender.sentWeek}</TableCell>
                <TableCell className="text-right tabular-nums">{sender.bouncesWeek}</TableCell>
                <TableCell className="text-sm">
                  {sender.perHour === null && sender.perDay === null
                    ? t('admin.mailSending.serverLimits')
                    : t('admin.mailSending.ownLimits', { hour: sender.perHour ?? '—', day: sender.perDay ?? '—' })}
                </TableCell>
                <TableCell>
                  <SendingState sender={sender} />
                </TableCell>
                <TableCell className="whitespace-nowrap text-right">
                  {sender.pausedReason ? (
                    <Button size="sm" variant="outline" onClick={() => update.mutate({ userId: sender.userId, change: { paused: false } })}>
                      {t('admin.mailSending.resume')}
                    </Button>
                  ) : (
                    <Button size="sm" variant="outline" onClick={() => update.mutate({ userId: sender.userId, change: { paused: true } })}>
                      {t('admin.mailSending.pause')}
                    </Button>
                  )}{' '}
                  {sender.flagReason ? (
                    <Button size="sm" variant="ghost" onClick={() => update.mutate({ userId: sender.userId, change: { clearFlag: true } })}>
                      {t('admin.mailSending.clearFlag')}
                    </Button>
                  ) : null}{' '}
                  <Button size="sm" variant="ghost" onClick={() => setEditing(sender)}>
                    {t('admin.mailSending.editLimits')}
                  </Button>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      )}
      {editing ? (
        <LimitsDialog
          sender={editing}
          pending={update.isPending}
          onClose={() => setEditing(null)}
          onSave={(change) => update.mutate({ userId: editing.userId, change })}
        />
      ) : null}
    </PageBody>
  )
}
