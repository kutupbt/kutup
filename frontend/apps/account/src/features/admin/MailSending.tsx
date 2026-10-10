import { useQuery } from '@tanstack/react-query'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import api from '@kutup/session/client'
import { Badge } from '@kutup/ui/components/badge'
import { Button } from '@kutup/ui/components/button'
import { Card } from '@kutup/ui/components/card'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@kutup/ui/components/dialog'
import { Field } from '@kutup/ui/components/field'
import { Input } from '@kutup/ui/components/input'
import { Fact } from '@kutup/ui/components/page'
import { Skeleton } from '@kutup/ui/components/skeleton'
import { apiErrorMessage } from '@kutup/ui/lib/apiError'
import { formatInstant } from '@kutup/ui/lib/format'
import { sendersKey, useUpdateMailSending, type Change, type MailSender } from './mailSendingApi'

// Sending safety for administrators (docs/plans/mail.md): what an account
// sends outside the server, its limits, pause and flag. Counts only.

/** One account's limits: empty means the server's. */
export function LimitsDialog({ sender, onClose, onSave, pending }: { sender: MailSender; onClose: () => void; onSave: (change: Change) => void; pending: boolean }) {
  const { t } = useTranslation()
  const [perHour, setPerHour] = useState(sender.perHour?.toString() ?? '')
  const [perDay, setPerDay] = useState(sender.perDay?.toString() ?? '')
  const parse = (value: string) => (value.trim() === '' ? null : Math.max(0, Math.min(100_000, Number.parseInt(value, 10) || 0)))
  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{t('admin.mailSending.limitsTitle', { name: sender.username || sender.email })}</DialogTitle>
          <DialogDescription>{t('admin.mailSending.limitsDescription')}</DialogDescription>
        </DialogHeader>
        <Field label={t('admin.mailSending.perHour')}>
          {(field) => <Input {...field} inputMode="numeric" value={perHour} onChange={(e) => setPerHour(e.target.value)} placeholder={t('admin.mailSending.serverLimit')} />}
        </Field>
        <Field label={t('admin.mailSending.perDay')}>
          {(field) => <Input {...field} inputMode="numeric" value={perDay} onChange={(e) => setPerDay(e.target.value)} placeholder={t('admin.mailSending.serverLimit')} />}
        </Field>
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>
            {t('common.cancel')}
          </Button>
          <Button disabled={pending} onClick={() => onSave({ perHour: parse(perHour), perDay: parse(perDay) })}>
            {t('common.save')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

/** Paused and flagged badges, or "sending normally". */
export function SendingState({ sender }: { sender: MailSender }) {
  const { t, i18n } = useTranslation()
  if (!sender.pausedReason && !sender.flagReason) {
    return <span className="text-sm text-muted-foreground">{t('admin.mailSending.ok')}</span>
  }
  return (
    <span className="space-x-1">
      {sender.pausedReason ? (
        <Badge variant="danger" title={formatInstant(sender.pausedAt, i18n.language) ?? undefined}>
          {t(`admin.mailSending.paused.${sender.pausedReason}`)}
        </Badge>
      ) : null}
      {sender.flagReason ? (
        <Badge variant="warn" title={formatInstant(sender.flaggedAt, i18n.language) ?? undefined}>
          {t(`admin.mailSending.flagged.${sender.flagReason}`)}
        </Badge>
      ) : null}
    </span>
  )
}

/** The user page's "Mail sending" card: one account, even before it sends. */
export function MailSendingCard({ userId }: { userId: string }) {
  const { t } = useTranslation()
  const [editing, setEditing] = useState(false)
  const sender = useQuery({
    queryKey: [...sendersKey, 'one', userId],
    queryFn: async () => (await api.get<MailSender>(`/admin/users/${userId}/mail-sending`)).data,
  })
  const update = useUpdateMailSending(() => setEditing(false))
  if (sender.isPending) return <Skeleton className="h-24 w-full" />
  if (sender.isError) return <p className="p-4 text-sm text-destructive">{apiErrorMessage(sender.error, t('common.tryAgain'))}</p>
  const s = sender.data
  return (
    <Card className="space-y-3 p-4">
      <div className="grid gap-3 sm:grid-cols-3">
        <Fact label={t('admin.mailSending.sentDay')}>{s.sentDay}</Fact>
        <Fact label={t('admin.mailSending.sentWeek')}>{s.sentWeek}</Fact>
        <Fact label={t('admin.mailSending.bounces')}>{s.bouncesWeek}</Fact>
        <Fact label={t('admin.mailSending.limits')}>
          {s.perHour === null && s.perDay === null
            ? t('admin.mailSending.serverLimits')
            : t('admin.mailSending.ownLimits', { hour: s.perHour ?? '—', day: s.perDay ?? '—' })}
        </Fact>
        <Fact label={t('admin.mailSending.state')}>
          <SendingState sender={s} />
        </Fact>
      </div>
      <div className="flex flex-wrap gap-2">
        <Button size="sm" variant="outline" disabled={update.isPending} onClick={() => update.mutate({ userId, change: { paused: !s.pausedReason } })}>
          {s.pausedReason ? t('admin.mailSending.resume') : t('admin.mailSending.pause')}
        </Button>
        {s.flagReason ? (
          <Button size="sm" variant="ghost" onClick={() => update.mutate({ userId, change: { clearFlag: true } })}>
            {t('admin.mailSending.clearFlag')}
          </Button>
        ) : null}
        <Button size="sm" variant="ghost" onClick={() => setEditing(true)}>
          {t('admin.mailSending.editLimits')}
        </Button>
      </div>
      {editing ? (
        <LimitsDialog sender={s} pending={update.isPending} onClose={() => setEditing(false)} onSave={(change) => update.mutate({ userId, change })} />
      ) : null}
    </Card>
  )
}
