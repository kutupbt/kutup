import { ArrowRight, Forward, Plus } from 'lucide-react'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import {
  forwardeeActions,
  forwarderActions,
  useAcceptForwarding,
  useForwardingAction,
  useForwardings,
  useOwnAddresses,
  useRenewForwarding,
  type MailForwarding,
} from '@kutup/mail-core/forwardings'
import { encryptionOff, type CheckedAddress } from '@kutup/mail-core/keyList'
import { Alert } from '@kutup/ui/components/alert'
import { Badge } from '@kutup/ui/components/badge'
import { Button } from '@kutup/ui/components/button'
import { ConfirmDestructive } from '@kutup/ui/components/confirm-destructive'
import { PageBody, PageHeader } from '@kutup/ui/components/page'
import { EmptyState, LoadingPanel } from '@kutup/ui/components/states'
import { Tabs, TabsList, TabsTrigger } from '@kutup/ui/components/tabs'
import { ForwardingDialog } from './ForwardingDialog'
import { describeForwarding, forwardingErrorMessage } from './forwardingText'

const STATE_BADGE: Record<MailForwarding['state'], 'ok' | 'warn' | 'neutral' | 'danger'> = {
  active: 'ok',
  pending: 'neutral',
  paused: 'neutral',
  outdated: 'warn',
  rejected: 'danger',
}

/**
 * Settings → Forwarding (Proton's `ForwardSection`): "From me", this
 * account's forwardings, and "To me", those to it, each with its state and
 * what may be done in that state (docs/plans/mail-forwarding.md).
 */
export function ForwardingSettingsPage() {
  const { t } = useTranslation()
  const forwardings = useForwardings()
  const addresses = useOwnAddresses()
  const [tab, setTab] = useState<'outgoing' | 'incoming'>('outgoing')
  const [editing, setEditing] = useState<MailForwarding | 'new' | null>(null)

  if (forwardings.isPending || addresses.isPending) return <LoadingPanel label={t('common.loading')} />
  if (forwardings.isError || addresses.isError) {
    return <Alert variant="error">{forwardingErrorMessage(forwardings.error ?? addresses.error, t)}</Alert>
  }
  // Only the current address sends, so only it forwards (the server's rule).
  const current = addresses.data.find((address) => address.state === 'active')
  const offFor = addresses.data.filter((address) => address.state === 'active' && encryptionOff(address))
  const list = forwardings.data[tab]

  return (
    <PageBody>
      <PageHeader
        title={t('forwarding.title')}
        description={t('forwarding.description')}
        actions={
          current ? (
            <Button onClick={() => setEditing('new')} data-testid="forwarding-add">
              <Plus />
              {t('forwarding.add')}
            </Button>
          ) : null
        }
      />
      {offFor.map((address) => (
        <Alert key={address.id} variant="warn" data-testid="forwarding-encryption-off">
          {t('forwarding.encryptionOff', { address: address.address })}
        </Alert>
      ))}
      <Tabs value={tab} onValueChange={(value) => setTab(value as typeof tab)}>
        <TabsList>
          <TabsTrigger value="outgoing">{t('forwarding.fromMe')}</TabsTrigger>
          <TabsTrigger value="incoming">{t('forwarding.toMe')}</TabsTrigger>
        </TabsList>
      </Tabs>
      {list.length === 0 ? (
        <EmptyState
          title={t(tab === 'outgoing' ? 'forwarding.emptyFromMe' : 'forwarding.emptyToMe')}
          description={t(tab === 'outgoing' ? 'forwarding.emptyFromMeHint' : 'forwarding.emptyToMeHint')}
        />
      ) : (
        <ul className="rounded-lg border border-border" data-testid={`forwarding-list-${tab}`}>
          {list.map((forwarding) =>
            tab === 'outgoing' ? (
              <OutgoingRow key={forwarding.id} forwarding={forwarding} from={current} onEdit={() => setEditing(forwarding)} />
            ) : (
              <IncomingRow key={forwarding.id} forwarding={forwarding} addresses={addresses.data} />
            ),
          )}
        </ul>
      )}
      {editing && current ? (
        <ForwardingDialog from={current} forwarding={editing === 'new' ? undefined : editing} onClose={() => setEditing(null)} />
      ) : null}
    </PageBody>
  )
}

function Row({ forwarding, from, to, children }: { forwarding: MailForwarding; from: string; to: string; children: React.ReactNode }) {
  const { t } = useTranslation()
  return (
    <li className="flex flex-wrap items-start gap-3 border-b border-border px-3 py-3 last:border-b-0" data-testid="forwarding-row" data-state={forwarding.state}>
      <Forward className="mt-0.5 size-4 shrink-0 text-muted-foreground" aria-hidden />
      <div className="min-w-0 flex-1 space-y-1">
        <p className="flex flex-wrap items-center gap-2 text-sm font-medium">
          <span className="truncate">{from}</span>
          <ArrowRight className="size-3.5 text-muted-foreground" aria-label={t('forwarding.to')} />
          <span className="truncate">{to}</span>
          <Badge variant={STATE_BADGE[forwarding.state]}>{t(`forwarding.state.${forwarding.state}`)}</Badge>
          <Badge variant={forwarding.kind === 'end_to_end' ? 'ok' : 'warn'}>{t(`forwarding.kind.${forwarding.kind}`)}</Badge>
        </p>
        <p className="text-xs text-muted-foreground">{describeForwarding(forwarding, t)}</p>
        {forwarding.notice ? <p className="text-xs text-status-warn">{t(`forwarding.notice.${forwarding.notice}`)}</p> : null}
        {forwarding.skipped > 0 ? <p className="text-xs text-muted-foreground">{t('forwarding.skipped', { count: forwarding.skipped })}</p> : null}
      </div>
      <div className="flex flex-wrap items-center gap-2">{children}</div>
    </li>
  )
}

function OutgoingRow({ forwarding, from, onEdit }: { forwarding: MailForwarding; from: CheckedAddress | undefined; onEdit: () => void }) {
  const { t } = useTranslation()
  const action = useForwardingAction()
  const renew = useRenewForwarding()
  const [deleting, setDeleting] = useState(false)
  const run = (kind: 'pause' | 'resume' | 'reinvite', done: string) =>
    action.mutate(
      { id: forwarding.id, action: kind },
      { onSuccess: () => toast.success(done), onError: (e) => toast.error(forwardingErrorMessage(e, t)) },
    )
  const busy = action.isPending || renew.isPending
  return (
    <Row forwarding={forwarding} from={forwarding.forwarderAddress} to={forwarding.forwardeeEmail}>
      {forwarderActions(forwarding).map((kind) =>
        kind === 'edit' ? (
          <Button key={kind} variant="outline" size="sm" onClick={onEdit} disabled={busy}>
            {t('forwarding.edit')}
          </Button>
        ) : kind === 'pause' ? (
          <Button key={kind} variant="outline" size="sm" disabled={busy} onClick={() => run('pause', t('forwarding.paused'))}>
            {t('forwarding.pause')}
          </Button>
        ) : kind === 'resume' ? (
          <Button key={kind} variant="outline" size="sm" disabled={busy} onClick={() => run('resume', t('forwarding.resumed'))}>
            {t('forwarding.resume')}
          </Button>
        ) : kind === 'reinvite' ? (
          <Button key={kind} variant="outline" size="sm" disabled={busy} onClick={() => run('reinvite', t('forwarding.reinvited', { to: forwarding.forwardeeEmail }))}>
            {t('forwarding.reinvite')}
          </Button>
        ) : kind === 'renew' ? (
          <Button
            key={kind}
            variant="outline"
            size="sm"
            disabled={busy || !from}
            loading={renew.isPending}
            onClick={() =>
              from &&
              renew.mutate(
                { forwarding, from },
                { onSuccess: () => toast.success(t('forwarding.renewed')), onError: (e) => toast.error(forwardingErrorMessage(e, t)) },
              )
            }
          >
            {t('forwarding.renew')}
          </Button>
        ) : (
          <Button key={kind} variant="ghost" size="sm" className="text-destructive" disabled={busy} onClick={() => setDeleting(true)}>
            {t('forwarding.delete')}
          </Button>
        ),
      )}
      <ConfirmDestructive
        open={deleting}
        onOpenChange={setDeleting}
        title={t('forwarding.deleteTitle')}
        description={t(forwarding.kind === 'outside' ? 'forwarding.deleteOutsideDescription' : 'forwarding.deleteDescription', { to: forwarding.forwardeeEmail })}
        submit={t('forwarding.delete')}
        pending={action.isPending}
        error={action.error}
        errorFallback={t('common.tryAgain')}
        onConfirm={() =>
          action.mutate(
            { id: forwarding.id, action: 'delete' },
            {
              onSuccess: () => {
                toast.success(t('forwarding.deleted'))
                setDeleting(false)
              },
            },
          )
        }
      />
    </Row>
  )
}

function IncomingRow({ forwarding, addresses }: { forwarding: MailForwarding; addresses: CheckedAddress[] }) {
  const { t } = useTranslation()
  const action = useForwardingAction()
  const accept = useAcceptForwarding()
  const [deleting, setDeleting] = useState(false)
  const to = addresses.find((address) => address.address === forwarding.forwardeeEmail)
  const busy = action.isPending || accept.isPending
  return (
    <Row forwarding={forwarding} from={forwarding.forwarderAddress} to={forwarding.forwardeeEmail}>
      {forwardeeActions(forwarding).map((kind) =>
        kind === 'accept' ? (
          <Button
            key={kind}
            size="sm"
            disabled={busy || !to}
            loading={accept.isPending}
            data-testid="forwarding-accept"
            onClick={() =>
              to &&
              accept.mutate(
                { forwarding, to },
                {
                  onSuccess: () => toast.success(t('forwarding.accepted', { from: forwarding.forwarderAddress })),
                  onError: (e) => toast.error(forwardingErrorMessage(e, t, t('forwarding.acceptFailed'))),
                },
              )
            }
          >
            {t('forwarding.accept')}
          </Button>
        ) : kind === 'decline' ? (
          <Button
            key={kind}
            variant="outline"
            size="sm"
            disabled={busy}
            onClick={() =>
              action.mutate(
                { id: forwarding.id, action: 'decline' },
                { onSuccess: () => toast.success(t('forwarding.declined')), onError: (e) => toast.error(forwardingErrorMessage(e, t)) },
              )
            }
          >
            {t('forwarding.decline')}
          </Button>
        ) : (
          <Button key={kind} variant="ghost" size="sm" className="text-destructive" disabled={busy} onClick={() => setDeleting(true)}>
            {t('forwarding.delete')}
          </Button>
        ),
      )}
      <ConfirmDestructive
        open={deleting}
        onOpenChange={setDeleting}
        title={t('forwarding.deleteTitle')}
        description={t('forwarding.deleteIncomingDescription', { from: forwarding.forwarderAddress })}
        submit={t('forwarding.delete')}
        pending={action.isPending}
        error={action.error}
        errorFallback={t('common.tryAgain')}
        onConfirm={() =>
          action.mutate(
            { id: forwarding.id, action: 'delete' },
            {
              onSuccess: () => {
                toast.success(t('forwarding.deleted'))
                setDeleting(false)
              },
            },
          )
        }
      />
    </Row>
  )
}
