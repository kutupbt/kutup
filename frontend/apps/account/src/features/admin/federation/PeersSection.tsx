import { Copy, FileSearch, RefreshCw } from 'lucide-react'
import { useMemo, useState, type FormEvent } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import type { FederationPeer } from '@kutup/session/api-types'
import { Alert } from '@kutup/ui/components/alert'
import { Badge } from '@kutup/ui/components/badge'
import { Button } from '@kutup/ui/components/button'
import { Card } from '@kutup/ui/components/card'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@kutup/ui/components/dialog'
import { Field } from '@kutup/ui/components/field'
import { Input } from '@kutup/ui/components/input'
import { Mono } from '@kutup/ui/components/mono'
import { Fact, Section } from '@kutup/ui/components/page'
import { EmptyState, LoadingPanel } from '@kutup/ui/components/states'
import { apiErrorMessage } from '@kutup/ui/lib/apiError'
import { copyText } from '@kutup/ui/lib/clipboard'
import { formatInstant } from '@kutup/ui/lib/format'
import { useBulkRetryPeers, usePeerAction, usePeerEvidence } from '../api'

function TrustBadge({ trust }: { trust: FederationPeer['trust'] }) {
  const { t } = useTranslation()
  const variant = trust === 'verified' ? 'ok' : trust === 'quarantined' ? 'danger' : 'neutral'
  return <Badge variant={variant}>{t(`admin.federation.peerTrust.${trust}`)}</Badge>
}

/**
 * Verification is an out-of-band comparison: the other server's operator
 * reads you their fingerprint, you paste it, and it must match exactly.
 */
function VerifyDialog({ peer, onClose }: { peer: FederationPeer; onClose: () => void }) {
  const { t } = useTranslation()
  const action = usePeerAction()
  const [typed, setTyped] = useState('')
  const matches = typed.trim() === peer.fingerprint
  function submit(e: FormEvent) {
    e.preventDefault()
    if (!matches) return
    action.mutate({ domain: peer.domain, action: 'verify', body: { fingerprint: peer.fingerprint } }, {
      onSuccess: () => { toast.success(t('admin.federation.verified', { domain: peer.domain })); onClose() },
    })
  }
  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{t('admin.federation.verifyTitle', { domain: peer.domain })}</DialogTitle>
          <DialogDescription>{t('admin.federation.verifyDescription')}</DialogDescription>
        </DialogHeader>
        <form className="space-y-4" onSubmit={submit}>
          <Fact label={t('admin.federation.pinned')}><Mono className="break-all">{peer.fingerprintDisplay}</Mono></Fact>
          <Field label={t('admin.federation.theirFingerprint')} error={typed && !matches ? t('admin.federation.fingerprintMismatch') : undefined} required>
            {(field) => <Input {...field} value={typed} onChange={(e) => setTyped(e.target.value)} className="font-mono" autoComplete="off" spellCheck={false} />}
          </Field>
          {action.isError ? <Alert variant="error">{apiErrorMessage(action.error, t('admin.federation.actionFailed'))}</Alert> : null}
          <DialogFooter>
            <Button type="button" variant="outline" onClick={onClose}>{t('common.cancel')}</Button>
            <Button type="submit" disabled={!matches} loading={action.isPending}>{t('admin.federation.verify')}</Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}

/** Break-glass: accept a changed identity for a quarantined peer. */
function RepinDialog({ peer, onClose }: { peer: FederationPeer; onClose: () => void }) {
  const { t } = useTranslation()
  const action = usePeerAction()
  const [fingerprint, setFingerprint] = useState('')
  const [domain, setDomain] = useState('')
  const ok = fingerprint.trim() === peer.pendingFingerprint && domain.trim() === peer.domain
  function submit(e: FormEvent) {
    e.preventDefault()
    if (!ok || !peer.pendingFingerprint) return
    action.mutate({
      domain: peer.domain,
      action: 'repin',
      body: { oldFingerprint: peer.fingerprint, newFingerprint: peer.pendingFingerprint, confirmDomain: peer.domain },
    }, { onSuccess: () => { toast.success(t('admin.federation.repinned', { domain: peer.domain })); onClose() } })
  }
  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent className="max-w-xl">
        <DialogHeader>
          <DialogTitle>{t('admin.federation.repinTitle', { domain: peer.domain })}</DialogTitle>
          <DialogDescription>{t('admin.federation.repinDescription')}</DialogDescription>
        </DialogHeader>
        <form className="space-y-4" onSubmit={submit}>
          {peer.quarantineReason ? <Alert variant="warn">{peer.quarantineReason}</Alert> : null}
          <Fact label={t('admin.federation.pinned')}><Mono className="break-all">{peer.fingerprint}</Mono></Fact>
          <Fact label={t('admin.federation.pending')}><Mono className="break-all">{peer.pendingFingerprint}</Mono></Fact>
          <Field label={t('admin.federation.theirNewFingerprint')} required>
            {(field) => <Input {...field} value={fingerprint} onChange={(e) => setFingerprint(e.target.value)} className="font-mono" autoComplete="off" spellCheck={false} />}
          </Field>
          <Field label={t('common.typeToConfirm', { phrase: peer.domain })} required>
            {(field) => <Input {...field} value={domain} onChange={(e) => setDomain(e.target.value)} autoComplete="off" spellCheck={false} />}
          </Field>
          {action.isError ? <Alert variant="error">{apiErrorMessage(action.error, t('admin.federation.actionFailed'))}</Alert> : null}
          <DialogFooter>
            <Button type="button" variant="outline" onClick={onClose}>{t('common.cancel')}</Button>
            <Button type="submit" variant="destructive" disabled={!ok} loading={action.isPending}>{t('admin.federation.repin')}</Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}

function EvidenceDialog({ domain, onClose }: { domain: string; onClose: () => void }) {
  const { t, i18n } = useTranslation()
  const evidence = usePeerEvidence(domain)
  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent className="max-w-2xl">
        <DialogHeader>
          <DialogTitle>{t('admin.federation.evidenceTitle', { domain })}</DialogTitle>
          <DialogDescription>{t('admin.federation.evidenceDescription')}</DialogDescription>
        </DialogHeader>
        {evidence.isPending ? <LoadingPanel label={t('common.loading')} /> : null}
        {evidence.isError ? <Alert variant="error">{apiErrorMessage(evidence.error, t('common.tryAgain'))}</Alert> : null}
        {evidence.data ? (
          <ol className="space-y-3">
            {evidence.data.documents.map((d) => (
              <li key={d.documentHash} className="rounded-md border border-border p-3 text-sm">
                <p className="flex flex-wrap items-center gap-2">
                  <Badge variant={d.acceptance === 'accepted' ? 'ok' : d.acceptance === 'quarantined' ? 'danger' : 'neutral'}>
                    {t(`admin.federation.acceptance.${d.acceptance}`)}
                  </Badge>
                  <Mono className="text-xs">#{d.sequence}</Mono>
                  <Mono className="text-xs text-muted-foreground">{formatInstant(d.recordedAt, i18n.language)}</Mono>
                </p>
                <Mono className="mt-2 block break-all text-xs">{d.fingerprintDisplay}</Mono>
              </li>
            ))}
            {evidence.data.truncated ? <p className="text-xs text-muted-foreground">{t('admin.federation.evidenceTruncated')}</p> : null}
          </ol>
        ) : null}
      </DialogContent>
    </Dialog>
  )
}

type Open = { kind: 'verify' | 'repin'; peer: FederationPeer } | { kind: 'evidence'; domain: string } | null

export function PeersSection({ peers }: { peers: FederationPeer[] }) {
  const { t, i18n } = useTranslation()
  const retry = usePeerAction()
  const bulk = useBulkRetryPeers()
  const [query, setQuery] = useState('')
  const [open, setOpen] = useState<Open>(null)
  const shown = useMemo(() => {
    const q = query.trim().toLowerCase()
    return q ? peers.filter((p) => p.domain.includes(q) || p.fingerprint.toLowerCase().includes(q)) : peers
  }, [peers, query])

  return (
    <Section
      title={t('admin.federation.peers')}
      description={t('admin.federation.peersHint')}
      actions={
        shown.length > 0 ? (
          <Button variant="outline" loading={bulk.isPending}
            onClick={() => bulk.mutate(shown.map((p) => p.domain), {
              onSuccess: (r) => toast.success(t('admin.federation.bulkRetried', {
                count: r.results.length, failed: r.results.filter((x) => !x.refreshed).length,
              })),
            })}>
            <RefreshCw />
            {t('admin.federation.retryShown')}
          </Button>
        ) : null
      }
    >
      {bulk.isError ? <Alert variant="error">{apiErrorMessage(bulk.error, t('admin.federation.actionFailed'))}</Alert> : null}
      <Card className="p-0">
        <div className="border-b border-border p-3">
          <Input value={query} onChange={(e) => setQuery(e.target.value)} placeholder={t('admin.federation.searchPeers')}
            aria-label={t('admin.federation.searchPeers')} className="max-w-sm" />
        </div>
        {peers.length === 0 ? (
          <EmptyState title={t('admin.federation.noPeersTitle')} description={t('admin.federation.noPeers')} />
        ) : null}
        <ul className="divide-y divide-border">
          {shown.map((peer) => (
            <li key={peer.domain} className="space-y-2 p-4">
              <div className="flex flex-wrap items-center gap-2">
                <Mono className="font-medium text-foreground">{peer.domain}</Mono>
                <TrustBadge trust={peer.trust} />
                <span className="ml-auto flex flex-wrap gap-1">
                  <Button size="sm" variant="ghost" onClick={() => setOpen({ kind: 'evidence', domain: peer.domain })}>
                    <FileSearch />
                    {t('admin.federation.evidence')}
                  </Button>
                  <Button size="sm" variant="outline" loading={retry.isPending && retry.variables?.domain === peer.domain}
                    onClick={() => retry.mutate({ domain: peer.domain, action: 'retry' }, { onSuccess: () => toast.success(t('admin.federation.retried', { domain: peer.domain })) })}>
                    {t('admin.federation.retry')}
                  </Button>
                  {peer.trust === 'tofu' ? (
                    <Button size="sm" variant="outline" onClick={() => setOpen({ kind: 'verify', peer })}>{t('admin.federation.verify')}</Button>
                  ) : null}
                  {peer.trust === 'quarantined' && peer.pendingFingerprint ? (
                    <Button size="sm" variant="destructive" onClick={() => setOpen({ kind: 'repin', peer })}>{t('admin.federation.repin')}</Button>
                  ) : null}
                </span>
              </div>
              <p className="flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
                <Mono className="break-all">{peer.fingerprintDisplay}</Mono>
                <button type="button" className="inline-flex items-center gap-1 text-primary hover:underline"
                  onClick={() => void copyText(peer.fingerprint).then(() => toast.success(t('common.copied')))}>
                  <Copy className="size-3" />
                  {t('admin.federation.copyFingerprint')}
                </button>
              </p>
              <p className="text-xs text-muted-foreground">
                {t('admin.federation.lastSeen', { when: formatInstant(peer.lastSeenAt, i18n.language) })}
                {' · '}
                {t('admin.federation.peerCounters', {
                  pending: peer.diagnostics.chatPendingTransactions,
                  incoming: peer.diagnostics.driveIncomingShares,
                  outgoing: peer.diagnostics.driveOutgoingShares,
                })}
              </p>
              {peer.lastDiscoveryError ? <Alert variant="warn">{peer.lastDiscoveryError}</Alert> : null}
            </li>
          ))}
        </ul>
        {retry.isError ? <div className="p-3"><Alert variant="error">{apiErrorMessage(retry.error, t('admin.federation.actionFailed'))}</Alert></div> : null}
      </Card>
      {open?.kind === 'verify' ? <VerifyDialog peer={open.peer} onClose={() => setOpen(null)} /> : null}
      {open?.kind === 'repin' ? <RepinDialog peer={open.peer} onClose={() => setOpen(null)} /> : null}
      {open?.kind === 'evidence' ? <EvidenceDialog domain={open.domain} onClose={() => setOpen(null)} /> : null}
    </Section>
  )
}
