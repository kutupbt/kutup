import { useEffect, useMemo, useState, type FormEvent } from 'react'
import { useTranslation } from 'react-i18next'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Icon, ICONS } from '@/components/mobile/Icon'
import {
  useAdminFederationPolicy,
  useAdminFederationPeerEvidence,
  useAdminFederationActivity,
  useBulkRetryAdminFederationPeers,
  useDeleteAdminFederationRule,
  useExportAdminFederationActivity,
  useRepinAdminFederationPeer,
  useRetryAdminFederationPeer,
  useUpdateAdminFederationPolicy,
  useUpsertAdminFederationRule,
  useVerifyAdminFederationPeer,
} from '@/api/hooks/useAdmin'
import type {
  AdminFederationPolicy,
  FederationDomainRule,
  FederationMinimumTrust,
  FederationMode,
  FederationPeer,
  FederationRuleAction,
  FederationTrustRequirement,
} from '@/types/api'
import { copyText } from '@/lib/format'
import { cn } from '@/lib/utils'
import { activityDetails, activityText } from './activity'

const MODES: FederationMode[] = ['disabled', 'allowlist', 'blocklist', 'open']
const ACTIONS: FederationRuleAction[] = ['inherit', 'allow', 'block']
const TRUST: FederationTrustRequirement[] = ['inherit', 'tofu', 'verified']

const MODE_COPY: Record<FederationMode, string> = {
  disabled: 'Deny all inbound and outbound traffic for this feature.',
  allowlist: 'Deny by default; only explicitly allowed directions can federate.',
  blocklist: 'Allow by default; explicitly blocked directions are denied.',
  open: 'Allow every authenticated server; saved trust requirements still apply.',
}

const titleCase = (value: string) => value.charAt(0).toUpperCase() + value.slice(1)
type PeerFilter = 'all' | FederationPeer['trust'] | 'issues'

interface Props {
  className?: string
  compact?: boolean
}

/** Shared responsive control plane for unified federation policy and peer trust. */
export function AdminFederationPolicyCard({ className, compact = false }: Props) {
  const { t } = useTranslation()
  const { data: policy, isLoading } = useAdminFederationPolicy()
  const updatePolicy = useUpdateAdminFederationPolicy()
  const upsertRule = useUpsertAdminFederationRule()
  const [domain, setDomain] = useState('')
  const [inbound, setInbound] = useState<FederationRuleAction>('inherit')
  const [outbound, setOutbound] = useState<FederationRuleAction>('inherit')
  const [trustRequirement, setTrustRequirement] = useState<FederationTrustRequirement>('inherit')
  const [selectedFeature, setSelectedFeature] = useState<'chat' | 'drive'>('chat')
  const [peerQuery, setPeerQuery] = useState('')
  const [peerFilter, setPeerFilter] = useState<PeerFilter>('all')
  const bulkRetry = useBulkRetryAdminFederationPeers()
  const featurePolicy = policy?.features.find((feature) => feature.feature === selectedFeature)
  const mode = featurePolicy?.mode ?? 'allowlist'
  const minimumTrust = featurePolicy?.minimumTrust ?? 'verified'
  const featureLabel = titleCase(selectedFeature)
  const filteredPeers = useMemo(() => {
    const query = peerQuery.trim().toLowerCase()
    return (policy?.peers ?? []).filter((peer) => {
      const matchesQuery = !query || peer.domain.toLowerCase().includes(query)
        || peer.fingerprint.includes(query)
      const hasIssue = peer.trust === 'quarantined' || Boolean(peer.lastDiscoveryError)
        || peer.diagnostics.chatMismatchTransactions > 0
      const matchesState = peerFilter === 'all'
        || (peerFilter === 'issues' ? hasIssue : peer.trust === peerFilter)
      return matchesQuery && matchesState
    })
  }, [peerFilter, peerQuery, policy?.peers])

  const savePolicy = (next: {
    globalEnabled?: boolean
    mode?: FederationMode
    minimumTrust?: FederationMinimumTrust
  }) => {
    if (!policy) return
    updatePolicy.mutate({
      globalEnabled: next.globalEnabled ?? policy.globalEnabled,
      feature: selectedFeature,
      mode: next.mode ?? mode,
      minimumTrust: next.minimumTrust ?? minimumTrust,
    })
  }

  function submitRule(event: FormEvent) {
    event.preventDefault()
    const canonical = domain.trim()
    if (!canonical) return
    upsertRule.mutate(
      { feature: selectedFeature, domain: canonical, inbound, outbound, trustRequirement },
      { onSuccess: () => setDomain('') },
    )
  }

  return (
    <section className={cn('bg-surface border border-border-light rounded-[var(--radius-lg)] overflow-hidden', className)}>
      <div className={cn('border-b border-border-light', compact ? 'px-3.5 py-3' : 'px-[18px] py-3.5')}>
        <div className="flex items-start gap-2.5">
          <span className="mt-0.5 text-primary"><Icon d={ICONS.globe} size={16} /></span>
          <div className="min-w-0">
            <div className="text-[14px] font-semibold text-text-primary">
              {t('admin.federation.title', 'Federation')}
            </div>
            <div className="text-[12.5px] text-text-tertiary mt-0.5">
              {t('admin.federation.description', 'Manage the shared server identity, feature admission policies, and pinned peers.')}
            </div>
          </div>
        </div>
      </div>

      {isLoading || !policy ? (
        <div className="px-[18px] py-5 text-[13px] text-text-tertiary">Loading federation…</div>
      ) : (
        <>
          <div className={cn('border-b border-border-light space-y-3', compact ? 'px-3.5 py-3' : 'px-[18px] py-4')}>
            {!policy.configured && (
              <div className="flex gap-2 rounded-[var(--radius)] border border-warning/40 bg-warning/10 px-3 py-2 text-[12px] text-text-secondary">
                <Icon d={ICONS.alertTriangle} size={15} color="var(--warning)" />
                <span>Set FEDERATION_SERVER_NAME and FEDERATION_SIGNING_KEY to publish federation.</span>
              </div>
            )}
            {policy.serverName && (
              <div className="text-[12px] text-text-tertiary">
                <div><span className="font-medium text-text-secondary">{policy.serverName}</span> · identity sequence {policy.identitySequence}</div>
                <div className="mt-1 flex items-start gap-2">
                  <code className="block min-w-0 break-all text-[10.5px]" title={policy.fingerprint ?? undefined}>{policy.fingerprintDisplay}</code>
                  {policy.fingerprint && <button type="button" className="shrink-0 text-primary hover:underline" onClick={() => void copyText(policy.fingerprint!)}>Copy full</button>}
                </div>
                <div className="mt-1">Capabilities: {policy.capabilities.join(', ')}</div>
              </div>
            )}
            <OperationalSummary policy={policy} compact={compact} />
            <label className="flex items-center justify-between gap-3 text-[13px] text-text-primary">
              <span>
                <span className="font-medium">Federation globally enabled</span>
                <span className="block text-[11.5px] text-text-tertiary">Turn this off for the emergency stop; it overrides every feature and rule.</span>
              </span>
              <input
                type="checkbox"
                checked={policy.globalEnabled}
                disabled={updatePolicy.isPending}
                onChange={(event) => savePolicy({ globalEnabled: event.target.checked })}
                aria-label="Enable federation globally"
              />
            </label>
            <div className={cn('grid gap-3', compact ? 'grid-cols-1' : 'grid-cols-2')}>
              <label className="text-[12px] text-text-tertiary">
                Feature
                <select value={selectedFeature} onChange={(event) => setSelectedFeature(event.target.value as 'chat' | 'drive')} className="mt-1 h-9 w-full rounded-md border border-input bg-background px-2.5 text-[13px] text-text-primary">
                  <option value="chat">Chat</option>
                  <option value="drive">Drive</option>
                </select>
                <span className="mt-1 block">Policies are independent; identity trust and quarantine are shared.</span>
              </label>
              <label className="text-[12px] text-text-tertiary">
                {featureLabel} admission mode
                <select value={mode} disabled={updatePolicy.isPending} onChange={(event) => savePolicy({ mode: event.target.value as FederationMode })} className="mt-1 h-9 w-full rounded-md border border-input bg-background px-2.5 text-[13px] text-text-primary">
                  {MODES.map((value) => <option key={value} value={value}>{titleCase(value)}{value === 'allowlist' ? ' · recommended' : ''}</option>)}
                </select>
                <span className="mt-1 block">{MODE_COPY[mode]}</span>
              </label>
              <label className="text-[12px] text-text-tertiary">
                {featureLabel} minimum identity trust
                <select value={minimumTrust} disabled={updatePolicy.isPending} onChange={(event) => savePolicy({ minimumTrust: event.target.value as FederationMinimumTrust })} className="mt-1 h-9 w-full rounded-md border border-input bg-background px-2.5 text-[13px] text-text-primary">
                  <option value="verified">Verified · recommended</option>
                  <option value="tofu">TOFU</option>
                </select>
                <span className="mt-1 block">An allow rule never bypasses this trust floor.</span>
              </label>
            </div>
          </div>

          <form onSubmit={submitRule} className={cn('border-b border-border-light', compact ? 'px-3.5 py-3' : 'px-[18px] py-4')}>
            <div className="text-[13.5px] font-medium text-text-primary">Add or replace a {featureLabel} server rule</div>
            <div className={cn('mt-3 grid gap-2', compact ? 'grid-cols-1' : 'grid-cols-[minmax(170px,1fr)_125px_125px_125px_auto]')}>
              <Input value={domain} onChange={(event) => setDomain(event.target.value)} placeholder="chat.example.com" autoCapitalize="none" autoCorrect="off" spellCheck={false} />
              <Select value={inbound} values={ACTIONS} label="Inbound" onChange={(value) => setInbound(value as FederationRuleAction)} />
              <Select value={outbound} values={ACTIONS} label="Outbound" onChange={(value) => setOutbound(value as FederationRuleAction)} />
              <Select value={trustRequirement} values={TRUST} label="Trust" onChange={(value) => setTrustRequirement(value as FederationTrustRequirement)} />
              <Button type="submit" size="sm" disabled={!domain.trim() || upsertRule.isPending}>Save</Button>
            </div>
          </form>

          <div className="border-b border-border-light">
            {policy.rules.filter((rule) => rule.feature === selectedFeature).length === 0 ? (
              <div className="px-[18px] py-4 text-[12.5px] text-text-tertiary">No {featureLabel} server rules configured.</div>
            ) : policy.rules.filter((rule) => rule.feature === selectedFeature).map((rule) => (
              <FederationRuleRow key={`${rule.feature}:${rule.domain}`} rule={rule} compact={compact} />
            ))}
          </div>

          <div className={cn('border-b border-border-light space-y-2', compact ? 'px-3.5 py-3' : 'px-[18px] py-3')}>
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="text-[13.5px] font-medium text-text-primary">Pinned server identities</div>
              <Button
                size="sm"
                variant="outline"
                disabled={filteredPeers.length === 0 || filteredPeers.length > 100 || bulkRetry.isPending}
                title={filteredPeers.length > 100 ? 'Narrow the filters to at most 100 peers.' : undefined}
                onClick={() => {
                  if (window.confirm(`Retry authenticated discovery for ${filteredPeers.length} visible peer${filteredPeers.length === 1 ? '' : 's'}?`)) {
                    bulkRetry.mutate(filteredPeers.map((peer) => peer.domain))
                  }
                }}
              >
                Retry visible ({filteredPeers.length})
              </Button>
            </div>
            <div className={cn('grid gap-2', compact ? 'grid-cols-1' : 'grid-cols-[minmax(180px,1fr)_180px]')}>
              <Input
                value={peerQuery}
                onChange={(event) => setPeerQuery(event.target.value)}
                placeholder="Search domain or fingerprint"
                aria-label="Search pinned federation peers"
              />
              <select
                value={peerFilter}
                onChange={(event) => setPeerFilter(event.target.value as PeerFilter)}
                className="h-9 w-full rounded-md border border-input bg-background px-2.5 text-[12.5px] text-text-primary"
                aria-label="Filter pinned federation peers"
              >
                <option value="all">All trust states</option>
                <option value="issues">Needs attention</option>
                <option value="tofu">TOFU</option>
                <option value="verified">Verified</option>
                <option value="quarantined">Quarantined</option>
              </select>
            </div>
          </div>
          {policy.peers.length === 0 ? (
            <div className="px-[18px] pb-4 text-[12.5px] text-text-tertiary">No remote server has completed authenticated discovery yet.</div>
          ) : filteredPeers.length === 0 ? (
            <div className="px-[18px] py-4 text-[12.5px] text-text-tertiary">No pinned server matches these filters.</div>
          ) : filteredPeers.map((peer) => <FederationPeerRow key={peer.domain} peer={peer} compact={compact} />)}
          <FederationAuditPanel compact={compact} domain={peerQuery.trim() && filteredPeers.length === 1 ? filteredPeers[0].domain : undefined} />
        </>
      )}
    </section>
  )
}

function OperationalSummary({ policy, compact }: { policy: AdminFederationPolicy; compact: boolean }) {
  const operational = policy.operational
  const chatPendingAge = operational.oldestChatPendingAt
    ? ` · oldest ${formatTimestamp(operational.oldestChatPendingAt)}`
    : ''
  const items = [
    ['Peer trust', `${operational.verifiedPeers} verified · ${operational.tofuPeers} TOFU · ${operational.quarantinedPeers} quarantined`],
    ['Chat delivery', `${operational.chatPendingTransactions} pending${chatPendingAge} · ${operational.chatMismatchTransactions} terminal mismatch`],
    ['Drive federation', `${operational.driveIncomingShares} incoming · ${operational.driveOutgoingShares} outgoing`],
    ['Replay defense', `${operational.activeReplayReservations} active reservations`],
  ]
  return (
    <div className={cn('grid gap-2', compact ? 'grid-cols-1' : 'grid-cols-2')}>
      {items.map(([label, value]) => (
        <div key={label} className="rounded-md border border-border-light bg-background/40 px-2.5 py-2">
          <div className="text-[10.5px] font-medium uppercase tracking-wide text-text-tertiary">{label}</div>
          <div className="mt-0.5 text-[11.5px] text-text-secondary">{value}</div>
        </div>
      ))}
    </div>
  )
}

function Select({ value, values, label, onChange, disabled }: { value: string; values: readonly string[]; label: string; onChange: (value: string) => void; disabled?: boolean }) {
  return (
    <label><span className="sr-only">{label}</span><select aria-label={label} value={value} disabled={disabled} onChange={(event) => onChange(event.target.value)} className="h-9 w-full rounded-md border border-input bg-background px-2 text-[12.5px] text-text-primary">
      {values.map((item) => <option key={item} value={item}>{label}: {titleCase(item)}</option>)}
    </select></label>
  )
}

function FederationRuleRow({ rule, compact }: { rule: FederationDomainRule; compact: boolean }) {
  const upsert = useUpsertAdminFederationRule()
  const remove = useDeleteAdminFederationRule()
  const [inbound, setInbound] = useState(rule.inbound)
  const [outbound, setOutbound] = useState(rule.outbound)
  const [trustRequirement, setTrustRequirement] = useState(rule.trustRequirement)
  useEffect(() => {
    setInbound(rule.inbound); setOutbound(rule.outbound); setTrustRequirement(rule.trustRequirement)
  }, [rule.inbound, rule.outbound, rule.trustRequirement])
  const changed = inbound !== rule.inbound || outbound !== rule.outbound || trustRequirement !== rule.trustRequirement
  return (
    <div className={cn('border-t border-border-light gap-2 px-[18px] py-3', compact ? 'grid grid-cols-1' : 'grid grid-cols-[minmax(170px,1fr)_125px_125px_125px_auto] items-center')}>
      <code className="truncate text-[12.5px] font-medium text-text-primary">{rule.domain}</code>
      <Select value={inbound} values={ACTIONS} label="Inbound" onChange={(value) => setInbound(value as FederationRuleAction)} />
      <Select value={outbound} values={ACTIONS} label="Outbound" onChange={(value) => setOutbound(value as FederationRuleAction)} />
      <Select value={trustRequirement} values={TRUST} label="Trust" onChange={(value) => setTrustRequirement(value as FederationTrustRequirement)} />
      <div className="flex justify-end gap-1.5">
        {changed && <Button size="sm" onClick={() => upsert.mutate({ feature: rule.feature, domain: rule.domain, inbound, outbound, trustRequirement })}>Save</Button>}
        <Button size="sm" variant="outline" onClick={() => remove.mutate({ feature: rule.feature, domain: rule.domain })}>Remove</Button>
      </div>
    </div>
  )
}

function FederationPeerRow({ peer, compact }: { peer: FederationPeer; compact: boolean }) {
  const verify = useVerifyAdminFederationPeer()
  const retry = useRetryAdminFederationPeer()
  const repin = useRepinAdminFederationPeer()
  const [showEvidence, setShowEvidence] = useState(false)
  const evidence = useAdminFederationPeerEvidence(peer.domain, showEvidence)
  const confirmVerify = () => {
    const fingerprint = window.prompt(`Type the full fingerprint shown for ${peer.domain}`)
    if (fingerprint === peer.fingerprint) verify.mutate({ domain: peer.domain, body: { fingerprint } })
  }
  const confirmRepin = () => {
    if (!peer.pendingFingerprint) return
    const domain = window.prompt(`Type ${peer.domain} to confirm break-glass re-pin`)
    if (domain !== peer.domain) return
    const old = window.prompt('Type the complete currently pinned fingerprint')
    if (old !== peer.fingerprint) return
    const next = window.prompt('Type the complete pending fingerprint')
    if (next !== peer.pendingFingerprint) return
    repin.mutate({ domain: peer.domain, body: { oldFingerprint: old, newFingerprint: next, confirmDomain: domain } })
  }
  return (
    <div className="border-t border-border-light px-[18px] py-3">
      <div className={cn(compact ? 'space-y-2' : 'flex items-start justify-between gap-4')}>
        <div className="min-w-0 text-[11.5px] text-text-tertiary">
          <div className="flex items-center gap-2"><code className="text-[12.5px] font-medium text-text-primary">{peer.domain}</code><span className={cn('rounded px-1.5 py-0.5 text-[10px] uppercase', peer.trust === 'quarantined' ? 'bg-destructive/10 text-destructive' : 'bg-primary/10 text-primary')}>{peer.trust}</span></div>
          <div className="mt-1 flex items-start gap-2">
            <code className="block min-w-0 break-all text-[10.5px]" title={peer.fingerprint}>{peer.fingerprintDisplay}</code>
            <button type="button" className="shrink-0 text-primary hover:underline" onClick={() => void copyText(peer.fingerprint)}>Copy full</button>
          </div>
          <div className="mt-1">Sequence {peer.sequence} · {peer.capabilities.join(', ') || 'capabilities unavailable'}</div>
          <div className="mt-1">
            Chat: {peer.diagnostics.chatPendingTransactions} pending, {peer.diagnostics.chatMismatchTransactions} mismatch · Drive: {peer.diagnostics.driveIncomingShares} incoming, {peer.diagnostics.driveOutgoingShares} outgoing
          </div>
          {peer.apiBase && <div className="mt-1 break-all">Authenticated API: {peer.apiBase}</div>}
          <div className="mt-1">Last authenticated observation: {formatTimestamp(peer.lastSeenAt)}</div>
          {peer.discoveryExpiresAt && <div className="mt-1">Discovery expires: {formatTimestamp(peer.discoveryExpiresAt)}</div>}
          {peer.quarantineReason && <div className="mt-1 text-destructive">{peer.quarantineReason}</div>}
          {peer.pendingFingerprint && (
            <div className="mt-1">
              Pending: <code className="break-all">{peer.pendingFingerprint}</code>{' '}
              <button type="button" className="text-primary hover:underline" onClick={() => void copyText(peer.pendingFingerprint!)}>Copy full</button>
            </div>
          )}
          {peer.lastDiscoveryError && <div className="mt-1 text-warning">Discovery: {peer.lastDiscoveryError}</div>}
        </div>
        <div className="flex shrink-0 flex-wrap gap-1.5">
          <Button size="sm" variant="outline" onClick={() => setShowEvidence((value) => !value)}>{showEvidence ? 'Hide evidence' : 'Evidence'}</Button>
          <Button size="sm" variant="outline" disabled={retry.isPending} onClick={() => retry.mutate({ domain: peer.domain })}>Retry</Button>
          {peer.trust === 'tofu' && <Button size="sm" onClick={confirmVerify}>Verify</Button>}
          {peer.trust === 'quarantined' && peer.pendingFingerprint && <Button size="sm" variant="outline" onClick={confirmRepin}>Re-pin</Button>}
        </div>
      </div>
      {showEvidence && <FederationPeerEvidenceView query={evidence} />}
    </div>
  )
}

function FederationPeerEvidenceView({ query }: { query: ReturnType<typeof useAdminFederationPeerEvidence> }) {
  if (query.isLoading) return <div className="mt-3 text-[11.5px] text-text-tertiary">Loading immutable identity evidence…</div>
  if (query.isError || !query.data) return <div className="mt-3 text-[11.5px] text-destructive">Identity evidence could not be loaded.</div>
  const evidence = query.data
  return (
    <div className="mt-3 rounded-md border border-border-light bg-background/50 p-3 text-[11px] text-text-tertiary">
      <div className="font-medium text-text-secondary">Authenticated identity evidence</div>
      <div className="mt-1 break-all">Current document hash: <code>{evidence.currentDocumentHash}</code></div>
      {evidence.pendingDocumentHash && <div className="mt-1 break-all text-warning">Pending document hash: <code>{evidence.pendingDocumentHash}</code></div>}
      {evidence.truncated && <div className="mt-1 text-warning">Showing the newest 200 preserved documents.</div>}
      <div className="mt-2 space-y-2">
        {evidence.documents.map((document) => (
          <details key={`${document.sequence}:${document.documentHash}`} className="rounded border border-border-light px-2.5 py-2">
            <summary className="cursor-pointer text-text-secondary">
              Sequence {document.sequence} · {document.acceptance} · {formatTimestamp(document.recordedAt)}
            </summary>
            <div className="mt-2 break-all">Document hash: <code>{document.documentHash}</code></div>
            <div className="mt-1 flex items-start gap-2">
              <code className="min-w-0 break-all">{document.fingerprintDisplay}</code>
              <button type="button" className="shrink-0 text-primary hover:underline" onClick={() => void copyText(document.fingerprint)}>Copy fingerprint</button>
            </div>
            <pre className="mt-2 max-h-64 overflow-auto whitespace-pre-wrap break-all rounded bg-surface p-2 text-[10px] text-text-secondary">{JSON.stringify(document.document, null, 2)}</pre>
          </details>
        ))}
      </div>
    </div>
  )
}

function FederationAuditPanel({ compact, domain }: { compact: boolean; domain?: string }) {
  const { t } = useTranslation()
  const activity = useAdminFederationActivity(20, domain)
  const exportActivity = useExportAdminFederationActivity()
  return (
    <div className={cn('border-t border-border-light', compact ? 'px-3.5 py-3' : 'px-[18px] py-4')}>
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div>
          <div className="text-[13.5px] font-medium text-text-primary">Federation audit</div>
          <div className="text-[11.5px] text-text-tertiary">Shared identity, policy, Chat, and Drive control-plane events.</div>
        </div>
        <Button size="sm" variant="outline" disabled={exportActivity.isPending} onClick={() => exportActivity.mutate(domain)}>
          Export CSV{domain ? ` · ${domain}` : ''}
        </Button>
      </div>
      {activity.isLoading ? (
        <div className="mt-3 text-[11.5px] text-text-tertiary">Loading federation audit…</div>
      ) : !activity.data?.entries.length ? (
        <div className="mt-3 text-[11.5px] text-text-tertiary">No matching federation audit events.</div>
      ) : (
        <div className="mt-3 divide-y divide-border-light rounded-md border border-border-light">
          {activity.data.entries.map((entry) => (
            <div key={entry.id} className="px-3 py-2 text-[11.5px]">
              <div className="text-text-secondary">{activityText(entry, t)}</div>
              <div className="mt-0.5 text-[10.5px] text-text-tertiary">{formatTimestamp(entry.occurredAt)}</div>
              {activityDetails(entry).map((detail) => <div key={detail} className="mt-0.5 break-all font-mono text-[10px] text-text-tertiary">{detail}</div>)}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

function formatTimestamp(value: string): string {
  return new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(value))
}
