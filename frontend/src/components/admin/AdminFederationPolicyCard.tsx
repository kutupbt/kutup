import { useEffect, useState, type FormEvent } from 'react'
import { useTranslation } from 'react-i18next'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Icon, ICONS } from '@/components/mobile/Icon'
import {
  useAdminFederationPolicy,
  useDeleteAdminFederationRule,
  useRepinAdminFederationPeer,
  useRetryAdminFederationPeer,
  useUpdateAdminFederationPolicy,
  useUpsertAdminFederationRule,
  useVerifyAdminFederationPeer,
} from '@/api/hooks/useAdmin'
import type {
  FederationDomainRule,
  FederationMinimumTrust,
  FederationMode,
  FederationPeer,
  FederationRuleAction,
  FederationTrustRequirement,
} from '@/types/api'
import { copyText } from '@/lib/format'
import { cn } from '@/lib/utils'

const MODES: FederationMode[] = ['disabled', 'allowlist', 'blocklist', 'open']
const ACTIONS: FederationRuleAction[] = ['inherit', 'allow', 'block']
const TRUST: FederationTrustRequirement[] = ['inherit', 'tofu', 'verified']

const MODE_COPY: Record<FederationMode, string> = {
  disabled: 'Deny all inbound and outbound Chat federation.',
  allowlist: 'Deny by default; only explicitly allowed directions can federate.',
  blocklist: 'Allow by default; explicitly blocked directions are denied.',
  open: 'Allow every authenticated server; saved trust requirements still apply.',
}

const titleCase = (value: string) => value.charAt(0).toUpperCase() + value.slice(1)

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
  const chat = policy?.features.find((feature) => feature.feature === 'chat')
  const mode = chat?.mode ?? 'allowlist'
  const minimumTrust = chat?.minimumTrust ?? 'verified'

  const savePolicy = (next: {
    globalEnabled?: boolean
    mode?: FederationMode
    minimumTrust?: FederationMinimumTrust
  }) => {
    if (!policy) return
    updatePolicy.mutate({
      globalEnabled: next.globalEnabled ?? policy.globalEnabled,
      feature: 'chat',
      mode: next.mode ?? mode,
      minimumTrust: next.minimumTrust ?? minimumTrust,
    })
  }

  function submitRule(event: FormEvent) {
    event.preventDefault()
    const canonical = domain.trim()
    if (!canonical) return
    upsertRule.mutate(
      { domain: canonical, inbound, outbound, trustRequirement },
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
              {t('admin.federation.description', 'Manage the shared server identity, Chat admission policy, and pinned peers.')}
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
                Chat admission mode
                <select value={mode} disabled={updatePolicy.isPending} onChange={(event) => savePolicy({ mode: event.target.value as FederationMode })} className="mt-1 h-9 w-full rounded-md border border-input bg-background px-2.5 text-[13px] text-text-primary">
                  {MODES.map((value) => <option key={value} value={value}>{titleCase(value)}{value === 'allowlist' ? ' · recommended' : ''}</option>)}
                </select>
                <span className="mt-1 block">{MODE_COPY[mode]}</span>
              </label>
              <label className="text-[12px] text-text-tertiary">
                Chat minimum identity trust
                <select value={minimumTrust} disabled={updatePolicy.isPending} onChange={(event) => savePolicy({ minimumTrust: event.target.value as FederationMinimumTrust })} className="mt-1 h-9 w-full rounded-md border border-input bg-background px-2.5 text-[13px] text-text-primary">
                  <option value="verified">Verified · recommended</option>
                  <option value="tofu">TOFU</option>
                </select>
                <span className="mt-1 block">An allow rule never bypasses this trust floor.</span>
              </label>
            </div>
          </div>

          <form onSubmit={submitRule} className={cn('border-b border-border-light', compact ? 'px-3.5 py-3' : 'px-[18px] py-4')}>
            <div className="text-[13.5px] font-medium text-text-primary">Add or replace a Chat server rule</div>
            <div className={cn('mt-3 grid gap-2', compact ? 'grid-cols-1' : 'grid-cols-[minmax(170px,1fr)_125px_125px_125px_auto]')}>
              <Input value={domain} onChange={(event) => setDomain(event.target.value)} placeholder="chat.example.com" autoCapitalize="none" autoCorrect="off" spellCheck={false} />
              <Select value={inbound} values={ACTIONS} label="Inbound" onChange={(value) => setInbound(value as FederationRuleAction)} />
              <Select value={outbound} values={ACTIONS} label="Outbound" onChange={(value) => setOutbound(value as FederationRuleAction)} />
              <Select value={trustRequirement} values={TRUST} label="Trust" onChange={(value) => setTrustRequirement(value as FederationTrustRequirement)} />
              <Button type="submit" size="sm" disabled={!domain.trim() || upsertRule.isPending}>Save</Button>
            </div>
          </form>

          <div className="border-b border-border-light">
            {policy.rules.filter((rule) => rule.feature === 'chat').length === 0 ? (
              <div className="px-[18px] py-4 text-[12.5px] text-text-tertiary">No Chat server rules configured.</div>
            ) : policy.rules.filter((rule) => rule.feature === 'chat').map((rule) => (
              <FederationRuleRow key={`${rule.feature}:${rule.domain}`} rule={rule} compact={compact} />
            ))}
          </div>

          <div className="px-[18px] py-3 text-[13.5px] font-medium text-text-primary">Pinned server identities</div>
          {policy.peers.length === 0 ? (
            <div className="px-[18px] pb-4 text-[12.5px] text-text-tertiary">No remote server has completed authenticated discovery yet.</div>
          ) : policy.peers.map((peer) => <FederationPeerRow key={peer.domain} peer={peer} compact={compact} />)}
        </>
      )}
    </section>
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
        {changed && <Button size="sm" onClick={() => upsert.mutate({ domain: rule.domain, inbound, outbound, trustRequirement })}>Save</Button>}
        <Button size="sm" variant="outline" onClick={() => remove.mutate(rule.domain)}>Remove</Button>
      </div>
    </div>
  )
}

function FederationPeerRow({ peer, compact }: { peer: FederationPeer; compact: boolean }) {
  const verify = useVerifyAdminFederationPeer()
  const retry = useRetryAdminFederationPeer()
  const repin = useRepinAdminFederationPeer()
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
    <div className={cn('border-t border-border-light px-[18px] py-3', compact ? 'space-y-2' : 'flex items-start justify-between gap-4')}>
      <div className="min-w-0 text-[11.5px] text-text-tertiary">
        <div className="flex items-center gap-2"><code className="text-[12.5px] font-medium text-text-primary">{peer.domain}</code><span className={cn('rounded px-1.5 py-0.5 text-[10px] uppercase', peer.trust === 'quarantined' ? 'bg-destructive/10 text-destructive' : 'bg-primary/10 text-primary')}>{peer.trust}</span></div>
        <div className="mt-1 flex items-start gap-2">
          <code className="block min-w-0 break-all text-[10.5px]" title={peer.fingerprint}>{peer.fingerprintDisplay}</code>
          <button type="button" className="shrink-0 text-primary hover:underline" onClick={() => void copyText(peer.fingerprint)}>Copy full</button>
        </div>
        <div className="mt-1">Sequence {peer.sequence} · {peer.capabilities.join(', ') || 'capabilities unavailable'}</div>
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
        <Button size="sm" variant="outline" onClick={() => retry.mutate({ domain: peer.domain })}>Retry</Button>
        {peer.trust === 'tofu' && <Button size="sm" onClick={confirmVerify}>Verify</Button>}
        {peer.trust === 'quarantined' && peer.pendingFingerprint && <Button size="sm" variant="outline" onClick={confirmRepin}>Re-pin</Button>}
      </div>
    </div>
  )
}
