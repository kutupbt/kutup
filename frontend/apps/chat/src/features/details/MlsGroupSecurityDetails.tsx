import type { ReactNode } from 'react'
import { AlertTriangle, Loader2, ShieldCheck } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { Mono } from '@kutup/ui/components/mono'
import { cn } from '@kutup/ui/lib/cn'
import type {
  LocalMlsConversationRecord,
  MlsAuthorityPolicyInspection,
  MlsOrderingServicePolicy,
} from '@kutup/chat-core/types'

export interface MlsGroupSecurityDetailsProps {
  group: LocalMlsConversationRecord
  authorityPolicies: MlsAuthorityPolicyInspection[]
  loading: boolean
}

/**
 * Member-visible, exact cryptographic state for an MLS group. All live
 * authority-policy values supplied here have already passed the shared Rust
 * identity and policy-chain verifier.
 *
 * Laid out for a narrow side-panel column: everything stacks, and every
 * machine value is monospace and breaks anywhere rather than overflowing.
 */
export function MlsGroupSecurityDetails({
  group,
  authorityPolicies,
  loading,
}: MlsGroupSecurityDetailsProps) {
  const { t, i18n } = useTranslation()
  const formatTimestamp = (unixSeconds: number) =>
    new Date(unixSeconds * 1000).toLocaleString(i18n.language)

  return (
    <div className="grid min-w-0 gap-3" data-testid="chat-group-security-details">
      <section className="min-w-0 rounded-lg border p-3" data-testid="chat-group-owner-policy">
        <h3 className="text-sm font-medium">{t('chat.groupSecurity.ownerTitle')}</h3>
        <p className="mt-1 text-xs text-muted-foreground">
          {t('chat.groupSecurity.setSummary', {
            sequence: group.currentOwnerSet.sequence,
            required: group.currentOwnerSet.requiredQuorum,
            total: group.currentOwnerSet.owners.length,
          })}
        </p>
        <div className="mt-3 grid gap-3">
          {group.currentOwnerSet.owners.map((owner) => {
            const member = group.currentRoster.find(
              (candidate) => candidate.ownerId === owner.ownerId,
            )
            const account = member
              ? `${member.address.username}@${member.address.server}`
              : t('chat.groupSecurity.unmappedOwner')
            return (
              <div
                key={owner.ownerId}
                className="min-w-0 rounded-lg bg-muted/30 p-3"
                data-testid={`chat-group-owner-credential-${account}`}
              >
                <p className="break-all text-xs font-medium">{account}</p>
                <ExactValue
                  label={t('chat.groupSecurity.ownerFingerprint')}
                  value={owner.ownerId}
                  testId={`chat-group-owner-fingerprint-${account}`}
                />
                <ExactValue label={t('chat.groupSecurity.ownerPublicKey')} value={owner.publicKey} />
              </div>
            )
          })}
        </div>
      </section>

      <section className="min-w-0 rounded-lg border p-3" data-testid="chat-group-authorities">
        <h3 className="text-sm font-medium">{t('chat.groupSecurity.authorityTitle')}</h3>
        <p className="mt-1 text-xs text-muted-foreground">
          {t('chat.groupSecurity.authoritySetSummary', {
            sequence: group.currentAuthoritySet.sequence,
            required: group.currentAuthoritySet.requiredQuorum,
            total: group.currentAuthoritySet.authorities.length,
          })}
        </p>
        <p className="mt-1 text-xs text-muted-foreground">
          {t('chat.groupSecurity.authorityExplainer')}
        </p>
        {loading && (
          <div
            className="mt-3 flex items-center gap-2 text-xs text-muted-foreground"
            data-testid="chat-group-authority-policy-loading"
            role="status"
          >
            <Loader2 className="h-3.5 w-3.5 shrink-0 animate-spin" />
            {t('chat.groupSecurity.verifyingPolicies')}
          </div>
        )}
        <div className="mt-3 grid gap-3">
          {group.currentAuthoritySet.authorities.map((authority) => {
            const inspection = authorityPolicies.find((item) => item.domain === authority.domain)
            const history = inspection?.history?.policies ?? []
            const current = history.at(-1)
            return (
              <article
                key={authority.domain}
                className="min-w-0 rounded-lg bg-muted/30 p-3"
                data-testid={`chat-group-authority-${authority.domain}`}
              >
                <p className="break-all text-sm">
                  <Mono emphasis>{authority.domain}</Mono>
                </p>
                {inspection?.unavailable ? (
                  <Status tone="warn">{t('chat.groupSecurity.unavailable')}</Status>
                ) : current && inspection?.currentMatchesGroupPin ? (
                  <Status
                    tone="ok"
                    testId={`chat-group-authority-policy-match-${authority.domain}`}
                  >
                    {t('chat.groupSecurity.matchesPin')}
                  </Status>
                ) : current ? (
                  <Status
                    tone="warn"
                    testId={`chat-group-authority-policy-mismatch-${authority.domain}`}
                  >
                    {t('chat.groupSecurity.differsFromPin')}
                  </Status>
                ) : null}

                <div className="mt-1 grid">
                  <ExactValue
                    label={t('chat.groupSecurity.pinFingerprint')}
                    value={authority.keyId}
                    testId={`chat-group-authority-pin-${authority.domain}`}
                  />
                  <ExactValue
                    label={t('chat.groupSecurity.pinPublicKey')}
                    value={authority.publicKey}
                  />
                </div>

                {inspection?.unavailable && (
                  <p className="mt-3 rounded border border-status-warn/50 bg-status-warn/10 p-2 text-xs">
                    {t('chat.groupSecurity.unavailableExplainer')}
                  </p>
                )}

                {current && (
                  <details
                    className="mt-3 min-w-0 rounded-lg border bg-background/60 p-2"
                    data-testid={`chat-group-authority-policy-${authority.domain}`}
                  >
                    <summary className="cursor-pointer text-xs font-medium">
                      {t('chat.groupSecurity.exactPolicy')}
                    </summary>
                    <div className="mt-3 grid gap-3 border-t pt-3">
                      <dl className="grid gap-1.5 text-xs">
                        <PolicyDatum
                          label={t('chat.groupSecurity.policySequence')}
                          value={String(current.sequence)}
                          testId={`chat-group-authority-policy-sequence-${authority.domain}`}
                        />
                        <PolicyDatum
                          label={t('chat.groupSecurity.historyLength')}
                          value={String(history.length)}
                        />
                        <PolicyDatum
                          label={t('chat.groupSecurity.issued')}
                          value={formatTimestamp(current.issuedAt)}
                        />
                        <PolicyDatum
                          label={t('chat.groupSecurity.identityGeneration')}
                          value={String(current.federationIdentityGeneration)}
                        />
                      </dl>
                      <div className="grid">
                        <ExactValue
                          label={t('chat.groupSecurity.policyHash')}
                          value={current.policyHash}
                        />
                        <ExactValue
                          label={t('chat.groupSecurity.payloadDigest')}
                          value={current.payloadDigest}
                        />
                        <ExactValue
                          label={t('chat.groupSecurity.identityFingerprint')}
                          value={current.federationIdentityKeyId}
                          testId={`chat-group-authority-identity-fingerprint-${authority.domain}`}
                        />
                        <ExactValue
                          label={t('chat.groupSecurity.identityPublicKey')}
                          value={current.federationIdentityPublicKey}
                        />
                        <ExactValue
                          label={t('chat.groupSecurity.controlFingerprint')}
                          value={current.policy.controlSigningKeyId}
                          testId={`chat-group-authority-policy-fingerprint-${authority.domain}`}
                        />
                        <ExactValue
                          label={t('chat.groupSecurity.controlPublicKey')}
                          value={current.policy.controlSigningPublicKey}
                        />
                      </div>
                      <PolicyValues policy={current.policy} />
                      <details className="min-w-0 rounded-lg border bg-background/60 p-2">
                        <summary className="cursor-pointer text-xs font-medium">
                          {t('chat.groupSecurity.fullHistory')}
                        </summary>
                        <div className="mt-2 grid gap-2">
                          {history.map((entry) => (
                            <div
                              key={entry.sequence}
                              className="min-w-0 rounded bg-muted/40 p-2 text-xs"
                              data-testid={`chat-group-authority-history-${authority.domain}-${entry.sequence}`}
                            >
                              <p>
                                {t('chat.groupSecurity.historyEntry', {
                                  sequence: entry.sequence,
                                  issued: formatTimestamp(entry.issuedAt),
                                  generation: entry.federationIdentityGeneration,
                                })}
                              </p>
                              <ExactValue
                                label={t('chat.groupSecurity.historyPolicyHash')}
                                value={entry.policyHash}
                              />
                              <ExactValue
                                label={t('chat.groupSecurity.historyPayloadDigest')}
                                value={entry.payloadDigest}
                              />
                              <ExactValue
                                label={t('chat.groupSecurity.historyIdentityFingerprint')}
                                value={entry.federationIdentityKeyId}
                              />
                              <ExactValue
                                label={t('chat.groupSecurity.historyControlFingerprint')}
                                value={entry.policy.controlSigningKeyId}
                              />
                            </div>
                          ))}
                        </div>
                      </details>
                    </div>
                  </details>
                )}
              </article>
            )
          })}
        </div>
      </section>
    </div>
  )
}

function Status({
  tone,
  testId,
  children,
}: {
  tone: 'ok' | 'warn'
  testId?: string
  children: ReactNode
}) {
  const Icon = tone === 'ok' ? ShieldCheck : AlertTriangle
  return (
    <p className="mt-1 flex items-start gap-1.5 text-xs" data-testid={testId}>
      <Icon
        aria-hidden
        className={cn(
          'mt-px h-3.5 w-3.5 shrink-0',
          tone === 'ok' ? 'text-status-ok' : 'text-status-warn',
        )}
      />
      <span>{children}</span>
    </p>
  )
}

function PolicyValues({ policy }: { policy: MlsOrderingServicePolicy }) {
  const { t } = useTranslation()
  const entries = [
    ['policyVersion', policy.policyVersion],
    ['canonicalDomain', policy.canonicalDomain],
    ['suite', `0x${policy.suite.toString(16).padStart(4, '0')}`],
    ['anonymousDeliverySuite', policy.anonymousDeliverySuite],
    ['acceptsGroupOrdering', t(policy.acceptsGroupOrdering ? 'chat.groupSecurity.yes' : 'chat.groupSecurity.no')],
    ['maximumGroupMembers', policy.maximumGroupMembers],
    ['maximumAuthorities', policy.maximumAuthorities],
    ['maximumControlPayloadBytes', policy.maximumControlPayloadBytes],
    ['pendingMessages', policy.pendingMessageRequests.maximumMessages],
    ['pendingCiphertextBytes', policy.pendingMessageRequests.maximumCiphertextBytes],
    ['pendingExpirySeconds', policy.pendingMessageRequests.expirySeconds],
    ['anonymousAttemptsPerIpMinute', policy.abuseLimits.anonymousAttemptsPerIpMinute],
    ['capabilityBundlesPerMinute', policy.abuseLimits.capabilityBundleRequestsPerMinute],
    ['sealedSendsPerCapabilityMinute', policy.abuseLimits.sealedSendsPerCapabilityMinute],
    ['sealedSendsPerCapabilityDay', policy.abuseLimits.sealedSendsPerCapabilityDay],
    ['federatedSealedSendsPerOriginMinute', policy.abuseLimits.federatedSealedSendsPerOriginMinute],
    ['maximumEnvelopesPerRequest', policy.abuseLimits.maximumEnvelopesPerRequest],
    ['maximumRequestBytes', policy.abuseLimits.maximumRequestBytes],
  ] as const
  return (
    <dl className="grid gap-1.5 rounded-lg border bg-background/60 p-2 text-xs">
      {entries.map(([key, value]) => (
        <PolicyDatum
          key={key}
          label={t(`chat.groupSecurity.policy.${key}`)}
          value={String(value)}
        />
      ))}
    </dl>
  )
}

/** One label/value row; wraps onto two lines when the column is too narrow. */
function PolicyDatum({
  label,
  value,
  testId,
}: {
  label: string
  value: string
  testId?: string
}) {
  return (
    <div
      className="flex min-w-0 flex-wrap items-baseline justify-between gap-x-3"
      data-testid={testId}
    >
      <dt className="text-muted-foreground">{label}</dt>
      <dd className="min-w-0 break-all text-right">
        <Mono emphasis>{value}</Mono>
      </dd>
    </div>
  )
}

function ExactValue({
  label,
  value,
  testId,
}: {
  label: string
  value: string
  testId?: string
}) {
  return (
    <div className="mt-2 min-w-0" data-testid={testId}>
      <div className="mb-1 text-xs text-muted-foreground">{label}</div>
      <Mono
        as="code"
        className="block select-all break-all rounded border bg-background/60 p-2 text-xs leading-5"
      >
        {value}
      </Mono>
    </div>
  )
}
