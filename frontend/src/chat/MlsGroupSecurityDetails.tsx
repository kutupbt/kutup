import { AlertTriangle, Loader2, ShieldCheck } from 'lucide-react'
import type {
  LocalMlsConversationRecord,
  MlsAuthorityPolicyInspection,
  MlsOrderingServicePolicy,
} from './types'

interface MlsGroupSecurityDetailsProps {
  group: LocalMlsConversationRecord
  authorityPolicies: MlsAuthorityPolicyInspection[]
  loading: boolean
}

/**
 * Member-visible, exact cryptographic state for an MLS group. All live
 * authority-policy values supplied here have already passed the shared Rust
 * identity and policy-chain verifier.
 */
export function MlsGroupSecurityDetails({
  group,
  authorityPolicies,
  loading,
}: MlsGroupSecurityDetailsProps) {
  return (
    <div className="grid gap-3" data-testid="chat-group-security-details">
      <section className="rounded-lg border p-3" data-testid="chat-group-owner-policy">
        <p className="text-sm font-medium">Owner authorization</p>
        <p className="mt-1 text-xs text-muted-foreground">
          Sequence {group.currentOwnerSet.sequence} · quorum{' '}
          {group.currentOwnerSet.requiredQuorum}/{group.currentOwnerSet.owners.length}
        </p>
        <div className="mt-3 grid gap-3">
          {group.currentOwnerSet.owners.map(owner => {
            const member = group.currentRoster.find(candidate =>
              candidate.ownerId === owner.ownerId)
            const account = member
              ? `${member.address.username}@${member.address.server}`
              : 'Unmapped group credential'
            return (
              <div
                key={owner.ownerId}
                className="rounded-lg bg-muted/30 p-3"
                data-testid={`chat-group-owner-credential-${account}`}
              >
                <p className="break-all text-xs font-medium">{account}</p>
                <ExactValue
                  label="Owner credential SHA-256 fingerprint"
                  value={owner.ownerId}
                  testId={`chat-group-owner-fingerprint-${account}`}
                />
                <ExactValue label="Owner Ed25519 public key" value={owner.publicKey} />
              </div>
            )
          })}
        </div>
      </section>

      <section className="rounded-lg border p-3" data-testid="chat-group-authorities">
        <p className="text-sm font-medium">Ordering authority policy</p>
        <p className="mt-1 text-xs text-muted-foreground">
          Group authority-set sequence {group.currentAuthoritySet.sequence} · quorum{' '}
          {group.currentAuthoritySet.requiredQuorum}/{group.currentAuthoritySet.authorities.length}
        </p>
        <p className="mt-1 text-xs text-muted-foreground">
          Live policy histories are independently authenticated by this client.
          The group keeps its exact pinned control key until an owner-approved MLS transition.
        </p>
        {loading && (
          <div
            className="mt-3 flex items-center gap-2 text-xs text-muted-foreground"
            data-testid="chat-group-authority-policy-loading"
          >
            <Loader2 className="h-3.5 w-3.5 animate-spin" />
            Verifying authority policy histories…
          </div>
        )}
        <div className="mt-3 grid gap-3">
          {group.currentAuthoritySet.authorities.map(authority => {
            const inspection = authorityPolicies.find(item => item.domain === authority.domain)
            const current = inspection?.history?.policies.at(-1)
            return (
              <article
                key={authority.domain}
                className="rounded-lg bg-muted/30 p-3"
                data-testid={`chat-group-authority-${authority.domain}`}
              >
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <p className="break-all text-sm font-medium">{authority.domain}</p>
                  {inspection?.unavailable ? (
                    <span className="flex items-center gap-1 text-xs text-warning">
                      <AlertTriangle className="h-3.5 w-3.5" />
                      Verification unavailable
                    </span>
                  ) : current && inspection?.currentMatchesGroupPin ? (
                    <span
                      className="flex items-center gap-1 text-xs text-success"
                      data-testid={`chat-group-authority-policy-match-${authority.domain}`}
                    >
                      <ShieldCheck className="h-3.5 w-3.5" />
                      Authenticated; matches group pin
                    </span>
                  ) : current ? (
                    <span
                      className="flex items-center gap-1 text-xs text-warning"
                      data-testid={`chat-group-authority-policy-mismatch-${authority.domain}`}
                    >
                      <AlertTriangle className="h-3.5 w-3.5" />
                      Authenticated current policy differs from group pin
                    </span>
                  ) : null}
                </div>

                <div className="mt-3 grid gap-2">
                  <ExactValue
                    label="Group-pinned control-key SHA-256 fingerprint"
                    value={authority.keyId}
                    testId={`chat-group-authority-pin-${authority.domain}`}
                  />
                  <ExactValue
                    label="Group-pinned Ed25519 control public key"
                    value={authority.publicKey}
                  />
                </div>

                {inspection?.unavailable && (
                  <p className="mt-3 rounded border border-warning/30 bg-warning-faint p-2 text-xs">
                    Current authenticated policy evidence is unavailable. The exact group pin
                    above remains in force; there is no key replacement or fallback.
                  </p>
                )}

                {current && (
                  <details
                    className="mt-3 rounded-lg border bg-background/60 p-2"
                    data-testid={`chat-group-authority-policy-${authority.domain}`}
                  >
                    <summary className="cursor-pointer text-xs font-medium">
                      Exact authenticated service policy
                    </summary>
                    <div className="mt-3 grid gap-3 border-t pt-3">
                      <div className="grid grid-cols-2 gap-2 text-xs">
                        <PolicyDatum
                          label="Policy sequence"
                          value={String(current.sequence)}
                          testId={`chat-group-authority-policy-sequence-${authority.domain}`}
                        />
                        <PolicyDatum
                          label="History length"
                          value={String(inspection?.history?.policies.length ?? 0)}
                        />
                        <PolicyDatum
                          label="Issued"
                          value={formatTimestamp(current.issuedAt)}
                        />
                        <PolicyDatum
                          label="Identity generation"
                          value={String(current.federationIdentityGeneration)}
                        />
                      </div>
                      <ExactValue label="Authenticated policy hash" value={current.policyHash} />
                      <ExactValue label="Canonical payload digest" value={current.payloadDigest} />
                      <ExactValue
                        label="Federation-identity SHA-256 fingerprint"
                        value={current.federationIdentityKeyId}
                        testId={`chat-group-authority-identity-fingerprint-${authority.domain}`}
                      />
                      <ExactValue
                        label="Federation-identity Ed25519 public key"
                        value={current.federationIdentityPublicKey}
                      />
                      <ExactValue
                        label="Current control-key SHA-256 fingerprint"
                        value={current.policy.controlSigningKeyId}
                        testId={`chat-group-authority-policy-fingerprint-${authority.domain}`}
                      />
                      <ExactValue
                        label="Current Ed25519 control public key"
                        value={current.policy.controlSigningPublicKey}
                      />
                      <PolicyValues policy={current.policy} />
                      <details className="rounded-lg border bg-background/60 p-2">
                        <summary className="cursor-pointer text-xs font-medium">
                          Complete authenticated policy history
                        </summary>
                        <div className="mt-2 grid gap-2">
                          {inspection?.history?.policies.map(entry => (
                            <div
                              key={entry.sequence}
                              className="rounded bg-muted/40 p-2 text-xs"
                              data-testid={`chat-group-authority-history-${authority.domain}-${entry.sequence}`}
                            >
                              <p>
                                Sequence {entry.sequence} · {formatTimestamp(entry.issuedAt)} ·
                                identity generation {entry.federationIdentityGeneration}
                              </p>
                              <ExactValue label="Policy hash" value={entry.policyHash} />
                              <ExactValue label="Payload digest" value={entry.payloadDigest} />
                              <ExactValue
                                label="Federation identity fingerprint"
                                value={entry.federationIdentityKeyId}
                              />
                              <ExactValue
                                label="Control-key fingerprint"
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

function PolicyValues({ policy }: { policy: MlsOrderingServicePolicy }) {
  const entries = [
    ['Policy version', policy.policyVersion],
    ['Canonical domain', policy.canonicalDomain],
    ['MLS ciphersuite', `0x${policy.suite.toString(16).padStart(4, '0')}`],
    ['Anonymous delivery suite', policy.anonymousDeliverySuite],
    ['Accepts group ordering', policy.acceptsGroupOrdering ? 'yes' : 'no'],
    ['Maximum group members', policy.maximumGroupMembers],
    ['Maximum authorities', policy.maximumAuthorities],
    ['Maximum control payload bytes', policy.maximumControlPayloadBytes],
    ['Pending-request messages', policy.pendingMessageRequests.maximumMessages],
    ['Pending-request ciphertext bytes', policy.pendingMessageRequests.maximumCiphertextBytes],
    ['Pending-request expiry seconds', policy.pendingMessageRequests.expirySeconds],
    ['Anonymous attempts/IP/minute', policy.abuseLimits.anonymousAttemptsPerIpMinute],
    ['Capability bundles/minute', policy.abuseLimits.capabilityBundleRequestsPerMinute],
    ['Sealed sends/capability/minute', policy.abuseLimits.sealedSendsPerCapabilityMinute],
    ['Sealed sends/capability/day', policy.abuseLimits.sealedSendsPerCapabilityDay],
    [
      'Federated sealed sends/origin/minute',
      policy.abuseLimits.federatedSealedSendsPerOriginMinute,
    ],
    ['Maximum envelopes/request', policy.abuseLimits.maximumEnvelopesPerRequest],
    ['Maximum request bytes', policy.abuseLimits.maximumRequestBytes],
  ] as const
  return (
    <div className="grid grid-cols-2 gap-2 rounded-lg border bg-background/60 p-2 text-xs">
      {entries.map(([label, value]) => (
        <PolicyDatum key={label} label={label} value={String(value)} />
      ))}
    </div>
  )
}

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
    <div className="min-w-0" data-testid={testId}>
      <div className="text-muted-foreground">{label}</div>
      <div className="break-all font-medium">{value}</div>
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
    <div className="mt-2" data-testid={testId}>
      <div className="mb-1 text-xs text-muted-foreground">{label}</div>
      <code className="block break-all rounded border bg-background/60 p-2 text-xs">{value}</code>
    </div>
  )
}

function formatTimestamp(unixSeconds: number): string {
  return new Date(unixSeconds * 1000).toLocaleString()
}
