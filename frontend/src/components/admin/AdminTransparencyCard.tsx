import { useState } from 'react'
import { AlertTriangle, Loader2, RefreshCw, ShieldCheck } from 'lucide-react'
import { toast } from 'sonner'
import api from '@/api/client'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { cn } from '@/lib/utils'

interface PolicyEnvelope {
  sequence: string | number
  previousPolicyHash?: string
  payloadDigest: string
  issuedAt: number
  payload: string
}

interface PolicyHistory {
  domain: string
  policies: PolicyEnvelope[]
}

interface PolicyPayload {
  logId: string
  operatorKeyId: string
  operatorPublicKey: string
  requiredQuorum: number
  maximumCheckpointAgeSeconds: number
  witnesses: Array<{
    witnessId: string
    keyId: string
    publicKey: string
    publicEndpoint: string
  }>
}

interface MonitorStatus {
  domain: string
  policySequence: string | number
  logId?: string
  checkpoint?: {
    checkpoint: { treeSize: string | number; rootHash: string }
    mapRoot: string
    authentication: { issuedAt: number }
  }
  lastSuccessfulAt?: string
  nextAttemptAt: string
  consecutiveFailures: number
  failureClass?: string
  warning: boolean
  blocked: boolean
  evidenceDigest?: string
}

interface EvidenceRecord {
  evidenceDigest: string
  evidence: unknown
  detectedAt: string
  acknowledgedAt?: string
  recoveryReason?: string
}

export function AdminTransparencyCard() {
  const [domain, setDomain] = useState('')
  const [loadedDomain, setLoadedDomain] = useState('')
  const [status, setStatus] = useState<MonitorStatus | null>(null)
  const [history, setHistory] = useState<PolicyHistory | null>(null)
  const [policy, setPolicy] = useState<PolicyPayload | null>(null)
  const [evidence, setEvidence] = useState<EvidenceRecord[]>([])
  const [reason, setReason] = useState('')
  const [loading, setLoading] = useState(false)
  const [recovering, setRecovering] = useState(false)

  async function load(target = domain) {
    const canonical = target.trim().toLowerCase()
    if (!canonical) return
    setLoading(true)
    try {
      const [statusResponse, historyResponse, evidenceResponse] = await Promise.all([
        api.get<MonitorStatus>(
          `/chat/transparency/domains/${encodeURIComponent(canonical)}/status`,
        ),
        api.get<PolicyHistory>(
          `/chat/transparency/domains/${encodeURIComponent(canonical)}/policy`,
        ),
        api.get<EvidenceRecord[]>(
          `/admin/chat/transparency/domains/${encodeURIComponent(canonical)}/evidence`,
        ),
      ])
      const current = historyResponse.data.policies.at(-1)
      if (!current) throw new Error('empty policy history')
      setLoadedDomain(canonical)
      setDomain(canonical)
      setStatus(statusResponse.data)
      setHistory(historyResponse.data)
      setPolicy(decodePayload(current.payload))
      setEvidence(evidenceResponse.data)
    } catch {
      toast.error('Transparency state could not be loaded for that domain.')
    } finally {
      setLoading(false)
    }
  }

  async function verifyNow() {
    if (!loadedDomain) return
    setLoading(true)
    try {
      await api.post(`/chat/transparency/domains/${encodeURIComponent(loadedDomain)}/verify`)
      await load(loadedDomain)
      toast.success('Remote transparency verification completed.')
    } catch {
      toast.error('Remote transparency verification failed.')
    } finally {
      setLoading(false)
    }
  }

  async function recover() {
    if (!loadedDomain || !status?.evidenceDigest || !reason.trim()) return
    setRecovering(true)
    try {
      await api.post(
        `/admin/chat/transparency/domains/${encodeURIComponent(loadedDomain)}/recover`,
        { evidenceDigest: status.evidenceDigest, reason: reason.trim() },
      )
      setReason('')
      await load(loadedDomain)
      toast.success('Transparency block recovered; immutable evidence was retained.')
    } catch {
      toast.error('Recovery requires matching evidence and a fresh valid monitor observation.')
    } finally {
      setRecovering(false)
    }
  }

  return (
    <section className="mb-5 overflow-hidden rounded-[var(--radius-lg)] border border-border-light bg-surface">
      <div className="border-b border-border-light px-[18px] py-3.5">
        <div className="text-[14px] font-semibold text-text-primary">
          Chat transparency audit
        </div>
        <div className="mt-0.5 text-[12.5px] text-text-tertiary">
          Inspect authenticated policy history, exact fingerprints, monitor freshness, and immutable fork evidence.
        </div>
      </div>
      <form
        className="flex gap-2 border-b border-border-light p-4"
        onSubmit={(event) => {
          event.preventDefault()
          void load()
        }}
      >
        <Input
          value={domain}
          onChange={(event) => setDomain(event.target.value)}
          placeholder="remote.example"
          autoCapitalize="none"
          autoCorrect="off"
          aria-label="Remote transparency domain"
        />
        <Button type="submit" disabled={loading || !domain.trim()}>
          {loading ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : null}
          Inspect
        </Button>
      </form>

      {status && policy && history && (
        <div className="grid gap-4 p-4 text-[13px]">
          <div
            className={cn(
              'flex items-center gap-2 rounded-lg border p-3 font-medium',
              status.blocked
                ? 'border-destructive/30 bg-destructive-faint text-destructive'
                : status.warning
                  ? 'border-warning/30 bg-warning-faint text-warning'
                  : 'border-success/30 bg-success-faint text-success',
            )}
          >
            {status.blocked
              ? <AlertTriangle className="h-4 w-4" />
              : <ShieldCheck className="h-4 w-4" />}
            <span className="flex-1">
              {status.blocked ? 'Blocked' : status.warning ? 'Warning' : 'Verified'} · {loadedDomain}
            </span>
            <Button variant="outline" size="sm" onClick={() => void verifyNow()} disabled={loading}>
              <RefreshCw className="mr-2 h-3.5 w-3.5" /> Verify now
            </Button>
          </div>

          <div className="grid grid-cols-2 gap-3 rounded-lg bg-surface-sunken p-3 md:grid-cols-4">
            <Datum label="Policy sequence" value={String(status.policySequence)} />
            <Datum label="Required quorum" value={String(policy.requiredQuorum)} />
            <Datum label="Tree size" value={String(status.checkpoint?.checkpoint.treeSize ?? '—')} />
            <Datum label="Checkpoint age" value={formatAge(status.checkpoint?.authentication.issuedAt)} />
            <Datum label="Last verified" value={status.lastSuccessfulAt ?? 'Never'} />
            <Datum label="Next attempt" value={status.nextAttemptAt} />
            <Datum label="Failures" value={String(status.consecutiveFailures)} />
            <Datum label="Failure class" value={status.failureClass ?? 'None'} />
          </div>

          <Fingerprint label="Log ID" value={policy.logId} />
          <Fingerprint label="Operator key ID" value={policy.operatorKeyId} />
          <Fingerprint label="Operator public key" value={policy.operatorPublicKey} />
          {status.checkpoint && (
            <>
              <Fingerprint label="Checkpoint root" value={status.checkpoint.checkpoint.rootHash} />
              <Fingerprint label="Sparse-map root" value={status.checkpoint.mapRoot} />
            </>
          )}
          {status.evidenceDigest && (
            <Fingerprint label="Active evidence digest" value={status.evidenceDigest} />
          )}

          <div>
            <div className="mb-2 font-semibold text-text-primary">Witness policy</div>
            <div className="grid gap-2">
              {policy.witnesses.map((witness) => (
                <div key={witness.witnessId} className="rounded-lg border border-border-light p-3">
                  <div className="font-medium">{witness.witnessId}</div>
                  <code className="mt-1 block break-all text-[11px] text-text-tertiary">{witness.keyId}</code>
                  <code className="mt-1 block break-all text-[11px] text-text-tertiary">{witness.publicKey}</code>
                  <div className="mt-1 break-all text-[11px] text-text-tertiary">{witness.publicEndpoint}</div>
                </div>
              ))}
            </div>
          </div>

          <details className="rounded-lg border border-border-light p-3">
            <summary className="cursor-pointer font-semibold">Authenticated policy history ({history.policies.length})</summary>
            <div className="mt-3 grid gap-2">
              {history.policies.map((entry) => (
                <div key={String(entry.sequence)} className="rounded bg-surface-sunken p-2 text-[11px]">
                  <div>Sequence {String(entry.sequence)} · {new Date(entry.issuedAt * 1000).toLocaleString()}</div>
                  <code className="mt-1 block break-all text-text-tertiary">{entry.payloadDigest}</code>
                  {entry.previousPolicyHash && (
                    <code className="mt-1 block break-all text-text-tertiary">previous {entry.previousPolicyHash}</code>
                  )}
                </div>
              ))}
            </div>
          </details>

          <details className="rounded-lg border border-border-light p-3" open={status.blocked}>
            <summary className="cursor-pointer font-semibold">Immutable fork evidence ({evidence.length})</summary>
            <div className="mt-3 grid gap-3">
              {evidence.length === 0 && <div className="text-text-tertiary">No signed contradictions stored.</div>}
              {evidence.map((record) => (
                <div key={record.evidenceDigest} className="rounded border border-border-light p-2">
                  <code className="block break-all text-[11px]">{record.evidenceDigest}</code>
                  <div className="mt-1 text-[11px] text-text-tertiary">
                    Detected {record.detectedAt}
                    {record.acknowledgedAt ? ` · acknowledged ${record.acknowledgedAt}` : ''}
                  </div>
                  <pre className="mt-2 max-h-64 overflow-auto whitespace-pre-wrap break-all rounded bg-surface-sunken p-2 text-[10px]">
                    {JSON.stringify(record.evidence, null, 2)}
                  </pre>
                </div>
              ))}
            </div>
          </details>

          {status.blocked && status.evidenceDigest && (
            <div className="rounded-lg border border-destructive/30 bg-destructive-faint p-3">
              <div className="font-semibold text-destructive">Break-glass recovery</div>
              <p className="my-2 text-[12px] text-text-tertiary">
                Requires a fresh valid checkpoint. The signed evidence remains immutable and the acknowledgement is audit logged.
              </p>
              <div className="flex gap-2">
                <Input
                  value={reason}
                  onChange={(event) => setReason(event.target.value)}
                  placeholder="Document the recovery decision"
                  maxLength={1024}
                />
                <Button
                  variant="destructive"
                  disabled={recovering || !reason.trim()}
                  onClick={() => void recover()}
                >
                  {recovering && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                  Recover
                </Button>
              </div>
            </div>
          )}
        </div>
      )}
    </section>
  )
}

function Datum({ label, value }: { label: string; value: string }) {
  return (
    <div className="min-w-0">
      <div className="text-[11px] text-text-tertiary">{label}</div>
      <div className="break-all font-medium text-text-primary">{value}</div>
    </div>
  )
}

function Fingerprint({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <div className="mb-1 text-[11px] font-medium text-text-tertiary">{label}</div>
      <code className="block break-all rounded border border-border-light bg-surface-sunken p-2 text-[11px]">{value}</code>
    </div>
  )
}

function decodePayload(payload: string): PolicyPayload {
  const binary = atob(payload)
  const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0))
  return JSON.parse(new TextDecoder().decode(bytes)) as PolicyPayload
}

function formatAge(issuedAt?: number): string {
  if (!issuedAt) return '—'
  const seconds = Math.max(0, Math.round(Date.now() / 1000) - issuedAt)
  if (seconds < 60) return `${seconds}s`
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m`
  return `${Math.floor(seconds / 3600)}h`
}
