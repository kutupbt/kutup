import type { SafetyNumberV1 } from '@kutup/chat-core/types'
import { SafetyVerificationDialog as SharedDialog } from '@kutup/ui/components/safety-verification'

export interface SafetyVerificationDialogProps {
  peer: string
  safety: SafetyNumberV1
  onVerify: (scannedPayload: string) => Promise<SafetyNumberV1>
  /**
   * Controlled mode. When `open` is given the dialog renders no trigger of its
   * own — the host (e.g. the details panel) owns the button. Left undefined,
   * the dialog brings its own shield icon button, as before.
   */
  open?: boolean
  onOpenChange?: (open: boolean) => void
}

/**
 * Chat's safety number in the shared dialog (the same number Drive shows,
 * kutup-crypto safety_number). Rust performs the authoritative payload
 * comparison and owns the trust state.
 */
export function SafetyVerificationDialog({ safety, ...props }: SafetyVerificationDialogProps) {
  const blocked = safety.continuityGap || safety.trust === 'Quarantined'
  return (
    <SharedDialog
      {...props}
      testIdPrefix="chat-safety"
      safety={{
        fingerprint: safety.fingerprint,
        qrPayload: safety.qrPayload,
        state: blocked ? 'blocked' : safety.trust === 'Verified' ? 'verified' : 'unverified',
        retainedAuthorityKeyId: safety.retainedAuthorityKeyId,
        authorityKeyId: safety.authorityKeyId,
        canVerifyBlocked: Boolean(safety.retainedAuthorityKeyId),
      }}
    />
  )
}
