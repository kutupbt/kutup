import type { SafetyNumberV2 } from '@kutup/chat-core/types'
import { SafetyVerificationDialog as SharedDialog } from '@kutup/ui/components/safety-verification'

export interface SafetyVerificationDialogProps {
  /** Who the number is with, as shown (a name or an address, never an account key). */
  peer: string
  safety: SafetyNumberV2
  onVerify: (scannedPayload: string) => Promise<SafetyNumberV2>
  /** Mark the contact's identity verified (or clear it) after comparing the numbers by eye. */
  onSetVerified?: (verified: boolean) => Promise<SafetyNumberV2>
  /**
   * Controlled mode. When `open` is given the dialog renders no trigger of its
   * own — the host (e.g. the details panel) owns the button. Left undefined,
   * the dialog brings its own shield icon button, as before.
   */
  open?: boolean
  onOpenChange?: (open: boolean) => void
}

/** Chat's QR codes: the safety number over both account identity keys. */
const CHAT_SAFETY_QR_PREFIX = 'kutup://verify/v4/'

/**
 * Chat's safety number in the shared dialog: libsignal's fingerprint over
 * both accounts' identity keys, as Signal's (docs/plans/account-identity-key.md).
 * Rust performs the authoritative payload comparison and owns the trust state.
 */
export function SafetyVerificationDialog({ safety, ...props }: SafetyVerificationDialogProps) {
  const blocked = safety.continuityGap || safety.trust === 'Quarantined'
  return (
    <SharedDialog
      {...props}
      testIdPrefix="chat-safety"
      payloadPrefix={CHAT_SAFETY_QR_PREFIX}
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
