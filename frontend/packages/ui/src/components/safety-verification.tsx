import { useEffect, useState } from 'react'
import { AlertTriangle, Camera, Check, Copy, Loader2, Shield, ShieldCheck } from 'lucide-react'
import { QRCodeSVG } from 'qrcode.react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { Button } from './button'
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger } from './dialog'
import { Input } from './input'
import { Mono } from './mono'
import { copyText } from '../lib/clipboard'
import { useQrScanner } from '../lib/qrScanner'

/**
 * Drive's safety QR: kutup-crypto `safety_number::QR_PREFIX`, over the
 * accounts' authorities. Chat's covers the account identity keys
 * (`kutup://verify/v4/`, chat-core's `SAFETY_QR_PREFIX`) and passes it as
 * `payloadPrefix`. Each side's code carries its own half first, so a scan
 * here is the other side's code.
 */
const VERIFY_PAYLOAD_PREFIX = 'kutup://verify/v3/'

/**
 * What the dialog shows: the pair's safety number (kutup-crypto
 * safety_number, the same in every app) and how far the peer is trusted.
 */
export interface SafetyNumberView {
  fingerprint: string
  qrPayload: string
  /** `blocked`: the identity changed or its history is incomplete. */
  state: 'unverified' | 'verified' | 'blocked'
  /** A changed identity: the one kept, and the new one offered. */
  retainedAuthorityKeyId?: string | null
  authorityKeyId?: string
  /** A changed identity may be verified (and so accepted) only when it says which one it replaces. */
  canVerifyBlocked?: boolean
}

export interface SafetyVerificationDialogProps {
  peer: string
  safety: SafetyNumberView
  /** Resolves when the scanned payload matched and the peer is verified; rejects otherwise. */
  onVerify: (scannedPayload: string) => Promise<unknown>
  /** The QR codes this app's numbers use (Drive's by default). */
  payloadPrefix?: string
  /**
   * Mark the peer verified, or clear it, after comparing the numbers by eye
   * (Signal's "Mark as verified" / "Clear verification"). Without it, only a
   * scan verifies.
   */
  onSetVerified?: (verified: boolean) => Promise<unknown>
  /** Test ids start with this (`chat-safety` in Chat). */
  testIdPrefix?: string
  /**
   * Controlled mode. When `open` is given the dialog renders no trigger of its
   * own — the host (e.g. the details panel) owns the button. Left undefined,
   * the dialog brings its own shield icon button, as before.
   */
  open?: boolean
  onOpenChange?: (open: boolean) => void
}

/** Pair-bound, face-to-face verification. Rust performs the authoritative
 * payload comparison; this component only captures and presents public data.
 * Chat and Drive show it for the same number. */
export function SafetyVerificationDialog({
  peer,
  safety,
  onVerify,
  open: controlledOpen,
  onOpenChange,
  testIdPrefix = 'safety',
  payloadPrefix = VERIFY_PAYLOAD_PREFIX,
  onSetVerified,
}: SafetyVerificationDialogProps) {
  const { t } = useTranslation()
  const [uncontrolledOpen, setUncontrolledOpen] = useState(false)
  const controlled = controlledOpen !== undefined
  const open = controlled ? controlledOpen : uncontrolledOpen
  const [scannedPayload, setScannedPayload] = useState('')
  const [verifying, setVerifying] = useState(false)
  const [marking, setMarking] = useState(false)
  const scanner = useQrScanner(
    payloadPrefix,
    (value) => setScannedPayload(value),
    (failure) =>
      toast.error(t(failure === 'unsupported' ? 'safetyNumber.scanUnsupported' : 'safetyNumber.cameraUnavailable')),
  )
  const { scanning } = scanner
  const verified = safety.state === 'verified'
  const blocked = safety.state === 'blocked'
  const verifyDisabled = !scannedPayload || verifying || (blocked && !safety.canVerifyBlocked)

  // A host closing a controlled dialog must release the camera too.
  useEffect(() => {
    if (!open) scanner.stop()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open])

  async function setVerified(value: boolean) {
    if (!onSetVerified || marking) return
    setMarking(true)
    try {
      await onSetVerified(value)
      toast.success(value ? t('safetyNumber.markedVerified', { peer }) : t('safetyNumber.clearedVerified'))
    } catch {
      toast.error(t('safetyNumber.markFailed'))
    } finally {
      setMarking(false)
    }
  }

  async function verify() {
    if (verifyDisabled) return
    setVerifying(true)
    try {
      await onVerify(scannedPayload)
      setScannedPayload('')
      toast.success(t('safetyNumber.verifiedToast', { peer }))
    } catch {
      toast.error(t('safetyNumber.mismatch'))
    } finally {
      setVerifying(false)
    }
  }

  const stateIcon = blocked ? (
    <AlertTriangle className="h-4 w-4 shrink-0 text-destructive" />
  ) : verified ? (
    <ShieldCheck className="h-4 w-4 shrink-0 text-status-ok" />
  ) : (
    <Shield className="h-4 w-4 shrink-0 text-muted-foreground" />
  )

  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        if (!controlled) setUncontrolledOpen(next)
        onOpenChange?.(next)
        if (!next) scanner.stop()
      }}
    >
      {!controlled && (
        <DialogTrigger asChild>
          <Button
            variant="ghost"
            size="icon"
            className="shrink-0"
            aria-label={
              blocked
                ? t('safetyNumber.triggerWarning', { peer })
                : verified
                  ? t('safetyNumber.triggerVerified', { peer })
                  : t('safetyNumber.triggerVerify', { peer })
            }
            data-testid={`${testIdPrefix}-open`}
          >
            {stateIcon}
          </Button>
        </DialogTrigger>
      )}
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle className="break-all">{t('safetyNumber.title', { peer })}</DialogTitle>
          <DialogDescription>{t('safetyNumber.description')}</DialogDescription>
        </DialogHeader>

        <div className="grid gap-4">
          <div className="flex items-center gap-2 rounded-lg border p-3 text-sm">
            {stateIcon}
            <span>
              {blocked
                ? t('safetyNumber.stateBlocked')
                : verified
                  ? t('safetyNumber.stateVerified')
                  : t('safetyNumber.stateUnverified')}
            </span>
          </div>

          <div className="flex justify-center">
            <div
              className="rounded-xl bg-white p-4"
              data-testid={`${testIdPrefix}-qr`}
              data-value={safety.qrPayload}
            >
              <QRCodeSVG
                value={safety.qrPayload}
                size={210}
                level="M"
                title={t('safetyNumber.qrLabel')}
              />
            </div>
          </div>

          <div className="grid gap-2">
            <div className="flex items-center justify-between gap-2">
              <span className="text-xs font-medium">{t('safetyNumber.numberLabel')}</span>
              <Button
                type="button"
                size="sm"
                variant="ghost"
                onClick={() =>
                  void copyText(safety.fingerprint).then(
                    () => toast.success(t('safetyNumber.copied')),
                    () => toast.error(t('safetyNumber.copyFailed')),
                  )
                }
              >
                <Copy />
                {t('common.copy')}
              </Button>
            </div>
            <Mono
              as="code"
              className="break-words rounded-lg bg-muted p-3 text-center text-xs leading-6"
              data-testid={`${testIdPrefix}-number`}
            >
              {safety.fingerprint}
            </Mono>
            {blocked && safety.retainedAuthorityKeyId && (
              <div className="grid gap-1 text-xs text-muted-foreground">
                <span>{t('safetyNumber.retainedAuthority')}</span>
                <Mono as="code" className="break-all rounded bg-muted p-2">
                  {safety.retainedAuthorityKeyId}
                </Mono>
                <span>{t('safetyNumber.candidateAuthority')}</span>
                <Mono as="code" className="break-all rounded bg-muted p-2">
                  {safety.authorityKeyId}
                </Mono>
              </div>
            )}
          </div>

          {!verified && (
            <div className="grid gap-3 border-t pt-4">
              <video
                ref={scanner.videoRef}
                className={scanning ? 'aspect-square w-full rounded-lg bg-black object-cover' : 'hidden'}
                muted
                playsInline
              />
              <Button type="button" variant="outline" onClick={() => void scanner.start()}>
                <Camera />
                {scanning ? t('safetyNumber.scanning') : t('safetyNumber.scan')}
              </Button>
              <label className="grid gap-2 text-xs font-medium">
                {t('safetyNumber.pasteLabel')}
                <Input
                  value={scannedPayload}
                  onChange={(event) => setScannedPayload(event.target.value.trim())}
                  autoComplete="off"
                  spellCheck={false}
                  placeholder={`${payloadPrefix}…`}
                  className="font-mono"
                />
              </label>
              <Button type="button" disabled={verifyDisabled} onClick={() => void verify()}>
                {verifying ? <Loader2 className="animate-spin" /> : <Check />}
                {t('safetyNumber.verify')}
              </Button>
              {onSetVerified && !blocked ? (
                <div className="grid gap-2 border-t pt-3">
                  <p className="text-xs text-muted-foreground">{t('safetyNumber.markVerifiedHint')}</p>
                  <Button
                    type="button"
                    variant="outline"
                    disabled={marking}
                    onClick={() => void setVerified(true)}
                    data-testid={`${testIdPrefix}-mark-verified`}
                  >
                    {marking ? <Loader2 className="animate-spin" /> : <ShieldCheck />}
                    {t('safetyNumber.markVerified')}
                  </Button>
                </div>
              ) : null}
            </div>
          )}
          {verified && onSetVerified ? (
            <div className="grid gap-2 border-t pt-4">
              <Button
                type="button"
                variant="outline"
                disabled={marking}
                onClick={() => void setVerified(false)}
                data-testid={`${testIdPrefix}-clear-verified`}
              >
                {marking ? <Loader2 className="animate-spin" /> : <Shield />}
                {t('safetyNumber.clearVerified')}
              </Button>
            </div>
          ) : null}
        </div>
      </DialogContent>
    </Dialog>
  )
}
