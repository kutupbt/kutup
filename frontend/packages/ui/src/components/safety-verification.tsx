import { useEffect, useRef, useState } from 'react'
import { AlertTriangle, Camera, Check, Copy, Loader2, Shield, ShieldCheck } from 'lucide-react'
import { QRCodeSVG } from 'qrcode.react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { Button } from './button'
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger } from './dialog'
import { Input } from './input'
import { Mono } from './mono'
import { copyText } from '../lib/clipboard'

interface DetectedBarcode {
  rawValue: string
}

interface BarcodeDetectorInstance {
  detect(source: HTMLVideoElement): Promise<DetectedBarcode[]>
}

type BarcodeDetectorConstructor = new (options: { formats: string[] }) => BarcodeDetectorInstance

function browserBarcodeDetector(): BarcodeDetectorConstructor | undefined {
  return (window as typeof window & { BarcodeDetector?: BarcodeDetectorConstructor }).BarcodeDetector
}

/**
 * Every app's safety QR (Chat, Drive): kutup-crypto `safety_number::QR_PREFIX`,
 * Signal's fingerprint v2 as base64url `CombinedFingerprints`. Each side's code
 * carries its own half first, so a scan here is the other side's code.
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
}: SafetyVerificationDialogProps) {
  const { t } = useTranslation()
  const [uncontrolledOpen, setUncontrolledOpen] = useState(false)
  const controlled = controlledOpen !== undefined
  const open = controlled ? controlledOpen : uncontrolledOpen
  const [scannedPayload, setScannedPayload] = useState('')
  const [verifying, setVerifying] = useState(false)
  const [scanning, setScanning] = useState(false)
  const videoRef = useRef<HTMLVideoElement>(null)
  const streamRef = useRef<MediaStream | null>(null)
  const scanTimerRef = useRef<number | null>(null)
  const verified = safety.state === 'verified'
  const blocked = safety.state === 'blocked'
  const verifyDisabled = !scannedPayload || verifying || (blocked && !safety.canVerifyBlocked)

  function stopScanner() {
    if (scanTimerRef.current !== null) window.clearTimeout(scanTimerRef.current)
    scanTimerRef.current = null
    streamRef.current?.getTracks().forEach((track) => track.stop())
    streamRef.current = null
    if (videoRef.current) videoRef.current.srcObject = null
    setScanning(false)
  }

  useEffect(() => stopScanner, [])

  // A host closing a controlled dialog must release the camera too.
  useEffect(() => {
    if (!open) stopScanner()
  }, [open])

  async function startScanner() {
    const Detector = browserBarcodeDetector()
    if (!Detector || !navigator.mediaDevices?.getUserMedia) {
      toast.error(t('safetyNumber.scanUnsupported'))
      return
    }
    try {
      stopScanner()
      const stream = await navigator.mediaDevices.getUserMedia({
        video: { facingMode: { ideal: 'environment' } },
        audio: false,
      })
      streamRef.current = stream
      setScanning(true)
      const video = videoRef.current
      if (!video) {
        stopScanner()
        return
      }
      video.srcObject = stream
      await video.play()
      const detector = new Detector({ formats: ['qr_code'] })
      const inspect = async () => {
        if (!streamRef.current || !videoRef.current) return
        try {
          const codes = await detector.detect(videoRef.current)
          const value = codes.find((code) => code.rawValue.startsWith(VERIFY_PAYLOAD_PREFIX))
            ?.rawValue
          if (value) {
            setScannedPayload(value)
            stopScanner()
            return
          }
        } catch {
          // A frame may be unavailable while the camera warms up; keep scanning.
        }
        scanTimerRef.current = window.setTimeout(() => void inspect(), 250)
      }
      void inspect()
    } catch {
      stopScanner()
      toast.error(t('safetyNumber.cameraUnavailable'))
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
        if (!next) stopScanner()
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
                ref={videoRef}
                className={scanning ? 'aspect-square w-full rounded-lg bg-black object-cover' : 'hidden'}
                muted
                playsInline
              />
              <Button type="button" variant="outline" onClick={() => void startScanner()}>
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
                  placeholder={`${VERIFY_PAYLOAD_PREFIX}…`}
                  className="font-mono"
                />
              </label>
              <Button type="button" disabled={verifyDisabled} onClick={() => void verify()}>
                {verifying ? <Loader2 className="animate-spin" /> : <Check />}
                {t('safetyNumber.verify')}
              </Button>
            </div>
          )}
        </div>
      </DialogContent>
    </Dialog>
  )
}
