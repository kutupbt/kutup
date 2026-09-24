import { useEffect, useRef, useState } from 'react'
import { AlertTriangle, Camera, Check, Copy, Loader2, Shield, ShieldCheck } from 'lucide-react'
import { QRCodeSVG } from 'qrcode.react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { Button } from '@kutup/ui/components/button'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from '@kutup/ui/components/dialog'
import { Input } from '@kutup/ui/components/input'
import { Mono } from '@kutup/ui/components/mono'
import { copyText } from '@kutup/ui/lib/clipboard'
import type { SafetyNumberV1 } from '@kutup/chat-core/types'

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

const VERIFY_PAYLOAD_PREFIX = 'kutup://verify/chat/v1/'

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

/** Pair-bound, face-to-face verification. Rust performs the authoritative
 * payload comparison; this component only captures and presents public data. */
export function SafetyVerificationDialog({
  peer,
  safety,
  onVerify,
  open: controlledOpen,
  onOpenChange,
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
  const verified = safety.trust === 'Verified' && !safety.continuityGap
  const blocked = safety.continuityGap || safety.trust === 'Quarantined'
  const verifyDisabled =
    !scannedPayload || verifying || (blocked && !safety.retainedAuthorityKeyId)

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
      toast.error(t('chat.safety.scanUnsupported'))
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
      toast.error(t('chat.safety.cameraUnavailable'))
    }
  }

  async function verify() {
    if (verifyDisabled) return
    setVerifying(true)
    try {
      await onVerify(scannedPayload)
      setScannedPayload('')
      toast.success(t('chat.safety.verifiedToast', { peer }))
    } catch {
      toast.error(t('chat.safety.mismatch'))
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
                ? t('chat.safety.triggerWarning', { peer })
                : verified
                  ? t('chat.safety.triggerVerified', { peer })
                  : t('chat.safety.triggerVerify', { peer })
            }
            data-testid="chat-safety-open"
          >
            {stateIcon}
          </Button>
        </DialogTrigger>
      )}
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle className="break-all">{t('chat.safety.title', { peer })}</DialogTitle>
          <DialogDescription>{t('chat.safety.description')}</DialogDescription>
        </DialogHeader>

        <div className="grid gap-4">
          <div className="flex items-center gap-2 rounded-lg border p-3 text-sm">
            {stateIcon}
            <span>
              {blocked
                ? t('chat.safety.stateBlocked')
                : verified
                  ? t('chat.safety.stateVerified')
                  : t('chat.safety.stateUnverified')}
            </span>
          </div>

          <div className="flex justify-center">
            <div
              className="rounded-xl bg-white p-4"
              data-testid="chat-safety-qr"
              data-value={safety.qrPayload}
            >
              <QRCodeSVG
                value={safety.qrPayload}
                size={210}
                level="M"
                title={t('chat.safety.qrLabel')}
              />
            </div>
          </div>

          <div className="grid gap-2">
            <div className="flex items-center justify-between gap-2">
              <span className="text-xs font-medium">{t('chat.safety.numberLabel')}</span>
              <Button
                type="button"
                size="sm"
                variant="ghost"
                onClick={() =>
                  void copyText(safety.fingerprint).then(
                    () => toast.success(t('chat.safety.copied')),
                    () => toast.error(t('chat.safety.copyFailed')),
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
              data-testid="chat-safety-number"
            >
              {safety.fingerprint}
            </Mono>
            {blocked && safety.retainedAuthorityKeyId && (
              <div className="grid gap-1 text-xs text-muted-foreground">
                <span>{t('chat.safety.retainedAuthority')}</span>
                <Mono as="code" className="break-all rounded bg-muted p-2">
                  {safety.retainedAuthorityKeyId}
                </Mono>
                <span>{t('chat.safety.candidateAuthority')}</span>
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
                {scanning ? t('chat.safety.scanning') : t('chat.safety.scan')}
              </Button>
              <label className="grid gap-2 text-xs font-medium">
                {t('chat.safety.pasteLabel')}
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
                {t('chat.safety.verify')}
              </Button>
            </div>
          )}
        </div>
      </DialogContent>
    </Dialog>
  )
}
