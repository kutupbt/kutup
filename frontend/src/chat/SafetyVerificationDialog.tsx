import { useEffect, useRef, useState } from 'react'
import { AlertTriangle, Camera, Check, Copy, Loader2, Shield, ShieldCheck } from 'lucide-react'
import { QRCodeSVG } from 'qrcode.react'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { copyText } from '@/lib/format'
import type { SafetyNumberV1 } from './types'

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

interface SafetyVerificationDialogProps {
  peer: string
  safety: SafetyNumberV1
  onVerify(scannedPayload: string): Promise<SafetyNumberV1>
}

/** Pair-bound, face-to-face verification. Rust performs the authoritative
 * payload comparison; this component only captures and presents public data. */
export function SafetyVerificationDialog({
  peer,
  safety,
  onVerify,
}: SafetyVerificationDialogProps) {
  const [open, setOpen] = useState(false)
  const [scannedPayload, setScannedPayload] = useState('')
  const [verifying, setVerifying] = useState(false)
  const [scanning, setScanning] = useState(false)
  const videoRef = useRef<HTMLVideoElement>(null)
  const streamRef = useRef<MediaStream | null>(null)
  const scanTimerRef = useRef<number | null>(null)
  const verified = safety.trust === 'Verified' && !safety.continuityGap
  const blocked = safety.continuityGap || safety.trust === 'Quarantined'

  function stopScanner() {
    if (scanTimerRef.current !== null) window.clearTimeout(scanTimerRef.current)
    scanTimerRef.current = null
    streamRef.current?.getTracks().forEach(track => track.stop())
    streamRef.current = null
    if (videoRef.current) videoRef.current.srcObject = null
    setScanning(false)
  }

  useEffect(() => stopScanner, [])

  async function startScanner() {
    const Detector = browserBarcodeDetector()
    if (!Detector || !navigator.mediaDevices?.getUserMedia) {
      toast.error('This browser cannot scan QR codes. Paste the QR value instead.')
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
          const value = codes.find(code => code.rawValue.startsWith('kutup://verify/chat/v1/'))
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
      toast.error('Camera access was unavailable. Paste the QR value instead.')
    }
  }

  async function verify() {
    if (!scannedPayload || verifying || (blocked && !safety.retainedAuthorityKeyId)) return
    setVerifying(true)
    try {
      await onVerify(scannedPayload)
      setScannedPayload('')
      toast.success(`${peer} is now verified on this device`)
    } catch {
      toast.error('That QR code does not match this conversation. Nothing was verified.')
    } finally {
      setVerifying(false)
    }
  }

  return (
    <Dialog
      open={open}
      onOpenChange={next => {
        setOpen(next)
        if (!next) stopScanner()
      }}
    >
      <DialogTrigger asChild>
        <Button
          variant="ghost"
          size="icon"
          className="shrink-0"
          aria-label={blocked
            ? `Security warning for ${peer}`
            : verified
              ? `${peer} is verified`
              : `Verify ${peer}`}
          data-testid="chat-safety-open"
        >
          {blocked
            ? <AlertTriangle className="h-4 w-4 text-destructive" />
            : verified
              ? <ShieldCheck className="h-4 w-4 text-emerald-600 dark:text-emerald-400" />
              : <Shield className="h-4 w-4 text-muted-foreground" />}
        </Button>
      </DialogTrigger>
      <DialogContent className="max-h-[90vh] max-w-md overflow-y-auto">
        <DialogHeader>
          <DialogTitle>Verify {peer}</DialogTitle>
          <DialogDescription>
            Meet in person and scan the QR code shown on the other person&apos;s device.
            Both devices must show the same complete safety number.
          </DialogDescription>
        </DialogHeader>

        <div className="grid gap-4">
          <div className="flex items-center gap-2 rounded-lg border p-3 text-sm">
            {blocked
              ? <AlertTriangle className="h-4 w-4 shrink-0 text-destructive" />
              : verified
                ? <ShieldCheck className="h-4 w-4 shrink-0 text-emerald-600" />
                : <Shield className="h-4 w-4 shrink-0 text-muted-foreground" />}
            <span>
              {blocked
                ? 'The pinned identity changed or contradicted its history. Sending remains blocked until you verify this exact replacement.'
                : verified
                  ? 'Verified face to face on this device.'
                  : 'Encrypted with a valid pinned identity, but not verified face to face.'}
            </span>
          </div>

          <div className="flex justify-center">
            <div
              className="rounded-xl bg-white p-4"
              data-testid="chat-safety-qr"
              data-value={safety.qrPayload}
            >
              <QRCodeSVG value={safety.qrPayload} size={210} level="M" />
            </div>
          </div>

          <div className="grid gap-2">
            <div className="flex items-center justify-between gap-2">
              <span className="text-xs font-medium">Complete safety number</span>
              <Button
                type="button"
                size="sm"
                variant="ghost"
                onClick={() => void copyText(safety.fingerprint).then(() => toast.success('Safety number copied'))}
              >
                <Copy className="mr-2 h-3.5 w-3.5" />
                Copy
              </Button>
            </div>
            <code
              className="break-words rounded-lg bg-muted p-3 text-center text-xs leading-6"
              data-testid="chat-safety-number"
            >
              {safety.fingerprint}
            </code>
            {blocked && safety.retainedAuthorityKeyId && (
              <div className="grid gap-1 text-xs text-muted-foreground">
                <span>Retained authority fingerprint</span>
                <code className="break-all rounded bg-muted p-2">
                  {safety.retainedAuthorityKeyId}
                </code>
                <span>Candidate authority fingerprint</span>
                <code className="break-all rounded bg-muted p-2">
                  {safety.authorityKeyId}
                </code>
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
                <Camera className="mr-2 h-4 w-4" />
                {scanning ? 'Scanning…' : 'Scan their QR code'}
              </Button>
              <label className="grid gap-2 text-xs font-medium">
                Or paste their QR value
                <Input
                  value={scannedPayload}
                  onChange={event => setScannedPayload(event.target.value.trim())}
                  autoComplete="off"
                  spellCheck={false}
                  placeholder="kutup://verify/chat/v1/…"
                />
              </label>
              <Button
                type="button"
                disabled={!scannedPayload || verifying || (blocked && !safety.retainedAuthorityKeyId)}
                onClick={() => void verify()}
              >
                {verifying
                  ? <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  : <Check className="mr-2 h-4 w-4" />}
                Verify exact match
              </Button>
            </div>
          )}
        </div>
      </DialogContent>
    </Dialog>
  )
}
